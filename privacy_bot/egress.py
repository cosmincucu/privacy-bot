"""A fail-closed, public-only HTTP/CONNECT proxy: the only way a page can leave this host.

The problem this closes: :func:`privacy_bot.network.validate_public_url` decides *before* a
connection which destinations are acceptable, but the browser resolves the name again when it
opens the socket. A document can publish ``badge.example → 93.184.216.34`` and, seconds later,
``badge.example → 192.168.1.1`` — DNS rebinding — and the address actually spoken to is then one
that was never validated. The same hole opens for ``http://169.254.169.254/``-style targets
reached through a redirect the client follows itself.

``PublicEgress`` moves the decision next to the socket:

* it listens on loopback only, on an ephemeral port, and is handed to Chromium as
  ``--proxy-server=http://127.0.0.1:<port>`` (and to the parent's HTTP scan client as its proxy);
* the target authority is parsed and checked here with :mod:`privacy_bot.network` rules — web
  ports only, no credentials, no ``.onion``, no internal/special names, no encoded addresses;
* the name is resolved **once**, *every* answer must be globally routable, and the upstream
  socket is then opened to the **numeric address that was just validated**. The hostname is never
  passed to the connector, so there is no second lookup and no window between check and connect;
* ``CONNECT`` yields a raw byte tunnel: TLS stays end-to-end between Chromium and the origin and
  this proxy never sees a certificate, a hostname inside SNI or a payload byte;
* absolute-form ``GET http://host/path HTTP/1.1`` is forwarded to port 80 with the request line
  rewritten to origin form and hop-by-hop headers removed;
* a redirect is **not** followed: a ``3xx`` is forwarded verbatim and the client's *next*
  connection is validated from scratch, so ``Location: http://192.168.1.1/`` is a dead end;
* malformed requests, proxy credentials, other ports, oversized heads/bodies/streams, stalled
  connects and over-capacity tunnels are refused with an HTTP status and the socket is closed.
  Nothing is ever "passed through to see what happens";
* nothing is logged and nothing is echoed: no URL, host, header or payload byte is written to a
  logger, and a refusal carries no body, so a page cannot use the proxy as an oracle for which
  internal names exist.

What this is *not*: an anonymity or caching proxy, or a host firewall. It protects against what a
*page* can make the browser fetch; a process that is already running on this machine needs none of
it. See ``docs/EGRESS.md`` for the limits and for how the parent wires it up.
"""
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

import httpx

from . import network
from .network import UrlNotAllowed, is_private_address

#: The only destination ports this proxy will ever open a socket to.
ALLOWED_PORTS = network.ALLOWED_PORTS

#: CONNECT tunnels plus forwarded HTTP exchanges sharing one listening socket.
MAX_ACTIVE_SESSIONS = 24
#: DNS is bounded separately (``dns_timeout``); these are the socket-level ceilings.
CONNECT_TIMEOUT_SECONDS = 30.0
SESSION_LIFETIME_SECONDS = 120.0
REQUEST_HEADER_TIMEOUT_SECONDS = 15.0
DNS_TIMEOUT_SECONDS = network.DNS_TIMEOUT_SECONDS
CLOSE_TIMEOUT_SECONDS = 2.0

MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_LINES = 64
MAX_TARGET_BYTES = 2 * 1024
#: A browser ``POST`` body is bounded; larger uploads are refused rather than buffered.
MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
#: Per direction, per session. A page cannot hold a tunnel open with an infinite stream.
MAX_BYTES_PER_STREAM = 32 * 1024 * 1024
CHUNK_BYTES = 64 * 1024

#: Removed before forwarding a plain request. ``Connection`` is always replaced by ``close``
#: so exactly one request/response crosses a socket and the next request is re-validated.
STRIPPED_HEADERS = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
    }
)


class EgressProtocolError(ValueError):
    """The request itself was malformed, oversized or unsupported (HTTP 400)."""


class EgressBusy(Exception):
    """The tunnel pool is full (HTTP 503); no upstream socket was opened."""


@dataclass
class _Exchange:
    """Per-connection bookkeeping: has a response been committed to the client yet?

    Once a tunnel is established (or a forwarded response is streaming), an HTTP error line
    would be garbage inside that byte stream, so a later failure just closes the socket.
    """

    committed: bool = False


@dataclass(frozen=True)
class _Request:
    method: str
    target: str
    version: str
    headers: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)

    @property
    def names(self) -> list[str]:
        return [name for name, _value, _raw in self.headers]

    def values(self, name: str) -> list[str]:
        return [value for n, value, _raw in self.headers if n == name]


async def system_resolver(host: str) -> list[str]:
    """Answers for *host* from the machine's resolver — replaced in tests."""
    rows = await asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    return [str(row[4][0]) for row in rows]


async def numeric_connector(address: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open the upstream socket to an already-validated *numeric* address.

    Deliberately no hostname reaches this function: ``asyncio.open_connection`` would resolve it
    a second time, and that gap is exactly what DNS rebinding exploits.
    """
    if ":" in address:  # IPv6 literal: state the family so no name lookup is even attempted
        return await asyncio.open_connection(address, port, family=socket.AF_INET6)
    return await asyncio.open_connection(address, port)


class PublicEgress:
    """Loopback HTTP proxy that will only ever connect to validated public addresses.

    ``resolver`` and ``connector`` are injectable (both async callables) so the security
    properties can be asserted without a network: ``resolver(host) -> [address, ...]`` and
    ``connector(numeric_address, port) -> (reader, writer)``.
    """

    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        resolver: Callable[[str], object] | None = None,
        connector: Callable[[str, int], object] | None = None,
        max_active_sessions: int = MAX_ACTIVE_SESSIONS,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        session_lifetime: float = SESSION_LIFETIME_SECONDS,
        request_header_timeout: float = REQUEST_HEADER_TIMEOUT_SECONDS,
        dns_timeout: float = DNS_TIMEOUT_SECONDS,
        max_header_bytes: int = MAX_HEADER_BYTES,
        max_header_lines: int = MAX_HEADER_LINES,
        max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES,
        max_bytes_per_stream: int = MAX_BYTES_PER_STREAM,
        chunk_bytes: int = CHUNK_BYTES,
    ) -> None:
        if bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("PublicEgress must bind loopback; a routable address is refused")
        self.bind_host = bind_host
        self._resolver = resolver or system_resolver
        self._connector = connector or numeric_connector
        self.max_active_sessions = max(1, int(max_active_sessions))
        self.connect_timeout = float(connect_timeout)
        self.session_lifetime = float(session_lifetime)
        self.request_header_timeout = float(request_header_timeout)
        self.dns_timeout = float(dns_timeout)
        self.max_header_bytes = int(max_header_bytes)
        self.max_header_lines = int(max_header_lines)
        self.max_request_body_bytes = int(max_request_body_bytes)
        self.max_bytes_per_stream = int(max_bytes_per_stream)
        self.chunk_bytes = max(1, int(chunk_bytes))

        self._server: asyncio.Server | None = None
        self._url: str | None = None
        self._closing = False
        self._connections: set[asyncio.Task] = set()
        self._sessions: set[asyncio.Task] = set()
        self._active = 0

    # ------------------------------------------------------------------ lifecycle

    @property
    def proxy_url(self) -> str | None:
        """``http://127.0.0.1:<port>`` once started, else ``None``."""
        return self._url

    @property
    def listening(self) -> bool:
        return self._server is not None and not self._closing

    @property
    def bound_address(self) -> tuple[str, int] | None:
        """What the socket is actually bound to — the loopback-only claim, checkable."""
        if self._server is None or not self._server.sockets:
            return None
        return (str(self._server.sockets[0].getsockname()[0]), int(self._server.sockets[0].getsockname()[1]))

    @property
    def active_sessions(self) -> int:
        """Live tunnels plus in-flight forwarded exchanges."""
        return self._active

    async def start(self) -> str:
        """Bind the loopback listener on an ephemeral port and return the proxy URL."""
        if self._server is not None:
            raise RuntimeError("PublicEgress is already running; call close() first")
        self._closing = False
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.bind_host,
            0,
            limit=self.max_header_bytes,
        )
        host, port = self.bound_address or (self.bind_host, 0)
        self.bind_host = host
        self._url = f"http://{host}:{port}"
        return self._url

    async def close(self) -> None:
        """Stop accepting, then cancel and reap every connection and tunnel — bounded.

        Safe to call twice and safe to call while tunnels are mid-flight: those tasks are
        cancelled, and their ``finally`` blocks close both sockets, so no session outlives the
        proxy that made it.
        """
        self._closing = True
        server, self._server = self._server, None
        self._url = None

        pending = [task for task in (*self._sessions, *self._connections) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True), CLOSE_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                pass  # sockets are already closed; nothing here may hang app shutdown
        self._sessions.clear()
        self._connections.clear()
        self._active = 0

        if server is not None:
            server.close()
            try:
                await asyncio.wait_for(server.wait_closed(), CLOSE_TIMEOUT_SECONDS)
            except (asyncio.TimeoutError, OSError):
                pass

    async def __aenter__(self) -> PublicEgress:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------ per connection

    async def _handle_connection(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        """One client socket: at most one request, one validated upstream, then closed."""
        task = asyncio.current_task()
        if self._closing:
            client_writer.close()
            return
        if task is not None:
            self._connections.add(task)
        try:
            await self._serve_request(client_reader, client_writer)
        except Exception:  # a connection must never kill the listener; nothing is logged
            pass
        finally:
            if task is not None:
                self._connections.discard(task)
            client_writer.close()

    async def _serve_request(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        state = _Exchange()
        try:
            request = await self._read_request(client_reader)
        except asyncio.TimeoutError:
            # a client that stalls gets closed, not waited on
            await self._reject(client_writer, 408, state)
            return
        except UrlNotAllowed:  # UrlNotAllowed is a ValueError, so it has to be caught first
            await self._reject(client_writer, 403, state)
            return
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, ValueError):
            await self._reject(client_writer, 400, state)
            return

        try:
            if request.method == "CONNECT":
                await self._handle_connect(request, state, client_reader, client_writer)
            elif request.method in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}:
                await self._handle_forward(request, state, client_reader, client_writer)
            else:
                raise EgressProtocolError(f"method {request.method} is not supported")
        except UrlNotAllowed:
            await self._reject(client_writer, 403, state)
        except EgressProtocolError:
            await self._reject(client_writer, 400, state)
        except EgressBusy:
            await self._reject(client_writer, 503, state)
        except asyncio.TimeoutError:
            await self._reject(client_writer, 504, state)
        except (OSError, asyncio.IncompleteReadError):
            await self._reject(client_writer, 502, state)

    # ------------------------------------------------------------------ request parsing

    async def _read_request(self, reader: asyncio.StreamReader) -> _Request:
        """Parse one request head with hard ceilings; anything odd is a 400, never a guess."""
        raw = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), self.request_header_timeout
        )
        if len(raw) > self.max_header_bytes:
            raise EgressProtocolError("request head is too large")
        text = raw.decode("latin-1")[:-4]  # readuntil hands back the head plus its CRLFCRLF terminator
        lines = text.split("\r\n")
        if len(lines) - 1 > self.max_header_lines:
            raise EgressProtocolError("too many header lines")
        if any(ch in line for line in lines for ch in ("\n", "\r")):
            raise EgressProtocolError("bare CR or LF inside the request head")

        request_line, *header_lines = lines
        parts = request_line.split(" ")
        if len(parts) != 3:
            raise EgressProtocolError("request line must have three fields")
        method, target, version = parts
        if not method.isascii() or not method.isalpha() or method != method.upper():
            raise EgressProtocolError("unsupported request method")
        if not target or len(target) > min(MAX_TARGET_BYTES, self.max_header_bytes):
            raise EgressProtocolError("proxy target is empty or too long")
        if not version.startswith("HTTP/1."):
            raise EgressProtocolError("only HTTP/1.x is proxied")

        headers: list[tuple[str, str, str]] = []
        for line in header_lines:
            name, separator, raw_value = line.partition(":")
            if not separator or not name or name != name.strip():
                raise EgressProtocolError("header line is malformed")
            value = raw_value.strip(" \t")  # one optional space after the colon is normal
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
                raise EgressProtocolError("header value carries a control character")
            headers.append((name.lower(), value, line))

        names = [name for name, _value, _raw in headers]
        if "proxy-authorization" in names:
            raise UrlNotAllowed("proxy credentials are not accepted")
        if names.count("content-length") > 1:
            raise EgressProtocolError("duplicate Content-Length")
        if names.count("host") > 1:
            raise EgressProtocolError("duplicate Host")
        return _Request(method, target, version, tuple(headers))

    def _content_length(self, request: _Request, *, connect: bool) -> int:
        """Body size for a forwarded request; CONNECT may carry an empty one at most."""
        values = request.values("content-length")
        encodings = request.values("transfer-encoding")
        if encodings:
            # Chunked bodies cannot be bounded up front, so this proxy refuses them.
            raise EgressProtocolError("Transfer-Encoding is not proxied")
        if not values:
            return 0
        if not values[0].isdigit():
            raise EgressProtocolError("Content-Length is not a number")
        size = int(values[0])
        if connect and size:
            raise EgressProtocolError("CONNECT must not carry a body")
        if size > self.max_request_body_bytes:
            raise EgressProtocolError("request body is too large")
        return size

    def _require_forwardable_headers(self, request: _Request) -> None:
        """Refuse a protocol switch on a plaintext hop (h2c, websocket) — the smuggler's toolbox.

        On ``CONNECT`` these headers are left alone: the tunnel is opaque bytes that this proxy
        cannot read, and the origin negotiates them inside TLS it terminates itself.
        """
        for name, value, _raw in request.headers:
            normalised = value.strip().lower()
            if name == "upgrade" and normalised:
                raise EgressProtocolError("Upgrade is not proxied in the clear")
            if name == "te" and normalised not in ("", "trailers"):
                raise EgressProtocolError(f"TE: {value} is not proxied")

    # ------------------------------------------------------------------ CONNECT

    async def _handle_connect(
        self,
        request: _Request,
        state: _Exchange,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Validate the tunnel target, open one socket to a numeric IP, then pipe raw bytes."""
        self._require_capacity()
        self._content_length(request, connect=True)
        host, port = _split_authority(request.target)
        host = host.lower().rstrip(".")
        self._validate_destination(f"https://{_bracketed(host)}:{port}/", host, port)

        host_header = request.values("host")
        authority = f"{_bracketed(host)}:{port}"
        if host_header and _normalise_authority(host_header[0]) != _normalise_authority(authority):
            raise EgressProtocolError("Host does not match the CONNECT target")

        address = await self._validated_address(host, port)
        upstream_reader, upstream_writer = await self._open_upstream(address, port)
        try:
            state.committed = True
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            await self._with_deadline(
                self._tunnel(client_reader, client_writer, upstream_reader, upstream_writer)
            )
        finally:
            upstream_writer.close()
            self._release_slot()

    # ------------------------------------------------------------------ absolute-form HTTP

    async def _handle_forward(
        self,
        request: _Request,
        state: _Exchange,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Forward one origin-form request to port 80 and pipe exactly one response back."""
        self._require_capacity()
        self._require_forwardable_headers(request)
        body_bytes = self._content_length(request, connect=False)

        try:
            candidate = httpx.URL(request.target)
            scheme = (candidate.scheme or "").lower()
            target_host = (candidate.host or "").lower().rstrip(".")
            target_port = candidate.port or 80
        except Exception as exc:
            raise EgressProtocolError(f"unparseable proxy target: {exc}")
        scheme_text = request.target.split(":", 1)[0].lower() if ":" in request.target else ""
        if scheme_text not in ("http", "https") or not scheme:
            # Origin-form (``GET /x``), ``*`` and anything not an absolute http(s) URL: with no
            # target in the request line there is nothing to validate, so nothing is forwarded.
            raise EgressProtocolError("proxy requests must use an absolute http(s) URL")
        if scheme == "https":
            raise EgressProtocolError("use CONNECT for https destinations")
        if scheme != "http":
            raise EgressProtocolError("only http(s) targets are proxied")

        # Destination rules first, so a credential-bearing or internal URL is refused as a
        # destination (403) rather than as a formatting accident.
        validated = self._validate_destination(request.target, target_host, target_port)
        path = _origin_form(validated)

        host_header = request.values("host")
        if not host_header:
            raise EgressProtocolError("absolute-form request is missing Host")
        if _normalise_authority(host_header[0]) != _normalise_authority(
            f"{_bracketed(target_host)}:{target_port}"
        ):
            raise EgressProtocolError("Host does not match the request target")

        address = await self._validated_address(target_host, target_port)

        upstream_reader, upstream_writer = await self._open_upstream(address, target_port)
        try:
            upstream_writer.write(self._render_forward(request, path))
            await upstream_writer.drain()
            state.committed = True  # from here the client's bytes are the origin's response
            await self._with_deadline(
                self._exchange(client_reader, client_writer, upstream_reader, upstream_writer, body_bytes)
            )
        finally:
            upstream_writer.close()
            self._release_slot()

    def _render_forward(self, request: _Request, path: str) -> bytes:
        """The request as it reaches the origin: origin-form line, no proxy headers, closed."""
        kept = [raw for name, _value, raw in request.headers if name not in STRIPPED_HEADERS]
        lines = [f"{request.method} {path} HTTP/1.1", *kept, "Connection: close"]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "strict")

    async def _exchange(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        body_bytes: int,
    ) -> None:
        """Push the bounded request body up, then pipe the response back until its end."""
        if body_bytes:
            await self._copy_exact(client_reader, upstream_writer, body_bytes)
        await self._copy_until_eof(upstream_reader, client_writer, self.max_bytes_per_stream)

    # ------------------------------------------------------------------ target validation

    def _validate_destination(self, url: str, host: str, port: int) -> str:
        """Structural gate shared by CONNECT and forwarded requests; raises :class:`UrlNotAllowed`."""
        if port not in ALLOWED_PORTS:
            raise UrlNotAllowed(f"port {port} is not allowed")
        # Onion, credentials, internal names, single labels, encoded addresses, non-web ports and
        # private literals are all refused here, before anything is resolved. ``.onion`` never
        # reaches the resolver: direct onion access is not part of this product.
        validated = network.validate_target_url(url, allow_onion=False)
        if network.is_onion_host(host):
            raise UrlNotAllowed(".onion destinations are refused by the egress proxy")
        return validated

    async def _validated_address(self, host: str, port: int) -> str:
        """Return the one numeric address this connection may use, or refuse the connection."""
        literal = _ip_literal(host)
        if literal is not None:
            if not _is_public_address(literal):
                raise UrlNotAllowed(f"{host} is not a public address")
            return literal

        answers = await self._resolve(host)
        if not answers:
            raise UrlNotAllowed(f"{host} does not resolve to any address")
        non_public = [answer for answer in answers if not _is_public_address(answer)]
        if non_public:
            raise UrlNotAllowed(f"{host} does not resolve exclusively to public addresses")
        return answers[0]

    def _require_capacity(self) -> None:
        """Refuse before any resolver or socket work when the pool is already full."""
        if self._active >= self.max_active_sessions:
            raise EgressBusy("too many active tunnels")

    def _release_slot(self) -> None:
        self._active = max(0, self._active - 1)

    async def _resolve(self, host: str) -> list[str]:
        """Exactly one resolver call per connection — that answer *is* the connect target."""
        try:
            answers = self._resolver(host)
            if inspect.isawaitable(answers):
                answers = await asyncio.wait_for(answers, self.dns_timeout)
        except asyncio.TimeoutError as exc:
            raise UrlNotAllowed(f"DNS lookup for {host} timed out") from exc
        except Exception as exc:  # gaierror, OSError, a misbehaving injected resolver
            raise UrlNotAllowed(f"{host} does not resolve ({type(exc).__name__})") from exc
        return _normalise_answers(answers if isinstance(answers, Iterable) else [answers])

    # ------------------------------------------------------------------ sockets

    async def _open_upstream(self, address: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Take a pool slot, connect under a deadline, and give the slot back on any failure."""
        self._require_capacity()
        self._active += 1
        try:
            reader_writer = self._connector(address, port)
            if inspect.isawaitable(reader_writer):
                reader_writer = await asyncio.wait_for(reader_writer, self.connect_timeout)
            try:
                upstream_reader, upstream_writer = reader_writer
            except (TypeError, ValueError) as exc:
                raise EgressProtocolError("connector did not return a (reader, writer) pair") from exc
            if not hasattr(upstream_writer, "write") or not hasattr(upstream_reader, "read"):
                raise EgressProtocolError("connector returned something that is not a socket")
            return upstream_reader, upstream_writer
        except BaseException:
            self._active -= 1
            raise

    async def _with_deadline(self, awaitable) -> None:
        """Run a session under ``session_lifetime`` and make it cancellable from ``close()``."""
        task = asyncio.ensure_future(awaitable)
        self._sessions.add(task)
        try:
            # No shield: cancelling this connection (``close()``) or hitting the deadline has to
            # reach the session task, whose own ``finally`` closes both sockets.
            await asyncio.wait_for(task, self.session_lifetime)
        finally:
            self._sessions.discard(task)
            if not task.done():
                task.cancel()
            try:
                # gather(return_exceptions=True) waits without re-raising: the session's own
                # result is reported by the await above, not a second time here.
                await asyncio.wait_for(
                    asyncio.gather(task, return_exceptions=True), CLOSE_TIMEOUT_SECONDS
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass  # already closing; the session's finally closed the transports

    async def _tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Pipe both directions; the tunnel ends when either side closes or a ceiling is hit."""
        tasks = [
            asyncio.ensure_future(
                self._copy_until_eof(client_reader, upstream_writer, self.max_bytes_per_stream)
            ),
            asyncio.ensure_future(
                self._copy_until_eof(upstream_reader, client_writer, self.max_bytes_per_stream)
            ),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()  # surface _StreamTooLarge / OSError to the caller
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def _copy_until_eof(
        self, source: asyncio.StreamReader, sink: asyncio.StreamWriter, limit: int
    ) -> None:
        moved = 0
        while True:
            chunk = await source.read(self.chunk_bytes)
            if not chunk:
                return
            moved += len(chunk)
            if moved > limit:
                raise EgressProtocolError("stream exceeded its byte ceiling")
            sink.write(chunk)
            await sink.drain()

    async def _copy_exact(
        self, source: asyncio.StreamReader, sink: asyncio.StreamWriter, nbytes: int
    ) -> None:
        remaining = nbytes
        while remaining > 0:
            chunk = await source.read(min(self.chunk_bytes, remaining))
            if not chunk:
                raise EgressProtocolError("client closed before sending the body it promised")
            remaining -= len(chunk)
            sink.write(chunk)
            await sink.drain()

    async def _reject(self, writer: asyncio.StreamWriter, status: int, state: _Exchange | None = None) -> None:
        """A status line and nothing else: no body, no reason text, nothing to probe with.

        Skipped once a response is committed — at that point the right answer to a failure is a
        closed socket, not an HTTP error spliced into someone's TLS stream.
        """
        if state is not None and state.committed:
            return
        reason = {
            400: "Bad Request", 403: "Forbidden", 408: "Request Timeout",
            502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
        }.get(status, "Closed")
        payload = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        try:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), CLOSE_TIMEOUT_SECONDS)
        except Exception:
            pass  # the peer is already gone; there is nothing to report and nothing to log


# ---------------------------------------------------------------------- helpers


def _split_authority(text: str) -> tuple[str, int]:
    """``host`` and ``port`` from a CONNECT authority; an explicit port is mandatory."""
    if text != text.strip() or any(character.isspace() or ord(character) < 0x21 for character in text):
        raise EgressProtocolError("proxy target contains whitespace or a control character")
    lowered = text.lower()
    if lowered.startswith("["):
        closing = lowered.find("]")
        if closing < 0:
            raise EgressProtocolError("unbalanced brackets in the proxy target")
        host = text[1:closing]
        rest = text[closing + 1:]
        if not rest.startswith(":") or len(rest) < 2:
            raise EgressProtocolError("an IPv6 proxy target needs a port")
        port_text = rest[1:]
    else:
        if text.count(":") > 1:
            raise EgressProtocolError("a bare IPv6 target must be bracketed")
        host, separator, port_text = text.partition(":")
        if not separator:
            raise EgressProtocolError("a CONNECT target needs a port")
    if not host:
        raise EgressProtocolError("proxy target has no host")
    if not port_text.isdigit():
        raise EgressProtocolError("proxy port is not numeric")
    port = int(port_text)
    if not 0 < port <= 65535:
        raise EgressProtocolError("proxy port is out of range")
    return host, port


def _normalise_authority(text: str) -> str:
    """Case-, bracket- and default-port-normalised host for comparing Host against target.

    ``[::1]:443``, ``[::1]`` and ``::1`` must compare equal, or a well-formed IPv6 request would
    be refused for a formatting reason instead of a destination reason.
    """
    lowered = str(text).strip().lower().removeprefix("http://").removeprefix("https://").rstrip(".")
    if lowered.startswith("["):
        closing = lowered.find("]")
        if closing > 0:
            host = lowered[1:closing]
            rest = lowered[closing + 1:]
            port_text = rest[1:] if rest.startswith(":") else ""
            return host if port_text in ("", "80", "443") else f"{host}:{port_text}"
    host, separator, port_text = lowered.rpartition(":")
    if separator and port_text.isdigit() and int(port_text) in ALLOWED_PORTS:
        return host.removeprefix("[").removesuffix("]")
    return lowered


def _bracketed(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _ip_literal(host: str) -> str | None:
    """The plain address form of *host* when it is an IP literal, else ``None``."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _is_public_address(address: str) -> bool:
    """True only for an address that is globally routable and not in any special-purpose range."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
        ip = mapped
    if is_private_address(str(ip)):
        return False
    return bool(ip.is_global)


def _normalise_answers(raw: Iterable[object] | object) -> list[str]:
    """Resolver answers as sorted, de-duplicated plain addresses; junk is dropped."""
    if isinstance(raw, (str, bytes)):
        raw = [raw]
    answers: set[str] = set()
    for item in raw or ():  # type: ignore[union-attr]
        text = str(item).strip().lower().strip("[]").split("%", 1)[0]
        address = _ip_literal(text)
        if address is not None:
            answers.add(address)
    return sorted(answers)


def _origin_form(validated_url: str) -> str:
    """``/path?query`` of a validated absolute URL, for the request line sent to the origin."""
    rest = validated_url.split("://", 1)[1]
    _authority, separator, remainder = rest.partition("/")
    return (separator + remainder) if separator else "/"
