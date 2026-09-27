"""The egress proxy must be able to say "no" to everything and never leak to the LAN.

These tests drive a real TCP client socket against a real ``PublicEgress`` listener, but the
outside world is always a fake: the injected resolver decides what DNS says, and the injected
connector records the ``(address, port)`` the proxy tried and hands back an in-memory socket pair.
No test here opens a connection to a LAN, host or the public internet, and none needs one — the
whole point is that *the proxy's own choice of address* is what is being verified.

The claims under test, in order of how much they matter:

1. one resolution per connection, and the socket is opened to a **numeric, globally routable**
   address taken from that answer — the hostname never reaches the connector (no rebinding window);
2. a mixed answer (one public, one private) refuses the connection rather than preferring public;
3. ``.onion``, internal names, credentials, non-web ports and malformed requests are refused
   *before* anything is looked up or connected;
4. limits are real: header size, body size, stream bytes, session count, connect time, session
   lifetime — each ends the session instead of degrading;
5. ``close()`` finishes in bounded time with every tunnel and socket closed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import sys
import time
from pathlib import Path

import pytest

# Import the code under test from this checkout, so a plain ``pytest`` run works before the
# package is installed (and never picks up another checkout's copy).
ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from privacy_bot.egress import PublicEgress  # noqa: E402

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"
LAN_IP = "10.42.0.178"
METADATA_IP = "169.254.169.254"


class RecordingWriter:
    """The proxy's view of the upstream socket: everything written is kept, nothing is sent."""

    def __init__(self) -> None:
        self.payload = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.payload.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed


class FakeUpstream:
    """One fake "public internet" endpoint: feedable reader plus a recorded writer."""

    def __init__(self) -> None:
        self.reader = asyncio.StreamReader()
        self.writer = RecordingWriter()

    def send(self, data: bytes) -> None:
        self.reader.feed_data(data)

    def hang_up(self) -> None:
        self.reader.feed_eof()

    @property
    def received(self) -> bytes:
        return bytes(self.writer.payload)


class RecordingResolver:
    """Async stand-in for DNS. ``answers`` is a list of per-call answer lists."""

    def __init__(self, answers: list[list[str]] | None = None) -> None:
        self.plan = answers or [[PUBLIC_V4]]
        self.calls: list[str] = []

    async def __call__(self, host: str) -> list[str]:
        index = len(self.calls)
        self.calls.append(host)
        answers = self.plan[index] if index < len(self.plan) else self.plan[-1]
        if isinstance(answers, Exception):  # a resolver that fails, not just answers
            raise answers
        return list(answers)


class Harness:
    """A proxy whose DNS and sockets are both under the test's control.

    ``overrides`` may replace the resolver/connector or any ceiling, so a test never has to
    wait 30 seconds to prove a 30-second rule.
    """

    def __init__(self, answers: list[list[str]] | None = None, **overrides) -> None:
        self.resolver = RecordingResolver(answers)
        self.connect_calls: list[tuple[str, int]] = []
        self.upstreams: list[FakeUpstream] = []

        async def connector(address: str, port: int):
            self.connect_calls.append((address, port))
            upstream = FakeUpstream()
            self.upstreams.append(upstream)
            return upstream.reader, upstream.writer

        settings: dict = {"resolver": self.resolver, "connector": connector}
        settings.update(overrides)
        self.egress = PublicEgress(**settings)

    @property
    def upstream(self) -> FakeUpstream:
        assert self.upstreams, "the proxy never opened an upstream socket"
        return self.upstreams[0]

    async def start(self) -> str:
        return await self.egress.start()

    async def client(self, address: tuple[str, int] | None = None):
        host, port = address or self.egress.bound_address
        return await asyncio.open_connection(host, port)

    async def connect_request(self, target: str, extra: str = "") -> tuple:
        """Send a CONNECT head from a real socket and return the client streams."""
        reader, writer = await self.client()
        writer.write(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{extra}\r\n".encode("latin-1")
        )
        await writer.drain()
        return reader, writer

    async def request(self, head: str) -> bytes:
        """One shot: send a raw request head, half-close so the proxy can finish parsing, read."""
        reader, writer = await self.client()
        writer.write(head.encode("latin-1"))
        await writer.drain()
        writer.write_eof()
        data = await read_at_least(reader)
        writer.close()
        return data


async def read_at_least(reader, limit: int = 4096) -> bytes:
    """Read what the proxy answers (it always closes after a refusal)."""
    return await asyncio.wait_for(reader.read(limit), 3)


async def read_head(reader) -> str:
    return (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)).decode("latin-1")


async def expect_closed(reader) -> None:
    assert await asyncio.wait_for(reader.read(4096), 3) == b""


def status_of(response: bytes) -> int:
    first = response.split(b"\r\n", 1)[0].decode("latin-1")
    parts = first.split(" ")
    assert parts[0].startswith("HTTP/1."), f"not an HTTP response: {first!r}"
    return int(parts[1])


def numeric(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- lifecycle


async def test_start_returns_a_loopback_proxy_url_on_an_ephemeral_port():
    harness = Harness()
    url = await harness.start()
    try:
        assert url == harness.egress.proxy_url
        scheme, _, rest = url.partition("://")
        assert scheme == "http"
        host, _, port_text = rest.partition(":")
        assert host == "127.0.0.1" and int(port_text) > 0          # Chromium takes this verbatim
        assert harness.egress.bound_address == ("127.0.0.1", int(port_text))
        assert harness.egress.listening is True
        reader, writer = await harness.client()                     # and it really is listening
        writer.write_eof()
        body = await read_at_least(reader)                          # no request head -> refused
        assert body == b"" or status_of(body) == 400
        writer.close()
        with pytest.raises(RuntimeError):
            await harness.egress.start()                            # no second listener
    finally:
        await harness.egress.close()


async def test_a_routable_bind_address_is_refused_construction_time():
    for bad in ("10.42.0.178", "0.0.0.0", "192.168.64.10"):
        with pytest.raises(ValueError):
            PublicEgress(bind_host=bad)


async def test_close_is_bounded_and_kills_live_tunnels():
    """Stop must not wait for a tunnel to end on its own — it ends them (shutdown safety)."""
    harness = Harness(session_lifetime=600)
    await harness.start()
    host, port = harness.egress.bound_address
    reader, writer = await harness.connect_request("www.experian.co.uk:443")
    assert (await read_head(reader)).startswith("HTTP/1.1 200")
    writer.write(b"still-open-bytes")
    await writer.drain()
    assert harness.egress.active_sessions == 1

    started = time.monotonic()
    await asyncio.wait_for(harness.egress.close(), 3)
    assert time.monotonic() - started < 2.5
    assert harness.egress.active_sessions == 0
    assert harness.upstream.writer.closed is True                   # upstream socket closed
    await expect_closed(reader)                                     # client socket closed
    writer.close()

    with pytest.raises(ConnectionRefusedError):                     # listener is gone
        await harness.client((host, port))
    await harness.egress.close()                                    # idempotent


async def test_an_idle_client_that_never_finishes_a_request_head_is_cut_off():
    harness = Harness(request_header_timeout=0.3)
    await harness.start()
    try:
        reader, writer = await harness.client()
        writer.write(b"GET http://exa")                             # stalled, never terminated
        await writer.drain()
        started = time.monotonic()
        body = await read_at_least(reader)
        assert time.monotonic() - started < 2.0                     # 408 or EOF, but not a hang
        assert body == b"" or status_of(body) == 408
        writer.close()
    finally:
        await harness.egress.close()


# ------------------------------------------------------------- the rebinding property


async def test_connect_resolves_once_and_connects_to_the_validated_public_ip():
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.connect_request("www.experian.co.uk:443")
        assert (await read_head(reader)).startswith("HTTP/1.1 200")
        assert harness.resolver.calls == ["www.experian.co.uk"]     # exactly one lookup
        assert harness.connect_calls == [(PUBLIC_V4, 443)]          # ... and *that* address used
        assert numeric(harness.connect_calls[0][0])
        writer.close()
    finally:
        await harness.egress.close()


async def test_the_hostname_never_reaches_the_socket_layer():
    """If a name ever got through, the connector would resolve it again — the TOCTOU window."""
    harness = Harness()
    await harness.start()
    try:
        for target in ("www.experian.co.uk:443", "example.com:443"):
            reader, writer = await harness.connect_request(target)
            await read_head(reader)
            writer.close()
        assert harness.connect_calls
        assert all(numeric(address) for address, _port in harness.connect_calls)
    finally:
        await harness.egress.close()


async def test_one_private_answer_among_public_ones_denies_the_connection():
    harness = Harness(answers=[[PUBLIC_V4, LAN_IP]])
    await harness.start()
    try:
        response = await harness.request(
            "CONNECT dual.example.com:443 HTTP/1.1\r\nHost: dual.example.com:443\r\n\r\n"
        )
        assert status_of(response) == 403
        assert harness.resolver.calls == ["dual.example.com"]       # checked, then refused
        assert harness.connect_calls == []                          # never reached the socket
    finally:
        await harness.egress.close()


async def test_a_name_that_flips_to_loopback_is_refused_on_the_next_connection():
    """The rebinding regression: a record that turns private must not ride an earlier success."""
    harness = Harness(answers=[[PUBLIC_V4], ["127.0.0.1"], [METADATA_IP]])
    await harness.start()
    try:
        reader, writer = await harness.connect_request("flip.example.net:443")
        assert (await read_head(reader)).startswith("HTTP/1.1 200")
        writer.close()

        second = await harness.request(
            "CONNECT flip.example.net:443 HTTP/1.1\r\nHost: flip.example.net:443\r\n\r\n"
        )
        assert status_of(second) == 403
        third = await harness.request(
            "CONNECT flip.example.net:443 HTTP/1.1\r\nHost: flip.example.net:443\r\n\r\n"
        )
        assert status_of(third) == 403

        assert harness.resolver.calls == ["flip.example.net"] * 3   # no cached answer anywhere
        assert harness.connect_calls == [(PUBLIC_V4, 443)]          # only the first, public, one
    finally:
        await harness.egress.close()


async def test_a_public_ipv6_literal_is_proxied_without_any_lookup():
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.connect_request(f"[{PUBLIC_V6}]:443")
        assert (await read_head(reader)).startswith("HTTP/1.1 200")
        assert harness.resolver.calls == []                         # an address is not a name
        assert harness.connect_calls == [(PUBLIC_V6, 443)]
        writer.close()
    finally:
        await harness.egress.close()


async def test_a_public_ipv4_literal_target_is_refused_by_policy():
    """``https://93.184.216.34/`` is not a name a broker page needs, and it is a classic SSRF
    shorthand, so :mod:`privacy_bot.network` refuses bare IPv4 — the proxy inherits that."""
    harness = Harness()
    await harness.start()
    try:
        response = await harness.request(
            f"CONNECT {PUBLIC_V4}:443 HTTP/1.1\r\nHost: {PUBLIC_V4}:443\r\n\r\n"
        )
        assert status_of(response) == 403
        assert harness.resolver.calls == [] and harness.connect_calls == []
    finally:
        await harness.egress.close()


async def test_resolver_failure_and_timeout_are_refusals_not_passes():
    harness = Harness(answers=[[OSError("dns exploded")]])
    await harness.start()
    try:
        response = await harness.request(
            "CONNECT broken.example.uk:443 HTTP/1.1\r\nHost: broken.example.uk:443\r\n\r\n"
        )
        assert status_of(response) == 403
        assert harness.resolver.calls == ["broken.example.uk"]      # the lookup really was made

        async def stalled(_host: str) -> list[str]:
            await asyncio.sleep(5)
            return [PUBLIC_V4]

        slow = Harness(resolver=stalled, dns_timeout=0.3)
        await slow.start()
        try:
            response = await slow.request(
                "CONNECT slow.example.uk:443 HTTP/1.1\r\nHost: slow.example.uk:443\r\n\r\n"
            )
            assert status_of(response) == 403
            assert slow.connect_calls == []
        finally:
            await slow.egress.close()
    finally:
        await harness.egress.close()


# ------------------------------------------------------------------------ refusals up front

DENIED_TARGETS = [
    pytest.param("127.0.0.1:443", id="loopback-literal"),
    pytest.param("127.0.0.1:80", id="loopback-port80"),
    pytest.param(f"{METADATA_IP}:80", id="cloud-metadata"),
    pytest.param(f"{METADATA_IP}:443", id="cloud-metadata-443"),
    pytest.param(f"{LAN_IP}:443", id="lan-literal"),
    pytest.param("192.168.64.10:443", id="vm-lan-literal"),
    pytest.param("172.16.5.9:80", id="docker-network"),
    pytest.param("[::1]:443", id="ipv6-loopback"),
    pytest.param("[fe80::1]:443", id="ipv6-link-local"),
    pytest.param("[fc00::1234]:443", id="ipv6-ula"),
    pytest.param("localhost:443", id="localhost"),
    pytest.param("internal-host:443", id="single-label-hostname"),
    pytest.param("service.internal:443", id="internal-suffix"),
    pytest.param("printer.lan:80", id="lan-suffix"),
    pytest.param("wpad.local:80", id="wpad"),
    pytest.param("cache.example.invalid:443", id="reserved-tld"),
    pytest.param("abcdef2345abcdefg.onion:443", id="onion"),
    pytest.param("example.onion:80", id="onion-port80"),
    pytest.param("example.com:8443", id="non-web-port"),
    pytest.param("example.com:22", id="ssh-port"),
    pytest.param("example.com:0", id="zero-port"),
    pytest.param("user:pass@example.com:443", id="credentials-in-authority"),
    pytest.param("example.com", id="missing-port"),
    pytest.param("example.com:443/stealth", id="path-in-connect-target"),
    pytest.param("exa mple.com:443", id="whitespace-in-target"),
    pytest.param("EXAMPLE.COM:443..", id="trailing-dots-only"),
]


#: The same destinations reached the other way: absolute-form ``http://`` on port 80. These are
#: real URL authorities, unlike several CONNECT targets above that are malformed by construction.
DENIED_AUTHORITIES = [
    pytest.param("127.0.0.1", id="loopback"),
    pytest.param(METADATA_IP, id="cloud-metadata"),
    pytest.param(LAN_IP, id="lan-literal"),
    pytest.param("192.168.64.10", id="vm-lan-literal"),
    pytest.param("172.16.5.9", id="docker-network"),
    pytest.param("[::1]", id="ipv6-loopback"),
    pytest.param("[fe80::1]", id="ipv6-link-local"),
    pytest.param("[fc00::1234]", id="ipv6-ula"),
    pytest.param("localhost", id="localhost"),
    pytest.param("internal-host", id="single-label-hostname"),
    pytest.param("service.internal", id="internal-suffix"),
    pytest.param("printer.lan", id="lan-suffix"),
    pytest.param("wpad.local", id="wpad"),
    pytest.param("cache.example.invalid", id="reserved-tld"),
    pytest.param("abcdef2345abcdefg.onion", id="onion"),
    pytest.param("example.com:8443", id="non-web-port"),
    pytest.param("example.com:22", id="ssh-port"),
    pytest.param("user:pass@example.com", id="credentials-in-authority"),
    pytest.param("127.0.0.1:8080", id="loopback-and-bad-port"),
]


@pytest.mark.parametrize("target", DENIED_TARGETS)
async def test_denied_tunnel_targets_never_reach_dns_or_a_socket(target):
    """Every one of these is a 4xx and, crucially, zero lookups and zero connect attempts."""
    harness = Harness()
    await harness.start()
    try:
        response = await harness.request(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        assert status_of(response) >= 400, response
        assert status_of(response) < 500, response
        assert harness.resolver.calls == []
        assert harness.connect_calls == []
        assert harness.egress.active_sessions == 0
    finally:
        await harness.egress.close()


@pytest.mark.parametrize("authority", DENIED_AUTHORITIES)
async def test_the_same_targets_are_denied_as_plain_http_forwarding(authority):
    """A tunnel is not the only path: absolute-form http must be held to the same wall."""
    harness = Harness()
    await harness.start()
    try:
        response = await harness.request(
            f"GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        )
        assert status_of(response) >= 400, response
        assert status_of(response) < 500, response
        assert harness.resolver.calls == []
        assert harness.connect_calls == []
    finally:
        await harness.egress.close()


async def test_onion_is_refused_without_asking_the_resolver():
    """Tor-only names must never be handed to the system resolver, denied as they are here."""

    async def forbidden_resolver(host: str) -> list[str]:
        raise AssertionError(f"the resolver was asked about {host!r}")

    harness = Harness(resolver=forbidden_resolver)
    await harness.start()
    try:
        response = await harness.request(
            "CONNECT duckduckgq4l2b6yxqt5xpngx7yhachjz3l23hf27r2trcyyna6xnbp2qd.onion:443 "
            "HTTP/1.1\r\n"
            "Host: duckduckgq4l2b6yxqt5xpngx7yhachjz3l23hf27r2trcyyna6xnbp2qd.onion:443\r\n\r\n"
        )
        assert status_of(response) == 403
        assert harness.connect_calls == []
    finally:
        await harness.egress.close()


async def test_proxy_credentials_are_refused_not_forwarded():
    harness = Harness()
    await harness.start()
    try:
        response = await harness.request(
            "CONNECT www.experian.co.uk:443 HTTP/1.1\r\n"
            "Host: www.experian.co.uk:443\r\n"
            "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"
        )
        assert status_of(response) == 403
        assert harness.resolver.calls == []
        assert harness.connect_calls == []
        response = await harness.request(
            "GET http://someone@www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n"
        )
        assert status_of(response) == 403
        assert harness.connect_calls == []
    finally:
        await harness.egress.close()


# ---------------------------------------------------------------------- request parsing

MALFORMED_REQUESTS = [
    pytest.param("CONNECT www.experian.co.uk:443\r\n\r\n", id="no-version"),
    pytest.param("CONNECT a b:443 HTTP/1.1\r\n\r\n", id="target-with-space"),
    pytest.param("CONNECT www.experian.co.uk:443 HTTP/1.1 extra\r\n\r\n", id="four-fields"),
    pytest.param("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", id="h2-preamble"),
    pytest.param("connect www.experian.co.uk:443 HTTP/1.1\r\n\r\n", id="lowercase-method"),
    pytest.param("TRACE http://www.experian.co.uk/ HTTP/1.1\r\n\r\n", id="unsupported-method"),
    pytest.param("GET /index.html HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n", id="origin-form"),
    pytest.param("OPTIONS * HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n", id="asterisk-form"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nno-colon-header\r\n\r\n", id="header-without-colon"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\n Host: folded\r\n\r\n", id="obs-fold"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\nHost: other\r\n\r\n", id="duplicate-host"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", id="duplicate-content-length"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\nContent-Length: twelve\r\n\r\n", id="non-numeric-length"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\nTransfer-Encoding: chunked\r\n\r\n", id="chunked"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", id="upgrade-in-clear"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", id="host-header-mismatch"),
    pytest.param("GET https://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n", id="https-absolute-form"),
    pytest.param("GET http://www.experian.co.uk:8080/ HTTP/1.1\r\nHost: www.experian.co.uk:8080\r\n\r\n", id="absolute-form-bad-port"),
    pytest.param("GET ftp://www.experian.co.uk/ HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n", id="non-http-scheme"),
    pytest.param("\r\n\r\n", id="empty-request"),
    pytest.param("GET http://www.experian.co.uk/ HTTP/1.1\nHost: www.experian.co.uk\n\n", id="bare-lf-framing"),
]


@pytest.mark.parametrize("head", MALFORMED_REQUESTS)
async def test_malformed_or_smuggled_request_heads_are_refused_without_dns(head):
    harness = Harness()
    await harness.start()
    try:
        response = await harness.request(head)
        assert 400 <= status_of(response) < 500, response
        assert harness.resolver.calls == []
        assert harness.connect_calls == []
    finally:
        await harness.egress.close()


async def test_an_oversized_request_head_is_cut_off():
    harness = Harness()
    await harness.start()
    try:
        padding = "X-Junk: " + ("a" * 200) + "\r\n"
        head = "CONNECT www.experian.co.uk:443 HTTP/1.1\r\nHost: www.experian.co.uk:443\r\n" + (padding * 200)
        response = await harness.request(head + "\r\n")
        assert status_of(response) == 400
        assert harness.resolver.calls == [] and harness.connect_calls == []
    finally:
        await harness.egress.close()


async def test_too_many_header_lines_is_refused():
    harness = Harness(max_header_bytes=64 * 1024, max_header_lines=8)
    await harness.start()
    try:
        head = "CONNECT www.experian.co.uk:443 HTTP/1.1\r\n" + ("X-Pad: 1\r\n" * 40)
        response = await harness.request(head + "\r\n")
        assert status_of(response) == 400
        assert harness.connect_calls == []
    finally:
        await harness.egress.close()


# ------------------------------------------------------------------ plain HTTP forwarding


async def test_absolute_form_get_is_forwarded_in_origin_form_to_the_validated_ip():
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.client()
        writer.write(
            b"GET http://www.experian.co.uk/report?a=1&b=2 HTTP/1.1\r\n"
            b"Host: www.experian.co.uk\r\n"
            b"User-Agent: PrivacyBot\r\n"
            b"Proxy-Connection: keep-alive\r\n"
            b"Proxy-Authorization-Foo: bar\r\n"
            b"\r\n"
        )
        await writer.drain()
        await asyncio.sleep(0.05)
        forwarded = harness.upstream.received.decode("latin-1")
        assert forwarded.startswith("GET /report?a=1&b=2 HTTP/1.1\r\n")
        assert "User-Agent: PrivacyBot" in forwarded          # page headers survive
        assert "Proxy-Connection" not in forwarded            # proxy-only headers do not
        assert "Connection: close" in forwarded                # one exchange per socket
        assert harness.connect_calls == [(PUBLIC_V4, 80)]      # port 80, numeric, once-resolved
        assert len(harness.resolver.calls) == 1

        harness.upstream.send(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        assert await asyncio.wait_for(reader.read(1024), 3) == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        writer.close()
    finally:
        await harness.egress.close()


async def test_an_uppercase_scheme_and_host_still_prove_their_target():
    """Scheme case is case-insensitive per RFC, so a normalised target must still be validated."""
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.client()
        writer.write(b"GET HTTP://WWW.EXPERIAN.CO.UK/Report HTTP/1.1\r\nHost: WWW.EXPERIAN.CO.UK\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(0.05)
        assert harness.upstream.received.startswith(b"GET /Report HTTP/1.1\r\n")
        assert harness.connect_calls == [(PUBLIC_V4, 80)]
        assert harness.resolver.calls == ["www.experian.co.uk"]
        writer.close()
    finally:
        await harness.egress.close()


async def test_a_redirect_is_handed_back_unfollowed():
    """No redirect logic here at all: the client's next connection is validated afresh."""
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.client()
        writer.write(
            b"GET http://www.experian.co.uk/go HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n"
        )
        await writer.drain()
        await asyncio.sleep(0.05)
        harness.upstream.send(
            b"HTTP/1.1 302 Found\r\nLocation: http://192.168.1.1/admin\r\nContent-Length: 0\r\n\r\n"
        )
        response = await asyncio.wait_for(reader.read(4096), 3)
        assert b"302 Found" in response and b"192.168.1.1" in response
        assert harness.connect_calls == [(PUBLIC_V4, 80)]      # nothing followed it
        assert len(harness.resolver.calls) == 1
        writer.close()
    finally:
        await harness.egress.close()


async def test_a_post_body_is_forwarded_byte_for_byte_and_then_the_response_returns():
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.client()
        body = b"report=canonical"
        writer.write(
            b"POST http://www.experian.co.uk/submit HTTP/1.1\r\n"
            b"Host: www.experian.co.uk\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("latin-1")
            + body
        )
        await writer.drain()
        await asyncio.sleep(0.05)
        forwarded = harness.upstream.received
        assert forwarded.startswith(b"POST /submit HTTP/1.1\r\n")
        assert forwarded.endswith(body)
        harness.upstream.send(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\nok")
        assert b"202 Accepted" in await asyncio.wait_for(reader.read(4096), 3)
        writer.close()
    finally:
        await harness.egress.close()


async def test_an_oversized_request_body_is_refused_before_it_is_read():
    harness = Harness(max_request_body_bytes=32)
    await harness.start()
    try:
        response = await harness.request(
            "POST http://www.experian.co.uk/upload HTTP/1.1\r\n"
            "Host: www.experian.co.uk\r\nContent-Length: 100000\r\n\r\n"
        )
        assert status_of(response) == 400
        assert harness.connect_calls == []
    finally:
        await harness.egress.close()


async def test_an_overlong_response_stream_is_cut_off():
    """A server cannot stream forever: the ceiling closes the session instead."""
    harness = Harness(max_bytes_per_stream=128)
    await harness.start()
    try:
        reader, writer = await harness.client()
        writer.write(b"GET http://www.experian.co.uk/big HTTP/1.1\r\nHost: www.experian.co.uk\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(0.05)
        harness.upstream.send(b"x" * 4096)
        seen = await asyncio.wait_for(reader.read(1024), 3)
        assert len(seen) <= 256                       # only the ceiling worth of bytes got out
        await expect_closed(reader)                   # ... and the session is finished
        assert harness.egress.active_sessions == 0
        writer.close()
    finally:
        await harness.egress.close()


# --------------------------------------------------------------- tunnels and pool limits


async def test_tunnel_carries_bytes_both_ways_and_ends_when_the_origin_hangs_up():
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.connect_request("www.experian.co.uk:443")
        assert (await read_head(reader)).startswith("HTTP/1.1 200")
        writer.write(b"\x16\x03\x01 client-hello")            # opaque TLS bytes, untouched
        await writer.drain()
        await asyncio.sleep(0.05)
        assert harness.upstream.received == b"\x16\x03\x01 client-hello"

        harness.upstream.send(b"\x16\x03\x03 server-hello")
        assert await asyncio.wait_for(reader.read(64), 3) == b"\x16\x03\x03 server-hello"

        harness.upstream.hang_up()
        await expect_closed(reader)
        await asyncio.sleep(0.1)
        assert harness.egress.active_sessions == 0            # slot released, not leaked
        writer.close()
    finally:
        await harness.egress.close()


async def test_the_proxy_never_reads_or_reinterprets_tunnelled_bytes():
    harness = Harness()
    await harness.start()
    try:
        reader, writer = await harness.connect_request("www.experian.co.uk:443")
        await read_head(reader)
        payload = b"GET http://169.254.169.254/latest/meta-data HTTP/1.1\r\n\r\n"
        writer.write(payload)                                 # looks like a request; is not one
        await writer.drain()
        await asyncio.sleep(0.05)
        assert harness.upstream.received == payload
        assert len(harness.connect_calls) == 1                # no second socket was opened
        writer.close()
    finally:
        await harness.egress.close()


async def test_the_tunnel_pool_is_capped_and_recovers_when_a_slot_frees_up():
    harness = Harness(max_active_sessions=1)
    await harness.start()
    try:
        first, first_writer = await harness.connect_request("one.example.com:443")
        assert (await read_head(first)).startswith("HTTP/1.1 200")
        assert harness.egress.active_sessions == 1

        blocked = await harness.request(
            "CONNECT two.example.com:443 HTTP/1.1\r\nHost: two.example.com:443\r\n\r\n"
        )
        assert status_of(blocked) == 503
        assert harness.resolver.calls == ["one.example.com"]  # refused before doing any work
        assert len(harness.connect_calls) == 1

        harness.upstream.hang_up()                            # first tunnel ends
        await expect_closed(first)
        first_writer.close()
        await asyncio.sleep(0.1)
        assert harness.egress.active_sessions == 0

        third, third_writer = await harness.connect_request("three.example.com:443")
        assert (await read_head(third)).startswith("HTTP/1.1 200")
        third_writer.close()
    finally:
        await harness.egress.close()


async def test_a_session_is_killed_at_its_lifetime_limit():
    harness = Harness(session_lifetime=0.4)
    await harness.start()
    try:
        reader, writer = await harness.connect_request("www.experian.co.uk:443")
        assert (await read_head(reader)).startswith("HTTP/1.1 200")
        started = time.monotonic()
        await expect_closed(reader)                           # neither side closed; we did
        assert time.monotonic() - started < 3.0
        assert harness.egress.active_sessions == 0
        writer.close()
    finally:
        await harness.egress.close()


async def test_a_stalled_upstream_connect_fails_closed_with_a_timeout():
    """The 30-second rule: an unreachable host must not park a browser request."""

    async def black_hole(address: str, port: int):
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    harness = Harness(connector=black_hole, connect_timeout=0.4)
    await harness.start()
    try:
        response = await harness.request(
            "CONNECT www.experian.co.uk:443 HTTP/1.1\r\nHost: www.experian.co.uk:443\r\n\r\n"
        )
        assert status_of(response) == 504
        assert harness.egress.active_sessions == 0
    finally:
        await harness.egress.close()


async def test_an_upstream_socket_error_is_a_bad_gateway_and_frees_the_slot():
    async def refusing(address: str, port: int):
        raise ConnectionRefusedError("nothing listening")

    harness = Harness(connector=refusing)
    await harness.start()
    try:
        response = await harness.request(
            "CONNECT www.experian.co.uk:443 HTTP/1.1\r\nHost: www.experian.co.uk:443\r\n\r\n"
        )
        assert status_of(response) == 502
        assert harness.egress.active_sessions == 0
        assert len(harness.resolver.calls) == 1
    finally:
        await harness.egress.close()


# --------------------------------------------------------------------------- discretion


async def test_the_proxy_says_nothing_about_why_it_refused():
    """No body, no reason text, no log line: a denied page gets an oracle-free 4xx."""
    records: list[logging.LogRecord] = []

    class Catcher(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    root = logging.getLogger()
    handler = Catcher()
    root.addHandler(handler)
    level = root.level
    root.setLevel(logging.DEBUG)
    harness = Harness()
    await harness.start()
    try:
        response = await harness.request(
            f"CONNECT {LAN_IP}:443 HTTP/1.1\r\nHost: {LAN_IP}:443\r\n\r\n"
        )
        assert status_of(response) == 403
        assert response.count(b"\r\n") <= 4                   # status plus two headers plus blank
        assert b"10.42.0.178" not in response and b"private" not in response
        assert not any("experian" in r.getMessage().lower() for r in records)
    finally:
        await harness.egress.close()
        root.removeHandler(handler)
        root.setLevel(level)
    assert [r.name for r in records if r.name.startswith("privacy_bot")] == []
