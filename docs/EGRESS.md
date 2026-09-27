# Egress module — `privacy_bot/egress.py`

A small **fail-closed, public-only HTTP proxy** that lives inside the app process. Chromium and
the HTTP scan client use it as their proxy, so the address a page's request actually reaches is
chosen by the same code that decided the request was allowed. `browser.py` shares
one listener across its sessions and captures; `scanner.py` creates and closes a
listener for each independent HTTP watch.

```python
from privacy_bot.egress import PublicEgress

egress = PublicEgress()                     # one per app process
proxy_url = await egress.start()            # 'http://127.0.0.1:41347' (ephemeral port)
... launch Chromium / httpx with that proxy ...
await egress.close()                        # closes every tunnel and the listener
```

| API | Meaning |
| --- | --- |
| `await start() -> str` | Bind `127.0.0.1:0` and return `http://127.0.0.1:<port>`. Second call raises `RuntimeError` (one listener per instance). |
| `await close()` | Stop accepting, cancel and reap every connection and tunnel, close the listener. Bounded (≤ ~2 s), idempotent, safe with live tunnels. |
| `proxy_url` | The URL to hand to Chromium/httpx, or `None` before start / after close. |
| `bound_address` | `(host, port)` the socket is really bound to — the loopback-only claim, checkable from the outside. |
| `listening` | `True` between `start()` and `close()`. |
| `active_sessions` | Live tunnels plus in-flight forwarded exchanges (also the pool-usage gauge). |
| `async with PublicEgress() as e` | Same as start/close. |

Constructor knobs (all optional, defaults in the table below): `bind_host`, `resolver`,
`connector`, `max_active_sessions`, `connect_timeout`, `session_lifetime`,
`request_header_timeout`, `dns_timeout`, `max_header_bytes`, `max_header_lines`,
`max_request_body_bytes`, `max_bytes_per_stream`, `chunk_bytes`. `resolver` / `connector` exist so
the security properties are testable without touching a network — see *Tests* below.

## The hole this closes

`network.validate_public_url()` is a *request-time* check: it resolves the name, refuses anything
non-public, and returns. Chromium then resolves the same name **again** when it opens its socket.
Between those two lookups a record can change — `badge.example → 93.184.216.34` and, a second
later, `badge.example → 192.168.1.1` — which is DNS rebinding, and it defeats a check that runs
before the connection. The same gap exists for a redirect the client follows itself.

Here the check and the connect are the same code path:

1. parse the authority off `CONNECT host:port` / `GET http://host/path`;
2. run the shared destination rules (`network.validate_target_url`, `allow_onion=False`);
3. resolve the name **once** for this connection;
4. require **every** answer to be globally routable — one private answer kills the connection;
5. open the upstream socket to the **numeric address just validated**
   (`asyncio.open_connection("93.184.216.34", 443)`), never the hostname, so there is no second
   lookup and no window;
6. `CONNECT` → raw byte tunnel. Absolute-form `http` → origin-form request to port 80.

A new connection repeats steps 1–5 from scratch. Nothing is cached, so a record that flips to
`127.0.0.1` after one successful visit is refused on the next connection
(`test_a_name_that_flips_to_loopback_is_refused_on_the_next_connection`).

## What is refused, and when

Checked **before any DNS or socket work** (HTTP 403, or 400 for a malformed request):

* any port other than **80 / 443** (`example.com:8443`, `:22`, `:0`);
* **proxy credentials** — a `Proxy-Authorization` header, or `user:pass@` inside the authority;
* **`.onion`** of any kind — and it is never handed to the resolver, because direct onion access is
  not part of this product;
* **internal names** — `localhost`, `*.local`, `*.internal`, `*.lan`, `*.arpa`, `*.test`,
  `*.invalid`, single-label hosts like `internal-host`, plus `wpad`, `metadata`, `config`;
* **encoded / shorthand addresses** (`http://2130706433/`, `127.1`, bare IPv4 literals) and
  malformed or oversized targets;
* **non-public literals** — `127.0.0.1`, `10.x`, `172.16-31.x`, `192.168.x`, `169.254.169.254`,
  `0.x`, `100.64/10`, `::1`, `fe80::`, `fc00::`, multicast, reserved, unspecified, IPv4-mapped
  forms judged as their IPv4 meaning.

Checked **after the one lookup**: any answer that is not globally routable (this is the mixed-A-record
case: `93.184.216.34` **and** `10.42.0.178` → refused, not "prefer the public one").

Also refused before the response is committed: malformed request lines, bare CR/LF framing, header
lines without a colon, obs-fold continuation, duplicate `Host` / `Content-Length`, non-`HTTP/1.x`,
lowercase methods, `TRACE`/`CONNECT`-lookalikes, origin-form (`GET /x`) and `*` targets (no target
to validate), absolute-form `https://` (use `CONNECT`), `Host` that disagrees with the request
target, `Transfer-Encoding` (chunked can't be bounded), `Upgrade`/`TE` on a plaintext hop, and an
`Upgrade`-free but otherwise oversize head.

## Limits (defaults)

| Ceiling | Default | Behaviour when exceeded |
| --- | --- | --- |
| Active sessions (tunnels + forwarded exchanges) | 24 | `503`, refused before DNS |
| Upstream connect | 30 s | `504`, slot freed |
| Session lifetime (per tunnel / forwarded exchange) | 120 s | socket closed from both ends |
| Client request head | 15 s | `408`, connection closed |
| Request head size | 16 KiB / 64 lines | `400` |
| Request body (`Content-Length`) | 2 MiB | `400` (chunked: `400`, always) |
| Streamed bytes per direction | 32 MiB | connection closed, no further bytes |
| DNS | 8 s, one call per connection | `403` (a stalled or failing resolver is a refusal) |

Startup/shutdown order that matters: **start the egress before launching Chromium and `close()` it
only after the browser has stopped.** A browser whose proxy disappears gets connection-refused and
fails closed — it does not fall back to a direct route — but stopping the egress first turns a live
session into a wall of errors instead of a clean shutdown.

## Discretion

No logging of any kind: no URL, host, header, peer or payload byte is written anywhere, and
`privacy_bot/egress.py` imports no logging module. A refusal is a status line plus
`Content-Length: 0` — no body and no reason text — because a response that says *why* it refused
turns the proxy into an oracle a page can probe ("is there a host called `internal-host`?"). Debug what the
proxy did from `active_sessions`, the tests, and what the page reports — not from its responses.

## Honest limits — read before wiring this in

* **Not a firewall.** It protects what a *page* can make the browser fetch. Any process already
  running as this user can open its own socket; OS-level egress rules still belong on the host.
* **No TLS interception, by design.** The proxy cannot see or filter what is inside a tunnel, so it
  cannot block a public host's bad *content*, only its address. Do not add
  `--ignore-certificate-errors`: Chromium's own certificate validation is what makes "the tunnel is
  blind" safe.
* **Idle tunnels are held against the pool** until the client closes them or the 120 s lifetime
  expires, and clients do **not** share one tunnel between requests. Measured with httpx against a
  single public host: 8 parallel `GET`s opened 8 tunnels and filled an 8-slot pool, and the 9th
  request to a different host came back as a proxy `503`. Real Chromium against a site with many
  third-party hosts will exhaust 24 slots the same way and start seeing `503` for new hosts — the
  parent should pass a larger `max_active_sessions` (64 is a sane starting point for browsing) and
  treat a `503` as "proxy saturated", never as "site is clean".
* **120 s is a hard cut, not an idle timeout**: a download or long-poll over two minutes is severed.
  That is the requested bound; if real browsing needs long streams, the knob is `session_lifetime`
  (and it should become an idle timeout, not just a bigger number).
* **Bare IPv4 destinations are refused** (by `network.validate_target_url`, which treats them as an
  SSRF shorthand). IPv6 literals are allowed only when globally routable. A page served from a bare
  IPv4 address will not load — deliberate.
* **TCP + HTTP/1.x proxying only.** No `SOCKS`, no `CONNECT`-with-UDP / `:protocol_version=h2`, no
  `Upgrade` in the clear. Chromium must therefore not be told to use QUIC/HTTP/3 for the origin
  through this proxy (it won't: QUIC does not use an HTTP proxy, it falls back to TCP), and
  WebTransport-style UDP paths simply will not work — a page that *requires* them is broken here,
  not clean.
* **The proxy's own address must stay a literal.** Chromium resolves `--proxy-server` itself;
  `127.0.0.1` is not a name, so that path cannot rebind. Do not use `--proxy-bypass-list` /
  `--proxy-exclude-for-host`: a bypass is a direct route, which is the thing being removed.
* **DNS is the machine's resolver** (one `getaddrinfo` per connection, in a thread). A hostile
  answer is refused; a slow one is refused. Split-horizon DNS on this host therefore cannot be used
  to point a public name at the LAN *and* get connected to it — but it can still make a name
  resolve to nothing, which shows up as a `403`, not as a "clean" result.
* **`0.0.0.0` / LAN binds are refused at construction**, not at bind time, so a misconfigured
  `bind_host` can never quietly expose this proxy to the LAN. The corollary for deployment: this
  proxy and Chromium must share a network namespace. If the browser is ever split into another
  container, `127.0.0.1:<port>` stops reaching it — run the proxy as a sidecar in that container or
  keep them together; do not relax the bind to make it work.
* **No authentication and no allowlist of its own.** Anything on this machine that can reach
  `127.0.0.1:<port>` can ask it to connect to a public host. It is a guard for the browser, not an
  access-control layer; the port is ephemeral and never bound off-loopback.

## Tests

`tests/test_egress.py` (94 tests, ~2 s) drives a real TCP client against a real listener, but with
DNS and the upstream socket injected, so no test connects to a LAN, a host or the internet. The
claims it pins down, in order of importance:

1. `CONNECT` resolves **once** and `open_connection` receives the validated **public numeric** IP;
   the hostname never reaches the connector;
2. a mixed public/private answer denies the connection and opens nothing;
3. `.onion`, internal names, credentials, wrong ports and malformed heads are denied with
   *zero* resolver calls and *zero* connect attempts;
4. forwarded requests leave in origin form with proxy headers stripped and `Connection: close`;
   a `302` is handed back unfollowed;
5. stream, body, head, pool, connect-time and lifetime ceilings each end the session;
6. `close()` returns in under ~2 s with every tunnel socket closed and the listener gone.
