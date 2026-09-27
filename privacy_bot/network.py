"""URL validation for the private browser: public, credential-free destinations only.

The browser may share a host with other services, so every destination it can be
talked into visiting is checked here — the page it opens, each main-frame navigation and every subresource it loads.
Rules enforced in this module:

* ``http``/``https`` only — no ``file:``, ``data:``, ``blob:``, ``javascript:``,
  ``view-source:`` or any other scheme a document or a link could carry;
* no credentials in the URL (``https://user:pass@host/`` is refused, not stripped);
* port 80/443 only;
* no loopback, private, link-local, multicast, reserved or unspecified addresses, and no
  internal host names (``localhost``, ``*.local``, ``*.internal``, ``*.lan``, …);
* ``*.onion`` is refused unless the caller passes ``allow_onion=True``, and then it is
  never handed to the system resolver — name-based retrieval over Tor lives elsewhere;
* host names are resolved and *every* answer must be public, so a hostname that points at
  the LAN is rejected at check time rather than trusted because it "looks like a domain".

This is a request-time guard inside the browser process, not an egress firewall: between
this check and Chromium's own connection the answer could change (DNS rebind TOCTOU). The
same value is re-checked per request, and the host machine should still not expose
services the browser may reach on a raw IP.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urljoin

import httpx

ALLOWED_PORTS = frozenset({80, 443})
DNS_TIMEOUT_SECONDS = 8.0
MAX_URL_CHARS = 4000

ONION_SUFFIX = ".onion"

#: Cloud metadata and single-label internal names that must never be fetched.
DENIED_HOSTS = frozenset(
    {"localhost", "metadata", "metadata.google.internal", "wpad", "config"}
)
#: Reserved / non-routable suffixes plus the usual internal TLDs.
DENIED_SUFFIX_RE = re.compile(
    r"(^|\.)(localhost|local|arpa|internal|intranet|lan|home|localdomain|corp|srv|svc"
    r"|cluster|test|invalid|example)$",
    re.I,
)
#: Schemes that can appear in a link and must never reach a client.
FORBIDDEN_SCHEMES = (
    "file", "data", "blob", "about", "javascript", "vbscript", "view-source", "jar",
    "ftp", "ftps", "sftp", "gopher", "ws", "wss", "mailto", "tel", "sms", "chrome",
    "chrome-extension", "edge", "brave", "resource", "blob-uri", "intent", "market",
)


class UrlNotAllowed(ValueError):
    """Raised for a destination this service will not contact."""


def is_private_address(address: str) -> bool:
    """True when *address* is loopback/private/link-local/multicast/reserved/unspecified."""
    try:
        ip = ipaddress.ip_address(str(address).strip().strip("[]"))
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:  # ::ffff:127.0.0.1 must behave like 127.0.0.1
        ip = mapped
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_onion_host(host: str) -> bool:
    """True for ``<addr>.onion``. A bare ``onion`` host is not a Tor service address."""
    lowered = str(host or "").lower().rstrip(".")
    return lowered.endswith(ONION_SUFFIX) and len(lowered) > len(ONION_SUFFIX)


def _looks_like_numeric_host(host: str) -> bool:
    """Catch ``http://2130706433/`` and ``http://127.1/`` style IP shorthands.

    Real TLDs are never all-digits, so a numeric final label is always an encoded
    address that the OS resolver would happily turn into a loopback or LAN hit.
    """
    text = host.lower().rstrip(".")
    if re.fullmatch(r"0x[0-9a-f]+|\d+", text):
        return True
    if "." not in text or ":" in text:
        return False
    return bool(re.fullmatch(r"\d+", text.rsplit(".", 1)[1]))


def host_allowed(host: str, allowed_hosts) -> bool:
    """True when *host* is covered by *allowed_hosts* (empty/None = no restriction).

    Entries may be written as ``example.com``, ``.example.com`` or a full URL; a bare
    entry matches that host and its subdomains. ``*`` disables the check.
    """
    entries = [str(e).strip().lower().rstrip(".") for e in (allowed_hosts or []) if str(e).strip()]
    if not entries or "*" in entries:
        return True
    target = str(host or "").lower().rstrip(".")
    for entry in entries:
        if "://" in entry:
            try:
                entry = (httpx.URL(entry).host or "").lower().rstrip(".")
            except Exception:
                continue
        entry = entry.lstrip(".")
        if not entry:
            continue
        if target == entry or target.endswith("." + entry):
            return True
    return False


def validate_target_url(
    url,
    *,
    base: str | None = None,
    allow_onion: bool = False,
    allowed_hosts=None,
) -> str:
    """Return an absolute ``http(s)`` URL string, or raise :class:`UrlNotAllowed`.

    Structure-only: no DNS here. ``allow_onion`` permits an ``.onion`` host without any
    resolver lookup; ``allowed_hosts`` optionally restricts the hostname (an empty list
    means "not configured", never "allow nothing").
    """
    text = str(url or "").strip()
    if not text:
        raise UrlNotAllowed("empty URL")
    if len(text) > MAX_URL_CHARS:
        raise UrlNotAllowed(f"URL is longer than {MAX_URL_CHARS} characters")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in text):
        raise UrlNotAllowed("URL contains control characters or whitespace")
    if base:
        try:
            text = urljoin(base, text)
        except ValueError as exc:
            raise UrlNotAllowed(f"cannot resolve {url!r} against its page: {exc}")

    try:
        candidate = httpx.URL(text)
        scheme = (candidate.scheme or "").lower()
        host = (candidate.host or "").lower().rstrip(".")
        port = candidate.port
        has_credentials = bool(candidate.username or candidate.password)
    except Exception as exc:
        raise UrlNotAllowed(f"unparseable URL: {exc}")

    if not scheme:
        raise UrlNotAllowed("URL has no scheme")
    if scheme in FORBIDDEN_SCHEMES:
        raise UrlNotAllowed(f"scheme {scheme}: is not a web scheme")
    if scheme not in ("http", "https"):
        raise UrlNotAllowed(f"scheme {scheme} is not http(s)")
    if not host:
        raise UrlNotAllowed("URL has no host")
    if has_credentials or "@" in _authority(text):
        # ``https://:@host/`` and ``https://host@evil/`` both hide the real destination.
        raise UrlNotAllowed("URL must not carry credentials")
    if any(character in host for character in "\\@/%[]"):
        raise UrlNotAllowed("URL host is malformed")

    if is_onion_host(host):
        if not allow_onion:
            raise UrlNotAllowed(".onion addresses are only used with explicit Tor sources")
    else:
        if host in DENIED_HOSTS or DENIED_SUFFIX_RE.search(host):
            raise UrlNotAllowed(f"host {host} is an internal name")
        if is_private_address(host):
            raise UrlNotAllowed(f"host {host} is a private or loopback address")
        if _looks_like_numeric_host(host):
            raise UrlNotAllowed(f"host {host} is an encoded IP address")
        try:
            ipaddress.ip_address(host)
            ip_literal = True
        except ValueError:
            ip_literal = False
        if not ip_literal:
            if "." not in host:
                # No public DNS name is a single label; ``http://internal-host/`` is a LAN hop.
                raise UrlNotAllowed(f"host {host} is not a public domain name")
            if len(host) > 253 or any(len(label) > 63 or not label for label in host.split(".")):
                raise UrlNotAllowed(f"host {host} is not a well-formed hostname")
            try:
                host.encode("idna")  # reject malformed unicode hostnames before the resolver
            except UnicodeError as exc:
                raise UrlNotAllowed(f"host {host} is not a valid hostname: {exc}")
        resolved_port = port or (443 if scheme == "https" else 80)
        if resolved_port not in ALLOWED_PORTS:
            raise UrlNotAllowed(f"port {resolved_port} is not allowed")

    if not host_allowed(host, allowed_hosts):
        raise UrlNotAllowed(f"host {host} is outside the configured allowlist")
    return str(candidate)


def _authority(text: str) -> str:
    """The ``user@host:port`` part of an absolute URL, for checks httpx normalises away."""
    rest = text.split("://", 1)[1] if "://" in text else ""
    return rest.split("/", 1)[0].split("?")[0].split("#")[0]


async def _resolve(host: str) -> list[str]:
    """System resolver answers for *host* as plain address strings."""
    try:
        answers = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM),
            timeout=DNS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise UrlNotAllowed(f"DNS lookup for {host} timed out after {DNS_TIMEOUT_SECONDS:.0f}s")
    except socket.gaierror as exc:
        raise UrlNotAllowed(f"{host} does not resolve ({exc})")
    except OSError as exc:
        raise UrlNotAllowed(f"DNS lookup for {host} failed: {type(exc).__name__}: {exc}")
    return sorted({str(answer[4][0]) for answer in answers})


async def validate_public_url(url, allow_onion: bool = False, *, allowed_hosts=None) -> str:
    """Return *url* only when it is a credential-free public web destination.

    Every DNS answer must be globally routable — a hostname with one public and one
    private record is refused rather than hoped over. ``.onion`` passes structure checks
    when ``allow_onion`` is set and is never resolved by the system resolver; fetching it
    is a Tor-proxy concern handled outside this module.
    """
    target = validate_target_url(url, allow_onion=allow_onion, allowed_hosts=allowed_hosts)
    host = (httpx.URL(target).host or "").lower().rstrip(".")
    if is_onion_host(host):
        return target
    answers = await _resolve(host)
    if not answers:
        raise UrlNotAllowed(f"{host} does not resolve to any address")
    non_public = [answer for answer in answers if is_private_address(answer) or not _is_global(answer)]
    if non_public:
        raise UrlNotAllowed(
            f"{host} does not resolve exclusively to public addresses (got {', '.join(non_public)})"
        )
    return target


def _is_global(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global)
