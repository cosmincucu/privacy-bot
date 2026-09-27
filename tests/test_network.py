"""URL validation for the private browser: what it may open, and what it must refuse.

The browser may run alongside other services, so these tests are the contract for
"public destination or nothing". The system resolver is replaced everywhere — no test here
touches the network, and one test asserts the resolver is *never asked* about ``.onion``.
"""
from __future__ import annotations

import asyncio
import socket
import sys
import time
from pathlib import Path

import pytest

# Import the code under test from this checkout, so a plain ``pytest`` run from the repository
# root works before the package is installed (and never picks up another project's copy).
ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from privacy_bot import network  # noqa: E402
from privacy_bot.network import (  # noqa: E402
    UrlNotAllowed,
    host_allowed,
    is_onion_host,
    is_private_address,
    validate_public_url,
    validate_target_url,
)

PUBLIC_IP = "93.184.216.34"


def fake_resolver(*answers):
    """Stand in for ``socket.getaddrinfo`` and return *answers* for any name."""

    def _resolve(host, port=0, family=0, type=0, proto=0, flags=0):
        rows = []
        for answer in answers:
            family_hint = socket.AF_INET6 if ":" in answer else socket.AF_INET
            rows.append((family_hint, socket.SOCK_STREAM, 6, "", (answer, 0)))
        return rows

    return _resolve


def never_resolves(monkeypatch):
    """Fail loudly if validation asks DNS anything (used for ``.onion`` expectations)."""

    def _spy(*args, **kwargs):
        raise AssertionError("the system resolver must never be asked about this host")

    monkeypatch.setattr(socket, "getaddrinfo", _spy)


def check_public(url, monkeypatch=None, *answers, **kwargs):
    """Run the async validator with the resolver pinned to *answers* (one public IP)."""
    if monkeypatch is not None:
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolver(*(answers or (PUBLIC_IP,))))
    return asyncio.run(validate_public_url(url, **kwargs))


def check(url, **kwargs):
    """Run the validator with whatever resolver the test already installed."""
    return asyncio.run(validate_public_url(url, **kwargs))


# --------------------------------------------------------------------------- accepted


def test_plain_public_https_page_is_returned(monkeypatch):
    target = check_public("https://www.experian.co.uk/report", monkeypatch)
    assert target == "https://www.experian.co.uk/report"


def test_plain_http_is_still_a_web_destination(monkeypatch):
    assert check_public("http://example.com/summary", monkeypatch).startswith("http://example.com")


@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com:80/", "https://example.com:443/"])
def test_default_and_explicit_web_ports(url, monkeypatch):
    assert check_public(url, monkeypatch)


def test_uppercase_scheme_and_host_are_normalised(monkeypatch):
    assert check_public("HTTPS://EXAMPLE.COM/Report", monkeypatch) == "https://example.com/Report"


def test_unicode_host_becomes_punycode_before_any_lookup(monkeypatch):
    assert check_public("http://例え.jp/report", monkeypatch) == "http://xn--r8jz45g.jp/report"


def test_public_ipv6_literal_is_accepted(monkeypatch):
    assert check_public("http://[2606:4700:4700::1111]/report", monkeypatch)


def test_fragment_and_query_survive(monkeypatch):
    target = check_public("https://example.com/r?a=1&b=2#top", monkeypatch)
    assert "a=1" in target and target.endswith("#top")


# --------------------------------------------------------------------------- schemes


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "data:text/html,<script>alert(1)</script>",
        "blob:https://example.com/2f1c",
        "about:blank",
        "javascript:alert(1)",
        "vbscript:msgbox(1)",
        "view-source:https://example.com",
        "jar:https://example.com!/a",
        "ftp://example.com/pub",
        "ws://example.com/socket",
        "mailto:someone@example.com",
        "tel:08001234567",
        "chrome://version",
        "chrome-extension://abcdefhm/content/x.html",
        "gopher://example.com/1",
        "intent://scan/#Intent;scheme=x;end",
    ],
)
def test_non_web_schemes_are_refused(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        check_public(url, monkeypatch=None)


@pytest.mark.parametrize("url", ["example.com/report", "//example.com/report", "/report", "report"])
def test_a_destination_needs_an_absolute_web_scheme(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        validate_target_url(url)


def test_a_relative_href_resolves_against_its_page_base(monkeypatch):
    never_resolves(monkeypatch)
    assert validate_target_url("/credit/report", base="https://example.com/home") == "https://example.com/credit/report"
    assert validate_target_url("report", base="https://example.com/credit/home") == "https://example.com/credit/report"


def test_a_relative_href_cannot_point_at_the_lan(monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        validate_target_url("//127.0.0.1/admin", base="https://example.com/home")
    with pytest.raises(UrlNotAllowed):
        validate_target_url("file:///etc/passwd", base="https://example.com/home")


# --------------------------------------------------------------------------- credentials, ports, shapes


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.com/report",
        "https://user@example.com/report",
        "https://:@example.com/report",
        "https://example.com@evil-peer.example.org/report",  # looks like a host, is a username
    ],
)
def test_urls_carrying_credentials_are_refused_not_stripped(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed, match="credential"):
        validate_target_url(url)


@pytest.mark.parametrize("url", ["http://example.com:8080/", "https://example.com:8443/", "http://example.com:22/"])
def test_only_web_ports(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed, match="port"):
        validate_target_url(url)


@pytest.mark.parametrize(
    "url",
    ["", None, "   ", "https://", "https:///report", "https://exam ple.com/", "https://example.com/a\nb",
     "https://example.com/\x00", "http://" + "a" * 300 + ".com/", "http://example.com/" + "q" * 5000],
)
def test_empty_malformed_or_oversized_targets(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        validate_target_url(url)


def test_refusal_is_a_readable_value_error():
    # The API layer catches ValueError to build {"detail": ...}; the type must stay compatible.
    error = UrlNotAllowed("host 127.0.0.1 is a private or loopback address")
    assert isinstance(error, ValueError)
    assert "private" in str(error)


# --------------------------------------------------------------------------- private destinations


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/report",
        "http://LOCALHOST:80/report",
        "http://localhost.localdomain/report",
        "http://127.0.0.1/report",
        "http://127.0.0.53/x",
        "http://[::1]/report",
        "http://10.42.0.178:6280/x",
        "http://10.0.0.5/x",
        "http://192.168.1.1/admin",
        "http://172.16.9.9/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
        "http://224.0.0.1/",
        "http://[ff02::1]/",
        "http://[fe80::1%25eth0]/",
        "http://[fc00::1234]/",
        "http://[::ffff:127.0.0.1]/",
        "http://100.64.0.1/x",  # CGNAT range, not a public website
        "http://198.18.0.1/x",  # benchmark range, reserved
    ],
)
def test_localhost_private_linklocal_and_multicast_destinations(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        validate_target_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://internal-host/x",
        "http://internal-client/x",
        "http://internal-service/x",
        "http://wpad/x",
        "http://metadata/google",
        "http://litellm.internal:4000/x",
        "http://printer.local/x",
        "http://box.internal/x",
        "http://host.corp/x",
        "http://router.home.arpa/x",
        "http://svc.cluster/x",
        "http://db.invalid/x",
        "http://host.test/x",
    ],
)
def test_internal_names_and_single_label_hosts_never_reach_out(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        validate_target_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",           # 127.0.0.1 in decimal
        "http://0x7f000001/",           # 127.0.0.1 in hex
        "http://127.1/",                # loopback shorthand
        "http://3232235777/",           # 192.168.1.1 in decimal
        "http://10.1/x",                # private, and no TLD
    ],
)
def test_ip_shorthands_are_refused(url, monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed):
        validate_target_url(url)


@pytest.mark.parametrize(
    "address,expected",
    [
        ("127.0.0.1", True), ("::1", True), ("10.1.2.3", True), ("192.168.0.1", True),
        ("172.20.0.1", True), ("169.254.10.10", True), ("224.0.0.5", True), ("239.1.1.1", True),
        ("0.0.0.0", True), ("::ffff:10.0.0.1", True), ("fc00::1", True), ("fe80::1", True),
        ("93.184.216.34", False), ("2606:4700:4700::6810:f8f9", False), ("8.8.8.8", False),
        ("not-an-ip", False), ("", False),
    ],
)
def test_is_private_address_helper(address, expected):
    assert is_private_address(address) is expected


# --------------------------------------------------------------------------- DNS answers


def test_a_public_name_that_answers_private_is_refused(monkeypatch):
    # The classic rebinding trick: a real-looking hostname whose A record is the loopback.
    with pytest.raises(UrlNotAllowed, match="public addresses"):
        check_public("http://127.0.0.1.nip.io/report", monkeypatch, "127.0.0.1")


def test_one_private_answer_among_public_ones_refuses_the_whole_host(monkeypatch):
    with pytest.raises(UrlNotAllowed, match="public addresses"):
        check_public("https://dual.example.com/report", monkeypatch, PUBLIC_IP, "10.42.0.178")


def test_a_name_with_no_answers_is_an_error_not_a_pass(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver())
    with pytest.raises(UrlNotAllowed):
        asyncio.run(validate_public_url("https://gone.example.com/report"))


def test_a_failing_lookup_is_reported_as_refusal(monkeypatch):
    def _fail(*args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)
    with pytest.raises(UrlNotAllowed, match="does not resolve"):
        asyncio.run(validate_public_url("https://nowhere.example.com/report"))


def test_a_hanging_lookup_is_cut_off(monkeypatch):
    monkeypatch.setattr(network, "DNS_TIMEOUT_SECONDS", 0.2)

    def _slow(*args, **kwargs):
        time.sleep(1.0)
        return fake_resolver(PUBLIC_IP)("x", 0)

    monkeypatch.setattr(socket, "getaddrinfo", _slow)
    started = time.monotonic()
    with pytest.raises(UrlNotAllowed, match="timed out"):
        asyncio.run(validate_public_url("https://slow.example.com/report"))
    assert time.monotonic() - started < 5, "the DNS timeout must bound the wait, not the socket default"


def test_every_call_re_resolves_so_a_flipping_record_cannot_slip_through(monkeypatch):
    check_public("https://example.com/report", monkeypatch, PUBLIC_IP)
    with pytest.raises(UrlNotAllowed, match="public addresses"):
        check_public("https://example.com/report", monkeypatch, "192.168.67.89")


# --------------------------------------------------------------------------- onion


def test_onion_never_normalised_through_the_resolver(monkeypatch):
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed, match="onion"):
        asyncio.run(validate_public_url("http://n3r2v4r9i3x2v7qo.onion/c/summary"))
    # Reaching here without AssertionError *is* the assertion: no lookup happened.


def test_onion_passes_only_when_the_source_asks_for_tor(monkeypatch):
    never_resolves(monkeypatch)
    target = asyncio.run(validate_public_url("http://n3r2v4r9i3x2v7qo.onion/c/summary", True))
    assert target == "http://n3r2v4r9i3x2v7qo.onion/c/summary"


def test_onion_still_needs_a_real_address_and_a_web_scheme(monkeypatch):
    never_resolves(monkeypatch)
    for url in ["http://onion/x", "https://.onion/x", "file:///tmp/x.onion", "http://user:pw@abc.onion/x"]:
        with pytest.raises(UrlNotAllowed):
            validate_target_url(url, allow_onion=True)


def test_an_onion_port_is_the_hidden_service_owner_business(monkeypatch):
    """Port 80/443 exists to stop hops at *our* services; a hidden service on :8081 is reachable
    by anyone on Tor, so an explicitly-Tor source keeps whatever port it publishes."""
    never_resolves(monkeypatch)
    assert validate_target_url("http://abc.onion:8081/x", allow_onion=True) == "http://abc.onion:8081/x"
    # ... and the same port on a clear-web host is still refused.
    with pytest.raises(UrlNotAllowed, match="port"):
        validate_target_url("http://example.com:8081/x")


@pytest.mark.parametrize("host,expected", [("abc.onion", True), ("sub.abc.onion", True), ("onion", False),
                                           ("example.com", False), (".onion", False), ("onion.example.com", False)])
def test_is_onion_host_helper(host, expected):
    assert is_onion_host(host) is expected


def test_listening_an_onion_in_the_allowlist_does_not_enable_tor(monkeypatch):
    """``allow_onion`` is the switch for Tor; an allowlist entry is only a name filter."""
    never_resolves(monkeypatch)
    with pytest.raises(UrlNotAllowed, match="onion"):
        check("http://abc.onion/x", allowed_hosts=["abc.onion"])


# --------------------------------------------------------------------------- allowlist


@pytest.mark.parametrize(
    "host,entries,expected",
    [
        ("example.com", ["example.com"], True),
        ("www.example.com", ["example.com"], True),
        ("example.com", [".example.com"], True),
        ("deep.sub.example.com", ["sub.example.com"], True),
        ("example.com.evil.io", ["example.com"], False),   # suffix lookalike
        ("notexample.com", ["example.com"], False),
        ("evil.example.com", ["www.example.com"], False),
        ("example.com", [], True),                          # unconfigured = unrestricted
        ("example.com", ["  "], True),
        ("example.com", ["*"], True),
        ("any.host", ["*"], True),
        ("login.example.com", ["https://login.example.com/start?x=1"], True),
        ("198.51.100.7", ["198.51.100.7"], True),
        ("example.com", None, True),
    ],
)
def test_host_allowed_helper(host, entries, expected):
    assert host_allowed(host, entries) is expected


def test_allowlist_restricts_the_source_site_only(monkeypatch):
    target = check_public(
        "https://secure.broker.example.com/report", monkeypatch, allowed_hosts=["broker.example.com"]
    )
    assert target == "https://secure.broker.example.com/report"
    with pytest.raises(UrlNotAllowed, match="allowlist"):
        check_public(
            "https://secure.brokerother.example.com/report", monkeypatch, allowed_hosts=["broker.example.com"]
        )
    # Subresources are still public-checked even when off the allowlist — that is the
    # browser's job — so the allowlist failure must be about the allowlist, not DNS.
    never_target = asyncio.run(validate_public_url("https://cdn.example.com/x.css", allowed_hosts=None))
    assert never_target.endswith("/x.css")


def test_allowlist_does_not_license_a_private_host(monkeypatch):
    with pytest.raises(UrlNotAllowed):
        check_public("http://10.42.0.178/report", monkeypatch, allowed_hosts=["10.42.0.178"])


def test_allowlist_checks_the_resolved_target_after_a_base_join(monkeypatch):
    never_resolves(monkeypatch)
    assert validate_target_url("/home", base="https://broker.example.com/x", allowed_hosts=["broker.example.com"])
    with pytest.raises(UrlNotAllowed, match="allowlist"):
        validate_target_url(
            "https://tracker.example.com/pixel",
            base="https://broker.example.com/x",
            allowed_hosts=["broker.example.com"],
        )
