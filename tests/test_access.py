"""Acceptance fixtures for the no-token home-network mode.

Privacy Bot has no login, so these tests are the whole boundary: a request from outside the
configured LAN/Tailscale subnets must be refused even when it asserts a private address in a
forwarding header, and the one trusted proxy must be refused when its assertion is missing,
duplicated, malformed or a chain. Every request here is a hand-built ASGI scope with raw
(bytes, bytes) headers — no sockets, and duplicate behaviour is exercised independently.
"""
from __future__ import annotations

import sys
from ipaddress import ip_network
from pathlib import Path

import pytest
from starlette.requests import Request

ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from privacy_bot.access import NetworkAccess  # noqa: E402

LAN = "10.42.0.0/24"
TAILSCALE = "100.64.0.0/10"
PROXY = "172.30.0.2/32"
PROXY_IP = "172.30.0.2"


def guard(allowed=(LAN, TAILSCALE), proxies=(PROXY,)):
    return NetworkAccess(list(allowed), list(proxies))


def hdr(name, value):
    return (name.encode("latin-1"), value.encode("latin-1"))


def xff(value):
    return hdr("x-forwarded-for", value)


def request_from(peer, *headers):
    """A GET scope whose peer is *peer* (None = no client address at all)."""
    return Request({
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": "/", "raw_path": b"/", "query_string": b"", "root_path": "",
        "server": ("privacy-bot", 8000), "headers": list(headers),
        "client": None if peer is None else (peer, 40012),
    })


# --- direct peers: the socket address is the whole story -------------------------------------

@pytest.mark.parametrize("peer, expected", [
    ("10.42.0.5", True), ("100.80.1.2", True),
    ("10.42.9.9", False), ("192.168.1.7", False), ("8.8.8.8", False),
    ("172.30.0.4", False),           # an unrelated docker network, not the trusted proxy
    ("2a02:808::1", False), ("fd12:3456::10", False), ("::1", False), ("169.254.9.9", False),
])
def test_direct_peer_is_judged_only_by_its_socket_address(peer, expected):
    assert guard().permits(request_from(peer)) is expected


@pytest.mark.parametrize("peer", ["8.8.8.8", "172.30.0.4", "192.168.1.7", "10.221.0.5"])
def test_forged_forwarding_header_confers_no_privilege(peer):
    assert guard().permits(request_from(peer, xff("10.42.0.5"))) is False


@pytest.mark.parametrize("header", [xff("8.8.8.8"), xff("not-an-ip"), xff("10.42.0.5, 8.8.8.8")])
def test_a_permitted_address_is_not_locked_out_by_a_bogus_header(header):
    assert guard().permits(request_from("10.42.0.5", header)) is True


@pytest.mark.parametrize("peer", [None, "", "   ", "junk", "localhost", "10.42.0.5/24", "10.42.0.5:80"])
def test_missing_or_malformed_peer_is_refused(peer):
    assert guard().permits(request_from(peer)) is False


# --- the one trusted proxy ----------------------------------------------------------------

@pytest.mark.parametrize("header", [
    xff("10.42.0.5"), xff("100.80.1.2"), xff("::ffff:10.42.0.5"),
    xff(" 10.42.0.5 "), hdr("X-Forwarded-For", "10.42.0.5"),
])
def test_trusted_proxy_may_assert_one_allowed_address(header):
    assert guard().permits(request_from(PROXY_IP, header)) is True


def test_other_client_supplied_headers_alongside_are_ignored():
    headers = (xff("10.42.0.5"), hdr("x-real-ip", "8.8.8.8"), hdr("forwarded", 'for="8.8.8.8"'))
    assert guard().permits(request_from(PROXY_IP, *headers)) is True


@pytest.mark.parametrize("headers", [
    (),                                                 # silent proxy
    (xff("10.42.0.5"), xff("10.42.0.9")),             # duplicate, different claims
    (xff("10.42.0.5"), xff("10.42.0.5")),             # duplicate, identical claims
    (xff("10.42.0.5"), hdr("x-forwarded-for", "10.42.0.9")),   # duplicate, other casing
    (hdr("x-real-ip", "10.42.0.5"),),                  # headers this guard does not read
    (hdr("forwarded", 'for="10.42.0.5"'),),            # never substituted for XFF
])
def test_proxy_without_exactly_one_forwarded_for_is_refused(headers):
    assert guard().permits(request_from(PROXY_IP, *headers)) is False


@pytest.mark.parametrize("value", [
    "8.8.8.8", "172.30.0.2", "fd00::5", "10.42.9.9", "not-an-ip", "", "   ", "10.42.0.5/24",
    "10.42.0.5, 10.42.0.9", "10.42.0.5,8.8.8.8", "10.42.0.5,", ", 10.42.0.5", "::ffff:8.8.8.8",
])
def test_proxy_assertion_must_be_one_allowed_plain_address(value):
    assert guard().permits(request_from(PROXY_IP, xff(value))) is False


def test_proxy_peer_address_may_itself_be_ipv4_mapped():
    assert guard().permits(request_from("::ffff:172.30.0.2", xff("10.42.0.5"))) is True


def test_scope_without_headers_gives_the_proxy_nothing_to_assert():
    request = request_from(PROXY_IP, xff("10.42.0.5"))
    del request.scope["headers"]
    assert guard().permits(request) is False


# --- address families ----------------------------------------------------------------------

@pytest.mark.parametrize("allowed, peer, expected", [
    (["fd00:1234::/64"], "fd00:1234::11", True),
    (["fd00:1234::/64"], "fd00:5678::11", False),
    (["fd00:1234::/64"], "2001:4860:8802::1", False),
    (["10.42.0.0/24"], "fd00::5", False),
    (["fd00::/8"], "10.42.0.5", False),
    (["fd00::/8"], "::ffff:10.42.0.5", False),   # mapped IPv4 must not match an IPv6 rule
    (["10.42.0.0/24"], "::ffff:10.42.0.5", True),
    (["10.42.0.5/24"], "10.42.0.9", True),      # host bits in config are tolerated
])
def test_families_stay_distinct_and_ula_is_supported(allowed, peer, expected):
    assert guard(allowed=allowed, proxies=()).permits(request_from(peer)) is expected


def test_no_proxy_configured_means_forwarding_is_never_trusted():
    lan_only = guard(allowed=[LAN], proxies=[])
    assert lan_only.permits(request_from("10.42.0.5")) is True
    assert lan_only.permits(request_from(PROXY_IP, xff("10.42.0.5"))) is False


# --- configuration is fail-closed ----------------------------------------------------------

@pytest.mark.parametrize("allowed", [
    [], [""], ["   "], ["not-a-network"], ["10.42.0.0/33"], [10], ["0.0.0.0/0"], ["::/0"],
    ["8.8.8.0/24"], ["127.0.0.0/8"], ["::1/128"], ["169.254.0.0/16"], ["224.0.0.0/4"],
    ["ff00::/8"], ["fe80::/10"], ["2a02:1234::/32"], ["100.128.0.0/10"],
])
def test_allowed_networks_must_be_explicit_private_subnets(allowed):
    with pytest.raises(ValueError):
        NetworkAccess(list(allowed), [PROXY])


@pytest.mark.parametrize("proxies", [[""], ["0.0.0.0/0"], ["8.8.8.8/32"], ["127.0.0.1/32"],
                                     ["2a02:1234::/64"], ["not-a-network"], [None]])
def test_trusted_proxies_are_held_to_the_same_rule(proxies):
    with pytest.raises(ValueError):
        NetworkAccess([LAN], list(proxies))


def test_valid_configuration_is_kept_as_parsed_subnets():
    parsed = guard()
    assert parsed.allowed == (ip_network(LAN), ip_network(TAILSCALE))
    assert parsed.proxies == (ip_network(PROXY),)


# --- programmer errors are not swallowed as a denial ---------------------------------------

def test_a_non_request_is_an_error_not_a_denial():
    with pytest.raises(AttributeError):
        guard().permits(object())


class _PeerOnly:
    client = (PROXY_IP, 40012)          # no .scope: a wiring bug must surface, not deny


def test_a_half_built_request_surfaces_its_bug():
    with pytest.raises(AttributeError):
        guard().permits(_PeerOnly())
