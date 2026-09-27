"""Explicit home-network access guard for the no-token mode.

In optional network mode, access is decided by where the request arrived from rather than
an application login. The socket peer address is the only trustworthy evidence, and
``X-Forwarded-For`` counts solely when the peer is a proxy this config names explicitly — a client
that sprays its own private address into a forwarding header gains nothing.

Configuration is fail-closed and narrow on purpose: this mode must never quietly become an
internet-facing anonymous switch. ``is_private`` is deliberately *not* consulted, because on
CPython 3.12 it answers False for 100.64.0.0/10 (which would break Tailscale) and True for
127.0.0.0/8 (which would admit loopback). Instead every entry must sit inside one of the ranges
below, and cross-family comparisons are filtered out (``subnet_of`` raises TypeError on those).
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network

#: The only ranges this no-login mode may ever serve: RFC1918, IPv6 ULA, Tailscale CGNAT.
PRIVATE_SCOPES = tuple(
    ip_network(cidr) for cidr in
    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10")
)

FORWARDED_FOR = b"x-forwarded-for"


def _parse_address(value: object):
    """Parse an address, mapping IPv4-in-IPv6 to IPv4 so both families mean one thing.

    Raises ``ValueError`` for anything missing, padded-with-junk or otherwise not an address.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("address must be a non-empty string")
    address = ip_address(value.strip())
    if address.version == 6 and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _parse_network(value: object, label: str):
    """Parse one configured CIDR and prove it is an explicit, private, non-special subnet."""
    if not isinstance(value, str):
        raise ValueError(f"{label} entries must be CIDR strings")
    network = ip_network(value.strip(), strict=False)
    if network.prefixlen == 0:
        raise ValueError(f"{label} must name an explicit subnet, not a default route")
    base = network.network_address
    if base.is_loopback or base.is_multicast or base.is_unspecified:
        raise ValueError(f"{label} may not name loopback, multicast or unspecified addresses")
    if not any(network.version == scope.version and network.subnet_of(scope)
               for scope in PRIVATE_SCOPES):
        raise ValueError(f"{label} must sit inside RFC1918, IPv6 ULA or Tailscale 100.64.0.0/10")
    return network


class NetworkAccess:
    """Allow a request only when its real origin falls in an explicitly configured subnet.

    ``allowed_networks`` is required and non-empty; ``trusted_proxies`` may be empty, which simply
    means no reverse proxy sits in front and forwarding headers are therefore worth nothing.
    """

    def __init__(self, allowed_networks: list[str], trusted_proxies: list[str]) -> None:
        self.allowed = tuple(_parse_network(value, "allowed_networks") for value in allowed_networks)
        self.proxies = tuple(_parse_network(value, "trusted_proxies") for value in trusted_proxies)
        if not self.allowed:
            raise ValueError("allowed_networks must list at least one private subnet")

    @staticmethod
    def _matches(address, networks) -> bool:
        return any(net.version == address.version and address in net for net in networks)

    @staticmethod
    def _peer(request):
        """Socket peer address, or ``None`` when it is missing or malformed."""
        client = request.client
        if client is None or client.host is None:
            return None
        try:
            return _parse_address(client.host)
        except ValueError:
            return None

    @staticmethod
    def _forwarded(request):
        """The one address a trusted proxy asserted, or ``None``.

        Read from the raw ASGI header list so a duplicated header cannot be merged into one value
        by a mapping, and so a comma chain — which an attacker may have seeded upstream — is never
        reduced to "the first entry is probably real".
        """
        values = [value for key, value in request.scope.get("headers") or ()
                  if key.lower() == FORWARDED_FOR]
        if len(values) != 1 or b"," in values[0]:
            return None
        try:
            return _parse_address(values[0].decode("latin-1"))
        except ValueError:
            return None

    def permits(self, request) -> bool:
        """True when this request may reach the no-token app, False to refuse it."""
        peer = self._peer(request)
        if peer is None:
            return False
        if self._matches(peer, self.proxies):
            forwarded = self._forwarded(request)
            return forwarded is not None and self._matches(forwarded, self.allowed)
        # Everyone else is judged only by the network their own connection proves.
        return self._matches(peer, self.allowed)
