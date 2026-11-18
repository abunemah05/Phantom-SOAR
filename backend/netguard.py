"""SSRF guard: outbound requests to caller-influenced URLs must only reach public addresses.

Blocks loopback, private (RFC 1918 / ULA), link-local (including the 169.254.169.254 cloud metadata
address), CGNAT, multicast, reserved and unspecified ranges, for IPv4 and IPv6 (IPv4-mapped IPv6 is
unwrapped first). Hostnames are resolved and EVERY returned address must be public. The guarded httpx
transport re-resolves and re-checks at connection time and connects to the vetted address, so DNS
rebinding between the check and the request cannot slip through.

Reference: OWASP SSRF Prevention Cheat Sheet
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
"""
import ipaddress
import logging
import socket
from typing import List, Optional
from urllib.parse import urlparse

import httpcore
import httpx

logger = logging.getLogger(__name__)

_EXTRA_BLOCKED = (
    ipaddress.ip_network("169.254.0.0/16"),     # link-local incl. cloud metadata 169.254.169.254
    ipaddress.ip_network("100.64.0.0/10"),      # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("fd00:ec2::/32"),      # AWS IPv6 metadata
    ipaddress.ip_network("fe80::/10"),
)


class UnsafeURLError(ValueError):
    """The URL or the address it resolves to is not allowed."""


def is_public_ip(value) -> bool:
    try:
        ip = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_private:
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)


def resolve_host(host: str, port: int = 443) -> List[str]:
    """All addresses a host resolves to (a literal IP resolves to itself)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"Host '{host}' does not resolve.") from exc
    addresses = []
    for info in infos:
        address = info[4][0].split("%")[0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise UnsafeURLError(f"Host '{host}' does not resolve.")
    return addresses


def assert_public_host(host: str, port: int = 443) -> List[str]:
    """Resolve `host` and require every address to be public; returns the addresses."""
    if not host:
        raise UnsafeURLError("URL has no host.")
    addresses = resolve_host(host, port)
    for address in addresses:
        if not is_public_ip(address):
            raise UnsafeURLError(f"Host '{host}' resolves to a non-public address and is not allowed.")
    return addresses


def assert_public_url(url: str) -> str:
    """Validate scheme, credentials, and that the host resolves only to public addresses."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError("Only http and https URLs are allowed.")
    if parsed.username or parsed.password:
        raise UnsafeURLError("URLs with embedded credentials are not allowed.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeURLError("Invalid port in URL.") from exc
    assert_public_host(parsed.hostname or "", port)
    return url.strip()


def same_origin_host(url_a: str, url_b: str) -> bool:
    """True when two URLs have the same scheme-less host and port."""
    def key(url: str):
        parsed = urlparse(url if "://" in (url or "") else f"https://{url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return ((parsed.hostname or "").lower(), port)
    return bool(url_a and url_b) and key(url_a) == key(url_b)


class _GuardedBackend(httpcore.SyncBackend):
    """Resolves at connect time, re-checks every address, and connects to the vetted IP."""

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = assert_public_host(host, port)
        last_error: Optional[Exception] = None
        for address in addresses:
            try:
                return super().connect_tcp(address, port, timeout=timeout, local_address=local_address,
                                           socket_options=socket_options)
            except httpcore.ConnectError as exc:
                last_error = exc
        raise last_error or httpcore.ConnectError(f"Could not connect to {host}")


def guarded_transport(verify=True) -> httpx.HTTPTransport:
    transport = httpx.HTTPTransport(verify=verify)
    # httpx does not expose the network backend; httpcore's ConnectionPool keeps it here.
    # https://www.encode.io/httpcore/network-backends/
    transport._pool._network_backend = _GuardedBackend()
    return transport


def guarded_client(**kwargs) -> httpx.Client:
    """httpx.Client whose connections can only reach public addresses (redirects are not followed)."""
    verify = kwargs.pop("verify", True)
    kwargs.setdefault("follow_redirects", False)
    # No environment proxies: a proxy would resolve and connect to the target itself, bypassing the check.
    kwargs.setdefault("trust_env", False)
    return httpx.Client(transport=guarded_transport(verify=verify), **kwargs)
