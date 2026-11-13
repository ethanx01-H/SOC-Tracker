"""Resolve the originating client address when the app runs behind a proxy.

``request.client.host`` is the address of the last hop, which behind nginx or a
Docker port mapping is the proxy itself. Everything that keys on the client
address (rate limiting, login lockout, the audit trail) has to agree on one
resolved value, so it lives here rather than being recomputed per caller.
"""

import ipaddress
import logging

from fastapi import Request

from .config import TRUSTED_PROXIES

logger = logging.getLogger("soc_tracker.net")


def _network(entry: str):
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        logger.warning("Ignoring invalid TRUSTED_PROXIES entry: %s", entry)
        return None


TRUSTED_NETWORKS = tuple(
    network for network in (_network(entry) for entry in TRUSTED_PROXIES) if network is not None
)


def _address(value: str):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def is_trusted_proxy(value: str) -> bool:
    """True when this address is one of the proxies allowed to set forwarding headers."""
    address = _address(value)
    if address is None:
        return False
    return any(address in network for network in TRUSTED_NETWORKS)


def _forwarded_chain(request: Request) -> list[str]:
    raw = request.headers.get("x-forwarded-for", "")
    chain = [part.strip() for part in raw.split(",") if part.strip()]
    if chain:
        return chain
    real_ip = request.headers.get("x-real-ip", "").strip()
    return [real_ip] if real_ip else []


def client_ip(request: Request) -> str:
    """Return the address of the client that originated the request.

    X-Forwarded-For is only believed when the peer is a configured trusted
    proxy. The chain is read right to left, skipping hops we know are proxies,
    so a client cannot prepend a forged address and inherit someone else's
    rate-limit or lockout bucket.
    """
    cached = getattr(request.state, "client_ip", None)
    if cached:
        return cached

    peer = request.client.host if request.client else ""
    resolved = peer
    if peer and is_trusted_proxy(peer):
        valid = [entry for entry in _forwarded_chain(request) if _address(entry) is not None]
        for entry in reversed(valid):
            if not is_trusted_proxy(entry):
                resolved = entry
                break
        else:
            # Every hop was a proxy we trust: the leftmost entry is the origin.
            if valid:
                resolved = valid[0]

    request.state.client_ip = resolved
    return resolved
