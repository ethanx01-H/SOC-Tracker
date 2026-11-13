"""Client address resolution behind a trusted proxy."""

from starlette.requests import Request

from soc_tracker.net import client_ip, is_trusted_proxy


def make_request(peer: str, forwarded_for: str | None = None, real_ip: str | None = None) -> Request:
    headers = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode()))
    if real_ip is not None:
        headers.append((b"x-real-ip", real_ip.encode()))
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": headers,
        "client": (peer, 12345),
    })


def test_trusted_proxy_defaults_to_loopback():
    assert is_trusted_proxy("127.0.0.1")
    assert is_trusted_proxy("::1")
    assert not is_trusted_proxy("203.0.113.9")
    assert not is_trusted_proxy("testclient")


def test_forwarded_header_used_from_trusted_proxy():
    assert client_ip(make_request("127.0.0.1", "203.0.113.9")) == "203.0.113.9"


def test_forwarded_header_ignored_from_untrusted_peer():
    # A direct client cannot choose its own identity.
    assert client_ip(make_request("198.51.100.7", "203.0.113.9")) == "198.51.100.7"


def test_chain_skips_trusted_hops_right_to_left():
    chain = "203.0.113.9, 127.0.0.1, 127.0.0.1"
    assert client_ip(make_request("127.0.0.1", chain)) == "203.0.113.9"


def test_all_trusted_hops_fall_back_to_leftmost():
    assert client_ip(make_request("127.0.0.1", "127.0.0.1, 127.0.0.1")) == "127.0.0.1"


def test_x_real_ip_used_when_forwarded_for_absent():
    assert client_ip(make_request("127.0.0.1", real_ip="203.0.113.44")) == "203.0.113.44"


def test_invalid_forwarded_entries_are_skipped():
    assert client_ip(make_request("127.0.0.1", "not-an-ip, 203.0.113.9")) == "203.0.113.9"


def test_result_is_cached_on_the_request():
    request = make_request("127.0.0.1", "203.0.113.9")
    assert client_ip(request) == "203.0.113.9"
    assert client_ip(request) == "203.0.113.9"
