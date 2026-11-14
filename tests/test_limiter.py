"""Limiter and lockout counters: per-process, and shared through Redis."""

import time

import fakeredis
import pytest
import redis

from sentriq import limiter


@pytest.fixture
def fake_redis(monkeypatch):
    """Two RedisStore instances backed by one fake server act like two workers."""
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kwargs: client))
    return client


def test_memory_store_stops_at_the_limit():
    store = limiter.MemoryStore()
    assert all(store.hit("10.0.0.1", limit=3, window=60) for _ in range(3))
    assert store.hit("10.0.0.1", limit=3, window=60) is False
    # A different client keeps its own budget.
    assert store.hit("10.0.0.2", limit=3, window=60) is True


def test_memory_store_window_rolls_over():
    store = limiter.MemoryStore()
    assert store.hit("10.0.0.3", limit=1, window=0.05) is True
    assert store.hit("10.0.0.3", limit=1, window=0.05) is False
    time.sleep(0.08)
    assert store.hit("10.0.0.3", limit=1, window=0.05) is True


def test_lockout_counts_pair_and_account_separately():
    store = limiter.MemoryStore()
    store.record_failure("10.0.0.9|alice", "alice")
    assert store.is_locked("10.0.0.9|alice", "alice") is False
    store.record_failure("10.0.0.9|alice", "alice")
    assert store.is_locked("10.0.0.9|alice", "alice") is False
    # A successful sign-in clears this pair only.
    store.clear("10.0.0.9|alice", "alice")
    assert store.is_locked("10.0.0.9|alice", "alice") is False


def test_redis_store_shares_the_limit_between_workers(fake_redis):
    worker_a = limiter.RedisStore("redis://example/0")
    worker_b = limiter.RedisStore("redis://example/0")

    # Three requests spread over two workers must exhaust one budget of three.
    assert worker_a.hit("10.1.0.5", limit=3, window=60) is True
    assert worker_b.hit("10.1.0.5", limit=3, window=60) is True
    assert worker_a.hit("10.1.0.5", limit=3, window=60) is True
    assert worker_b.hit("10.1.0.5", limit=3, window=60) is False


def test_redis_store_shares_login_lockout(fake_redis):
    worker_a = limiter.RedisStore("redis://example/0")
    worker_b = limiter.RedisStore("redis://example/0")
    pair, account = limiter.pair_key("10.2.0.5", "Bob"), limiter.username_key("Bob")

    for _ in range(limiter.LOGIN_LOCKOUT_THRESHOLD):
        worker_a.record_failure(pair, account)

    # The second worker sees the first worker's failures.
    assert worker_b.is_locked(pair, account) is True
    worker_b.clear(pair, account)
    assert worker_a.is_locked(pair, account) is False


def test_redis_outage_falls_back_to_process_memory():
    """Redis being down must not take the tracker down with it."""
    store = limiter.RedisStore("redis://127.0.0.1:1/0")
    assert store.hit("10.3.0.1", limit=2, window=60) is True
    assert store.hit("10.3.0.1", limit=2, window=60) is True
    assert store.hit("10.3.0.1", limit=2, window=60) is False
    store.record_failure("10.3.0.1|x", "x")
    assert store.is_locked("10.3.0.1|x", "x") is False


def test_get_store_prefers_redis_when_configured(monkeypatch, fake_redis):
    monkeypatch.setattr(limiter, "REDIS_URL", "redis://example/0")
    monkeypatch.setattr(limiter, "_store", None)
    assert limiter.get_store().kind == "redis"
    monkeypatch.setattr(limiter, "_store", None)
    monkeypatch.setattr(limiter, "REDIS_URL", None)
    assert limiter.get_store().kind == "memory"
    monkeypatch.setattr(limiter, "_store", None)
