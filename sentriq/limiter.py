"""Rate limiting and login lockout counters, with an optional shared store.

Per-process counters are correct for one worker and wrong for several: each
worker counts only its own traffic, so N workers allow N times the limit, and a
lockout only applies to the worker that saw the failed attempt. Setting
``REDIS_URL`` moves both counters into Redis so every worker shares one view.

Without Redis the process keeps its own counters, which is what a single-worker
SQLite pilot needs and is stated plainly in the README.
"""

import logging
import time
from collections import defaultdict, deque

from .config import (
    LOGIN_ACCOUNT_LOCKOUT_THRESHOLD,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_LOCKOUT_THRESHOLD,
    REDIS_URL,
)

logger = logging.getLogger("sentriq.limiter")

MEMORY_MAX_KEYS = 10000


class MemoryStore:
    """Counters held in this process. Correct for exactly one worker."""

    kind = "memory"

    def __init__(self) -> None:
        self.rate: dict[str, deque[float]] = defaultdict(deque)
        self.pairs: dict[str, list[float]] = defaultdict(list)
        self.accounts: dict[str, list[float]] = defaultdict(list)

    def _prune(self, bucket: dict[str, list[float]], key: str, now: float) -> list[float]:
        entries = bucket[key]
        if entries:
            entries[:] = [stamp for stamp in entries if now - stamp < LOGIN_LOCKOUT_SECONDS]
        return entries

    def hit(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        attempts = self.rate[key]
        while attempts and now - attempts[0] > window:
            attempts.popleft()
        if len(attempts) >= limit:
            return False
        attempts.append(now)
        if len(self.rate) > MEMORY_MAX_KEYS:
            for stale in list(self.rate)[:2000]:
                self.rate.pop(stale, None)
        return True

    def record_failure(self, pair_key: str, account_key: str) -> None:
        now = time.monotonic()
        self.pairs[pair_key].append(now)
        self.accounts[account_key].append(now)
        for bucket in (self.pairs, self.accounts):
            if len(bucket) > MEMORY_MAX_KEYS:
                for stale in list(bucket)[:2000]:
                    bucket.pop(stale, None)

    def is_locked(self, pair_key: str, account_key: str) -> bool:
        now = time.monotonic()
        per_pair = self._prune(self.pairs, pair_key, now)
        per_account = self._prune(self.accounts, account_key, now)
        return (
            len(per_pair) >= LOGIN_LOCKOUT_THRESHOLD
            or len(per_account) >= LOGIN_ACCOUNT_LOCKOUT_THRESHOLD
        )

    def clear(self, pair_key: str, account_key: str) -> None:
        self.pairs.pop(pair_key, None)
        self.accounts.pop(account_key, None)

    def reset(self) -> None:
        self.rate.clear()
        self.pairs.clear()
        self.accounts.clear()


class RedisStore:
    """Counters shared by every worker, in Redis.

    Fixed-window counters: one key per window, incremented and expired. A failed
    Redis call must never lock the SOC out of its own tracker, so every error
    falls back to this process's memory and is logged once.
    """

    kind = "redis"
    prefix = "soctracker"

    def __init__(self, url: str) -> None:
        import redis

        self.client = redis.Redis.from_url(
            url, socket_timeout=1, socket_connect_timeout=1, decode_responses=True
        )
        self._fallback = MemoryStore()
        self._warned = False

    def _degraded(self, action: str, error: Exception) -> None:
        if not self._warned:
            logger.warning("Redis unavailable (%s: %s); falling back to per-process counters.", action, error)
            self._warned = True

    def hit(self, key: str, limit: int, window: float) -> bool:
        bucket = int(time.time() // window)
        redis_key = f"{self.prefix}:rl:{key}:{bucket}"
        try:
            pipe = self.client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, window + 1)
            count, _ = pipe.execute()
            return int(count) <= limit
        except Exception as error:  # redis.RedisError, but never let it 500 a request
            self._degraded("rate limit", error)
            return self._fallback.hit(key, limit, window)

    def record_failure(self, pair_key: str, account_key: str) -> None:
        try:
            pipe = self.client.pipeline()
            for redis_key in (f"{self.prefix}:lf:{pair_key}", f"{self.prefix}:la:{account_key}"):
                pipe.incr(redis_key)
                pipe.expire(redis_key, LOGIN_LOCKOUT_SECONDS)
            pipe.execute()
        except Exception as error:
            self._degraded("login lockout", error)
            self._fallback.record_failure(pair_key, account_key)

    def is_locked(self, pair_key: str, account_key: str) -> bool:
        try:
            per_pair = self.client.get(f"{self.prefix}:lf:{pair_key}")
            per_account = self.client.get(f"{self.prefix}:la:{account_key}")
        except Exception as error:
            self._degraded("lockout check", error)
            return self._fallback.is_locked(pair_key, account_key)
        return (
            int(per_pair or 0) >= LOGIN_LOCKOUT_THRESHOLD
            or int(per_account or 0) >= LOGIN_ACCOUNT_LOCKOUT_THRESHOLD
        )

    def clear(self, pair_key: str, account_key: str) -> None:
        try:
            self.client.delete(f"{self.prefix}:lf:{pair_key}", f"{self.prefix}:la:{account_key}")
        except Exception as error:
            self._degraded("lockout clear", error)
            self._fallback.clear(pair_key, account_key)

    def reset(self) -> None:
        self._fallback.reset()
        try:
            for pattern in ("rl:*", "lf:*", "la:*"):
                for key in self.client.scan_iter(f"{self.prefix}:{pattern}"):
                    self.client.delete(key)
        except Exception as error:
            self._degraded("reset", error)


_store = None


def get_store():
    """Return the process-wide counter store, creating it on first use."""
    global _store
    if _store is None:
        if REDIS_URL:
            try:
                _store = RedisStore(REDIS_URL)
                logger.info("Rate limiting and login lockout share counters through Redis.")
            except Exception as error:
                logger.warning("Could not initialise Redis (%s); using per-process counters.", error)
                _store = MemoryStore()
        else:
            _store = MemoryStore()
    return _store


def set_store(store) -> None:
    """Replace the store (used by tests)."""
    global _store
    _store = store


def store_kind() -> str:
    return get_store().kind


def reset_security_state() -> None:
    """Drop all limiter and lockout state (used by tests)."""
    get_store().reset()


def username_key(username: str) -> str:
    return (username or "").strip().lower()


def pair_key(client_address: str, username: str) -> str:
    return f"{client_address}|{username_key(username)}"


def is_login_locked(client_address: str, username: str) -> bool:
    store = get_store()
    return store.is_locked(pair_key(client_address, username), username_key(username))


def record_failed_login(client_address: str, username: str) -> None:
    store = get_store()
    store.record_failure(pair_key(client_address, username), username_key(username))


def clear_failed_logins(client_address: str, username: str) -> None:
    """Clear only this pair's counters after a successful login.

    Clearing the whole address bucket (the previous behaviour) let one valid
    login wipe the protection for every other account behind the same proxy.
    """
    store = get_store()
    store.clear(pair_key(client_address, username), username_key(username))
