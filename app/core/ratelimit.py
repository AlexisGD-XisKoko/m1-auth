"""Rate limiting por IP y por cuenta (BT-06 · RNF-05).

Contador con INCR + EXPIRE en ventanas de un minuto. Si Redis no está disponible se
usa un contador en memoria (solo para desarrollo y pruebas; no comparte estado entre
réplicas) y se registra una advertencia.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Protocol

import redis

log = logging.getLogger(__name__)

WINDOW_SECONDS = 60


class Counter(Protocol):
    def hit(self, key: str, window: int) -> int: ...


class MemoryCounter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, tuple[int, float]] = {}

    def hit(self, key: str, window: int) -> int:
        now = time.monotonic()
        with self._lock:
            count, expires = self._data.get(key, (0, now + window))
            if now >= expires:
                count, expires = 0, now + window
            count += 1
            self._data[key] = (count, expires)
            return count

    def reset(self) -> None:
        with self._lock:
            self._data.clear()


class RedisCounter:
    def __init__(self, client: redis.Redis) -> None:
        self._r = client

    def hit(self, key: str, window: int) -> int:
        pipe = self._r.pipeline()
        pipe.incr(key)
        pipe.expire(key, window, nx=True)
        count, _ = pipe.execute()
        return int(count)


class RateLimiter:
    def __init__(self, counter: Counter) -> None:
        self.counter = counter
        self._fallback = MemoryCounter()

    def allow(self, scope: str, identity: str, limit: int) -> tuple[bool, int]:
        """Devuelve (permitido, segundos de espera sugeridos)."""
        bucket = int(time.time() // WINDOW_SECONDS)
        ident = hashlib.sha256(identity.lower().encode()).hexdigest()[:32]
        key = f"m1:rl:{scope}:{ident}:{bucket}"
        try:
            count = self.counter.hit(key, WINDOW_SECONDS)
        except redis.RedisError:
            log.warning("Redis no disponible; rate limiting en memoria")
            count = self._fallback.hit(key, WINDOW_SECONDS)
        retry_after = WINDOW_SECONDS - int(time.time()) % WINDOW_SECONDS
        return count <= limit, retry_after


def build_rate_limiter(backend: str, redis_client: redis.Redis | None) -> RateLimiter:
    if backend == "redis" and redis_client is not None:
        return RateLimiter(RedisCounter(redis_client))
    return RateLimiter(MemoryCounter())
