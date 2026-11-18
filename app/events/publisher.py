"""Event Publisher (BT-08 · sección 3.5.4): eventos de M1 en Redis Streams.

Evento publicado por M1: certificate.revoked {serial, profile, revoked_at}.
Si EVENTS_HMAC_KEY_BASE64 está configurada, cada mensaje lleva `sig` =
HMAC-SHA256(key, ts || "." || payload) para que los consumidores verifiquen el origen.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any

import redis

from app.core.logging import correlation_id_var

log = logging.getLogger(__name__)


class EventPublisher:
    def __init__(
        self, client: redis.Redis | None, stream: str, hmac_key: bytes | None = None
    ) -> None:
        self._r = client
        self.stream = stream
        self._key = hmac_key
        self.sent: list[dict[str, str]] = []  # útil para pruebas y depuración local

    def publish(self, event: str, data: dict[str, Any], correlation_id: str | None = None) -> None:
        payload = json.dumps(data, separators=(",", ":"), sort_keys=True, default=str)
        ts = str(int(time.time()))
        fields: dict[str, str] = {
            "event": event,
            "payload": payload,
            "ts": ts,
            "producer": "m1-auth",
            "correlation_id": correlation_id or correlation_id_var.get() or "",
        }
        if self._key:
            fields["sig"] = hmac.new(
                self._key, f"{ts}.{payload}".encode(), hashlib.sha256
            ).hexdigest()
        self.sent.append(fields)
        if self._r is None:
            return
        try:
            self._r.xadd(self.stream, fields, maxlen=10_000, approximate=True)  # type: ignore[arg-type]
        except redis.RedisError:
            log.warning("No se pudo publicar %s en Redis Streams", event)
