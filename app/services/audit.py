"""Audit Logger (OG-06 · RF-18).

Cada acción sensible inserta un registro en auth.audit_log (solo INSERT). Las
revocaciones y los cambios de rol se sellan con la TTP cuando TSA_URL está configurada.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import correlation_id_var
from app.crypto.tsa_client import request_timestamp
from app.models import AuditLog, utcnow


class Actions:
    REGISTER = "user.registered"
    LOGIN_OK = "login.success"
    LOGIN_FAIL = "login.failed"
    LOCKED = "account.locked"
    REFRESH_REUSE = "refresh.reuse_detected"
    LOGOUT = "logout"
    USER_CREATED = "user.created"
    ROLE_CHANGED = "user.role_changed"
    STATUS_CHANGED = "user.status_changed"
    CERT_ISSUED = "certificate.issued"
    CERT_REVOKED = "certificate.revoked"
    CRL_PUBLISHED = "crl.published"
    ENROLL_CODE = "device.enrollment_code_created"
    DEVICE_ENROLLED = "device.enrolled"
    DEVICE_REVOKED = "device.revoked"
    KEY_ROTATED = "jwt.key_rotated"
    PKI_BOOTSTRAP = "pki.dev_bootstrap"


def record(
    db: Session,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    ip: str | None = None,
    details: dict[str, Any] | None = None,
    tsa_url: str = "",
) -> AuditLog:
    entry = AuditLog(
        actor=actor[:128],
        action=action,
        target=(target or "")[:255] or None,
        ip=ip,
        correlation_id=correlation_id_var.get(),
        details=details,
        timestamp=utcnow(),
    )
    if tsa_url:
        canonical = json.dumps(
            {
                "actor": entry.actor,
                "action": action,
                "target": entry.target,
                "ts": entry.timestamp.isoformat(),
                "details": details,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
        entry.tsa_token = request_timestamp(tsa_url, canonical)
    db.add(entry)
    return entry
