"""Enrolamiento de escáneres (OG-08, BT-08 · RF-16, RF-17).

1. Un admin genera un código de un solo uso (32 bytes, 15 min); solo se guarda su hash.
2. La app validadora genera su par de llaves y envía CSR + código a /devices/enroll.
3. M1 marca el código con un UPDATE condicional (used_at IS NULL) para que no se use dos
   veces aunque lleguen dos peticiones simultáneas, firma con la intermedia de
   dispositivos y registra el dispositivo.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import bad_request, not_found
from app.crypto.keystore import KeyStore
from app.crypto.tokens import new_opaque_token, sha256_hex
from app.events.publisher import EventPublisher
from app.models import Certificate, Device, EnrollmentCode, utcnow
from app.services import audit, pki


def create_code(
    db: Session, settings: Settings, *, device_name: str, admin_id: uuid.UUID, ip: str | None
) -> tuple[EnrollmentCode, str]:
    raw = new_opaque_token()
    row = EnrollmentCode(
        code_hash=sha256_hex(raw),
        device_name=device_name,
        expires_at=utcnow() + dt.timedelta(minutes=settings.enrollment_code_ttl_minutes),
        created_by=admin_id,
    )
    db.add(row)
    audit.record(
        db,
        actor=str(admin_id),
        action=audit.Actions.ENROLL_CODE,
        target=device_name,
        ip=ip,
    )
    db.commit()
    return row, raw


def enroll(
    db: Session, keystore: KeyStore, *, code: str, csr_pem: str, ip: str | None
) -> tuple[Device, Certificate, str]:
    now = utcnow()
    code_hash = sha256_hex(code)
    result = db.execute(
        update(EnrollmentCode)
        .where(
            EnrollmentCode.code_hash == code_hash,
            EnrollmentCode.used_at.is_(None),
            EnrollmentCode.expires_at > now,
        )
        .values(used_at=now)
    )
    if getattr(result, "rowcount", 0) != 1:
        db.rollback()
        raise bad_request(
            "Código de enrolamiento inválido, expirado o ya utilizado.", "invalid-enrollment-code"
        )
    entry = db.scalar(select(EnrollmentCode).where(EnrollmentCode.code_hash == code_hash))
    if entry is None:  # imposible tras el UPDATE exitoso; defensa explícita
        raise bad_request("Código de enrolamiento inválido.", "invalid-enrollment-code")
    device = Device(nombre=entry.device_name, status="ACTIVE", enrolled_by=entry.created_by)
    db.add(device)
    db.flush()
    try:
        cert, chain = pki.issue(
            db,
            keystore,
            csr_pem=csr_pem,
            profile="device",
            requested_by=f"enrollment:{entry.id}",
            common_name=f"device-{device.id}",
            ip=ip,
        )
    except Exception:
        db.rollback()  # el código no se consume si el CSR es inválido
        raise
    device.cert_serial = cert.serial
    audit.record(
        db,
        actor=f"device:{device.id}",
        action=audit.Actions.DEVICE_ENROLLED,
        target=cert.serial,
        ip=ip,
        details={"nombre": device.nombre},
    )
    db.commit()
    return device, cert, chain


def revoke_device(
    db: Session,
    keystore: KeyStore,
    settings: Settings,
    publisher: EventPublisher,
    *,
    device_id: uuid.UUID,
    actor: str,
    ip: str | None,
) -> Device:
    """Desactiva un dispositivo (p. ej. teléfono perdido) y revoca su certificado (RF-17)."""
    device = db.get(Device, device_id)
    if device is None:
        raise not_found("Dispositivo no encontrado.")
    if device.cert_serial:
        cert = db.get(Certificate, device.cert_serial)
        if cert is not None and cert.status == "VALID":
            pki.revoke(
                db,
                keystore,
                settings,
                publisher,
                serial=device.cert_serial,
                reason="cessationOfOperation",
                actor=actor,
                ip=ip,
            )
    device.status = "REVOKED"
    audit.record(db, actor=actor, action=audit.Actions.DEVICE_REVOKED, target=str(device.id), ip=ip)
    db.commit()
    return device
