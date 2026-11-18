"""Servicio de PKI: firma de CSR por perfil, revocación y CRL (OG-07, JO-07, BT-07 ·
RF-12, RF-13, RF-14, RF-15)."""

from __future__ import annotations

import datetime as dt
import logging
import threading
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import as_utc
from app.core.errors import ProblemError, bad_request, conflict, forbidden, not_found
from app.crypto import ca
from app.crypto.keystore import KeyStore
from app.crypto.tsa_client import request_timestamp
from app.events.publisher import EventPublisher
from app.models import CaKey, Certificate, Device, utcnow
from app.services import audit
from app.services.keys import PKINotReadyError, chain_pem, load_intermediate

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Requester:
    """Quién pide un certificado: un admin (JWT) o un servicio (certificado mTLS)."""

    kind: str  # "admin" | "service"
    name: str  # UUID del admin o CN del servicio


def authorize_profile(settings: Settings, requester: Requester, profile: str) -> None:
    if profile not in ca.PROFILES:
        raise bad_request("Perfil desconocido.")
    if profile == "device":
        # Los escáneres solo obtienen certificado con un código de un solo uso (RF-16).
        if requester.kind != "admin":
            raise forbidden("El perfil device solo se emite por enrolamiento o por un admin.")
        return
    if requester.kind == "admin":
        return
    allowed = settings.profile_policy().get(profile, set())
    if "*" not in allowed and requester.name not in allowed:
        raise forbidden(f"El servicio «{requester.name}» no puede solicitar el perfil {profile}.")


def issue(
    db: Session,
    keystore: KeyStore,
    *,
    csr_pem: str,
    profile: str,
    requested_by: str,
    valid_days: int | None = None,
    common_name: str | None = None,
    ip: str | None = None,
) -> tuple[Certificate, str]:
    try:
        csr = ca.load_csr(csr_pem)
        issuer_name = ca.PROFILES[profile].issuer
        issuer_cert, issuer_key, _ = load_intermediate(db, keystore, issuer_name)
        cert = ca.issue_certificate(
            csr, profile, issuer_cert, issuer_key, common_name=common_name, valid_days=valid_days
        )
    except ca.CSRValidationError as exc:
        raise bad_request(str(exc), "invalid-csr") from exc
    except PKINotReadyError as exc:
        raise ProblemError(503, "Service Unavailable", str(exc), "pki-not-ready") from exc
    row = Certificate(
        serial=ca.serial_hex(cert.serial_number),
        subject=cert.subject.rfc4514_string(),
        profile=profile,
        issuer=issuer_name,
        requested_by=requested_by,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        status="VALID",
        pem=ca.cert_to_pem(cert),
    )
    db.add(row)
    audit.record(
        db,
        actor=requested_by,
        action=audit.Actions.CERT_ISSUED,
        target=row.serial,
        ip=ip,
        details={"profile": profile, "subject": row.subject},
    )
    return row, chain_pem(db, issuer_name)


# --- CRL ---------------------------------------------------------------------------------

_crl_lock = threading.Lock()
_crl_cache: dict[str, str] = {}


def _invalidate_crl() -> None:
    with _crl_lock:
        _crl_cache.clear()


def build_crls(db: Session, keystore: KeyStore, settings: Settings) -> str:
    """CRL v2 de cada intermedia, concatenadas en PEM. Se cachea hasta la siguiente revocación."""
    with _crl_lock:
        if "pem" in _crl_cache:
            return _crl_cache["pem"]
    parts: list[str] = []
    for name in ca.INTERMEDIATES:
        try:
            cert, key, row = load_intermediate(db, keystore, name)
        except PKINotReadyError:
            continue
        revoked = db.scalars(
            select(Certificate).where(Certificate.issuer == name, Certificate.status == "REVOKED")
        ).all()
        row.crl_number += 1
        crl = ca.build_crl(
            cert,
            key,
            [
                (int(c.serial, 16), as_utc(c.revoked_at) or utcnow(), c.reason or "unspecified")
                for c in revoked
            ],
            crl_number=row.crl_number,
            next_update_hours=settings.crl_next_update_hours,
        )
        parts.append(crl.public_bytes(serialization.Encoding.PEM).decode())
    db.commit()
    pem = "".join(parts)
    with _crl_lock:
        _crl_cache["pem"] = pem
        _crl_cache.pop("tsa", None)
    return pem


def crl_timestamp(settings: Settings, crl_pem: str) -> str | None:
    """Sello RFC 3161 de la CRL vigente (si la TTP está configurada)."""
    with _crl_lock:
        if "tsa" in _crl_cache:
            return _crl_cache["tsa"] or None
    token = request_timestamp(settings.tsa_url, crl_pem.encode()) if settings.tsa_url else None
    with _crl_lock:
        _crl_cache["tsa"] = token or ""
    return token


def revoke(
    db: Session,
    keystore: KeyStore,
    settings: Settings,
    publisher: EventPublisher,
    *,
    serial: str,
    reason: str,
    actor: str,
    ip: str | None,
) -> Certificate:
    serial = serial.lower().removeprefix("0x")
    cert = db.get(Certificate, serial)
    if cert is None:
        raise not_found("Certificado no encontrado.")
    if cert.status == "REVOKED":
        raise conflict("El certificado ya estaba revocado.", "already-revoked")
    if reason not in ca.REASONS:
        raise bad_request(f"Motivo inválido. Usa uno de: {', '.join(ca.REASONS)}.")
    cert.status = "REVOKED"
    cert.revoked_at = utcnow()
    cert.reason = reason
    for device in db.scalars(select(Device).where(Device.cert_serial == serial)):
        device.status = "REVOKED"
    audit.record(
        db,
        actor=actor,
        action=audit.Actions.CERT_REVOKED,
        target=serial,
        ip=ip,
        details={"reason": reason, "profile": cert.profile},
        tsa_url=settings.tsa_url,
    )
    db.commit()
    _invalidate_crl()
    crl = build_crls(db, keystore, settings)
    tsa = crl_timestamp(settings, crl)
    audit.record(
        db,
        actor="system",
        action=audit.Actions.CRL_PUBLISHED,
        target=serial,
        details={"sellada": tsa is not None},
    ).tsa_token = tsa
    db.commit()
    revoked_at = as_utc(cert.revoked_at)
    publisher.publish(
        "certificate.revoked",
        {
            "serial": serial,
            "profile": cert.profile,
            "revoked_at": int(revoked_at.timestamp()) if revoked_at else None,
        },
    )
    return cert


def requester_from_client_cert(db: Session, header_value: str) -> Requester | None:
    """Autentica a un servicio por el certificado de cliente que reenvía el gateway (mTLS).

    Acepta PEM o DER en base64 (formato de `passTLSClientCert` de Traefik). Solo se usa
    si TRUST_PROXY_CLIENT_CERT=true, porque la cabecera debe venir del gateway.
    """
    import base64
    import urllib.parse

    value = urllib.parse.unquote(header_value).strip()
    try:
        if "BEGIN CERTIFICATE" in value:
            cert = x509.load_pem_x509_certificate(value.encode())
        else:
            cert = x509.load_der_x509_certificate(base64.b64decode(value))
    except ValueError:
        return None
    row = db.get(Certificate, ca.serial_hex(cert.serial_number))
    if row is None or row.status != "VALID" or row.profile != "service":
        return None
    issuer_row = db.get(CaKey, "services")
    if issuer_row is None or not ca.verify_issued_by(cert, ca.pem_to_cert(issuer_row.cert_pem)):
        return None
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return Requester("service", str(cn[0].value)) if cn else None


def list_certificates(
    db: Session, *, profile: str | None, status: str | None, limit: int, offset: int
) -> list[Certificate]:
    stmt = select(Certificate)
    if profile:
        stmt = stmt.where(Certificate.profile == profile)
    if status:
        stmt = stmt.where(Certificate.status == status)
    return list(
        db.scalars(stmt.order_by(Certificate.not_before.desc()).limit(limit).offset(offset))
    )


def days_left(cert: Certificate) -> int:
    na = as_utc(cert.not_after)
    return int((na - utcnow()) / dt.timedelta(days=1)) if na else 0
