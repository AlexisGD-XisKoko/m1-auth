"""Gestión de llaves: firma JWT con rotación por kid (BT-05 · RNF-04) y almacén de la CA.

- Llaves JWT en auth.signing_keys, privadas cifradas con la KEK.
- El JWKS publica la llave activa y las retiradas dentro del periodo de gracia.
- Certificados de la jerarquía y llaves de las intermedias en auth.ca_keys.
"""

from __future__ import annotations

import datetime as dt
import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import as_utc
from app.crypto import ca
from app.crypto.keystore import KeyStore, generate_p256_key
from app.crypto.tokens import new_kid, public_jwk
from app.models import CaKey, SigningKey, utcnow
from app.services import audit

log = logging.getLogger(__name__)


class PKINotReadyError(RuntimeError):
    pass


# --- Llaves JWT -------------------------------------------------------------------------


def create_signing_key(db: Session, keystore: KeyStore) -> SigningKey:
    key = generate_p256_key()
    kid = new_kid()
    row = SigningKey(
        kid=kid,
        public_jwk=public_jwk(key.public_key(), kid),
        encrypted_private_key=keystore.wrap_private_key(key, kid),
        status="active",
    )
    db.add(row)
    return row


def ensure_signing_key(db: Session, keystore: KeyStore) -> None:
    if db.scalar(select(SigningKey).where(SigningKey.status == "active")) is None:
        create_signing_key(db, keystore)
        db.commit()
        log.info("Llave de firma JWT creada")


def active_signing_key(db: Session, keystore: KeyStore) -> tuple[str, ec.EllipticCurvePrivateKey]:
    row = db.scalar(
        select(SigningKey)
        .where(SigningKey.status == "active")
        .order_by(SigningKey.created_at.desc())
    )
    if row is None:
        row = create_signing_key(db, keystore)
        db.commit()
    return row.kid, keystore.unwrap_private_key(row.encrypted_private_key, row.kid)


def published_keys(db: Session, settings: Settings) -> list[SigningKey]:
    """Llave activa + retiradas dentro del periodo de gracia (RNF-04)."""
    limit = utcnow() - dt.timedelta(hours=settings.jwt_retired_key_grace_hours)
    rows = db.scalars(select(SigningKey).order_by(SigningKey.created_at.desc())).all()
    out: list[SigningKey] = []
    for row in rows:
        retired = as_utc(row.retired_at)
        if row.status == "active" or (retired is not None and retired >= limit):
            out.append(row)
    return out


def verification_keys(db: Session, settings: Settings) -> dict[str, ec.EllipticCurvePublicKey]:
    from jwt.algorithms import ECAlgorithm

    keys: dict[str, ec.EllipticCurvePublicKey] = {}
    for row in published_keys(db, settings):
        pub = ECAlgorithm.from_jwk(row.public_jwk)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            keys[row.kid] = pub
    return keys


def rotate_signing_key(db: Session, keystore: KeyStore, actor: str, ip: str | None) -> str:
    now = utcnow()
    for row in db.scalars(select(SigningKey).where(SigningKey.status == "active")):
        row.status = "retired"
        row.retired_at = now
    new = create_signing_key(db, keystore)
    audit.record(db, actor=actor, action=audit.Actions.KEY_ROTATED, target=new.kid, ip=ip)
    db.commit()
    return new.kid


# --- Almacén de la CA -------------------------------------------------------------------


def store_hierarchy(
    db: Session,
    keystore: KeyStore,
    root_cert: x509.Certificate,
    intermediates: dict[str, tuple[x509.Certificate, ec.EllipticCurvePrivateKey]],
) -> None:
    """Guarda la raíz (solo certificado) y las intermedias con su llave cifrada."""
    for name, (cert, _) in intermediates.items():
        if not ca.verify_issued_by(cert, root_cert):
            raise PKINotReadyError(f"La intermedia {name} no está firmada por la raíz.")
    db.merge(CaKey(name="root", cert_pem=ca.cert_to_pem(root_cert), encrypted_private_key=None))
    for name, (cert, key) in intermediates.items():
        db.merge(
            CaKey(
                name=name,
                cert_pem=ca.cert_to_pem(cert),
                encrypted_private_key=keystore.wrap_private_key(key, f"ca:{name}"),
                status="active",
            )
        )


def ensure_dev_pki(db: Session, keystore: KeyStore, settings: Settings) -> bool:
    """Si no hay jerarquía y PKI_DEV_BOOTSTRAP=true, simula la ceremonia (solo dev)."""
    if db.get(CaKey, "root") is not None:
        return False
    if not settings.pki_dev_bootstrap or settings.is_production:
        log.warning("PKI sin cargar: ejecuta scripts/ceremony/04_load_intermediates.py")
        return False
    h = ca.build_dev_hierarchy()
    store_hierarchy(db, keystore, h.root_cert, h.intermediates)
    audit.record(
        db,
        actor="system",
        action=audit.Actions.PKI_BOOTSTRAP,
        target="root+intermedias",
        details={"root_sha256": ca.fingerprint_sha256(h.root_cert), "simulada": True},
    )
    db.commit()
    log.warning("PKI de DESARROLLO creada (raíz simulada; la llave raíz se descartó)")
    return True


def load_intermediate(
    db: Session, keystore: KeyStore, name: str
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, CaKey]:
    row = db.get(CaKey, name)
    if row is None or row.encrypted_private_key is None or row.status != "active":
        raise PKINotReadyError(f"Intermedia «{name}» no disponible.")
    cert = ca.pem_to_cert(row.cert_pem)
    key = keystore.unwrap_private_key(row.encrypted_private_key, f"ca:{name}")
    return cert, key, row


def root_certificate(db: Session) -> x509.Certificate:
    row = db.get(CaKey, "root")
    if row is None:
        raise PKINotReadyError("Certificado raíz de la TTP no cargado.")
    return ca.pem_to_cert(row.cert_pem)


def chain_pem(db: Session, intermediate: str | None = None) -> str:
    """Cadena en PEM: intermedia(s) primero y al final la raíz de la TTP (RF-15)."""
    names = [intermediate] if intermediate else list(ca.INTERMEDIATES)
    parts: list[str] = []
    for name in names:
        row = db.get(CaKey, name)
        if row is not None:
            parts.append(row.cert_pem)
    root = db.get(CaKey, "root")
    if root is None:
        raise PKINotReadyError("Certificado raíz de la TTP no cargado.")
    parts.append(root.cert_pem)
    return "".join(parts)
