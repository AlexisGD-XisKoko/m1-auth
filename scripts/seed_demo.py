"""Datos semilla para la demo (OG-09). Idempotente: se puede correr varias veces.

Crea un usuario de cada rol, un certificado de evento de prueba y un escáner enrolado.
Uso: python scripts/seed_demo.py   (usa DATABASE_URL, KEK_BASE64 y PEPPER_BASE64 del .env)
Contraseña de todos los usuarios demo: variable SEED_PASSWORD (por defecto se genera e imprime).
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings  # noqa: E402
from app.core.database import build_engine, build_sessionmaker  # noqa: E402
from app.crypto.keystore import KeyStore  # noqa: E402
from app.models import Certificate, Device, User  # noqa: E402
from app.services import keys, pki, users  # noqa: E402

DEMO_USERS = [
    ("admin.demo@example.com", "Admin Demo", "admin"),
    ("staff.demo@example.com", "Staff Puerta Norte", "staff"),
    ("comprador.demo@example.com", "Comprador Demo", "buyer"),
]


def _csr(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return req.public_bytes(serialization.Encoding.PEM).decode()


def main() -> None:
    settings = get_settings()
    password = os.getenv("SEED_PASSWORD") or "demo-" + secrets.token_urlsafe(9)
    keystore = KeyStore(settings.kek())
    factory = build_sessionmaker(build_engine(settings))
    with factory() as db:
        keys.ensure_signing_key(db, keystore)
        keys.ensure_dev_pki(db, keystore, settings)
        for email, nombre, role in DEMO_USERS:
            if db.scalar(select(User).where(User.email == email)) is None:
                users.create_user(
                    db, settings, email=email, password=password, nombre=nombre, role=role
                )
                print(f"usuario {role:5s} {email}")
        db.commit()
        if db.scalar(select(Certificate).where(Certificate.subject.like("%evento-demo%"))) is None:
            cert, _ = pki.issue(
                db,
                keystore,
                csr_pem=_csr("m4-tickets-evento-demo"),
                profile="event-signing",
                requested_by="seed",
                valid_days=30,
            )
            print(f"certificado event-signing {cert.serial}")
        if db.scalar(select(Device).where(Device.nombre == "Escaner-Demo-01")) is None:
            device = Device(nombre="Escaner-Demo-01", status="ACTIVE")
            db.add(device)
            db.flush()
            cert, _ = pki.issue(
                db,
                keystore,
                csr_pem=_csr("scanner"),
                profile="device",
                requested_by="seed",
                common_name=f"device-{device.id}",
            )
            device.cert_serial = cert.serial
            print(f"dispositivo Escaner-Demo-01 con certificado {cert.serial}")
        db.commit()
    print(f"\nContraseña de los usuarios demo: {password}")


if __name__ == "__main__":
    main()
