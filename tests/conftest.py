"""Fixtures comunes.

Por defecto las pruebas usan SQLite en un archivo temporal (no requieren Docker).
Para correrlas contra PostgreSQL con los esquemas y roles reales:
    TEST_DATABASE_URL=postgresql+psycopg://m1_app:...@localhost:5432/boletera pytest
(en ese caso las tablas deben existir: `alembic upgrade head` con m1_owner).
"""

from __future__ import annotations

import base64
import os
import secrets
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.core.config import Settings
from app.core.database import build_engine
from app.main import create_app
from app.models import Base

ADMIN_EMAIL = "admin.pruebas@example.com"
ADMIN_PASSWORD = "admin-pruebas-" + secrets.token_hex(6)


def _b64() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture(scope="session")
def settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    db_url = os.getenv("TEST_DATABASE_URL") or (
        f"sqlite:///{Path(tmp_path_factory.mktemp('db')) / 'm1_test.db'}"
    )
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        env="test",
        database_url=db_url,
        rate_limit_backend="memory",
        kek_base64=os.getenv("TEST_KEK_BASE64") or _b64(),
        pepper_base64=os.getenv("TEST_PEPPER_BASE64") or _b64(),
        bootstrap_admin_email=ADMIN_EMAIL,
        bootstrap_admin_password=ADMIN_PASSWORD,
        rate_limit_login_per_ip=100_000,
        rate_limit_login_per_account=100_000,
        rate_limit_register_per_ip=100_000,
        enable_dev_stub=True,
        tsa_url="",
    )


@pytest.fixture(scope="session")
def app(settings: Settings) -> Iterator[Any]:
    engine = build_engine(settings)
    if settings.database_url.startswith("sqlite") or not inspect(engine).has_table(
        "users", schema="auth"
    ):
        Base.metadata.create_all(engine)
    engine.dispose()
    application = create_app(settings)
    with TestClient(application):  # ejecuta el lifespan una vez (llaves, PKI, admin)
        _ensure_test_admin(application, settings)
        yield application


def _ensure_test_admin(application: Any, settings: Settings) -> None:
    """En PostgreSQL compartido puede existir otro admin: se garantiza el de pruebas."""
    from sqlalchemy import select

    from app.crypto.passwords import hash_password
    from app.models import User
    from app.services.users import create_user

    with application.state.sessionmaker() as session:
        user = session.scalar(select(User).where(User.email == ADMIN_EMAIL))
        if user is None:
            create_user(
                session,
                settings,
                email=ADMIN_EMAIL,
                password=ADMIN_PASSWORD,
                nombre="Admin pruebas",
                role="admin",
            )
        else:
            user.password_hash = hash_password(ADMIN_PASSWORD)
            user.role, user.status, user.failed_attempts, user.locked_until = (
                "admin",
                "ACTIVE",
                0,
                None,
            )
        session.commit()


@pytest.fixture()
def client(app: Any) -> TestClient:
    return TestClient(app, client=("10.0.0.1", 50000))


@pytest.fixture()
def db(app: Any) -> Iterator[Any]:
    with app.state.sessionmaker() as session:
        yield session


# --- Utilidades -------------------------------------------------------------------------


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}.{uuid.uuid4().hex[:10]}@example.com"


STRONG_PASSWORD = "boletos-seguros-2026!"


def register_and_login(client: TestClient, role_email: str | None = None) -> dict[str, str]:
    email = role_email or unique_email()
    r = client.post(
        "/auth/register", json={"email": email, "password": STRONG_PASSWORD, "nombre": "Prueba"}
    )
    assert r.status_code == 201, r.text
    r = client.post("/auth/login", json={"email": email, "password": STRONG_PASSWORD})
    assert r.status_code == 200, r.text
    return {"email": email, **r.json()}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_headers(client: TestClient) -> dict[str, str]:
    r = client.post("/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return bearer(r.json()["access_token"])


def make_csr(cn: str = "m4-tickets", key: ec.EllipticCurvePrivateKey | None = None) -> str:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def split_pem(pem: str, marker: str = "CERTIFICATE") -> list[str]:
    end = f"-----END {marker}-----"
    return [p.strip() + "\n" + end + "\n" for p in pem.split(end) if f"BEGIN {marker}" in p]
