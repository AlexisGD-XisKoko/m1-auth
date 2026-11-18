"""Modelos SQLAlchemy del esquema `auth` de la BD general (OG-03, OG-07 · sección 2.6).

Ningún otro módulo tiene permisos sobre este esquema (RNF-13). Los demás leen datos de
usuario por API o por la vista `shared.v_usuarios` (id, role, status, idh).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA = "auth"

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA, naming_convention=NAMING)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


TS = DateTime(timezone=True)
# BIGSERIAL en PostgreSQL; INTEGER en SQLite para que el autoincremento funcione en pruebas.
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    nombre: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))  # formato PHC (Argon2id)
    role: Mapped[str] = mapped_column(String(16), default="buyer")
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    idh: Mapped[str] = mapped_column(String(64), unique=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow, server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256, nunca el token
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    expires_at: Mapped[dt.datetime] = mapped_column(TS)
    used_at: Mapped[dt.datetime | None] = mapped_column(TS, nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    nombre: Mapped[str] = mapped_column(String(128))
    cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    enrolled_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    enrolled_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow)


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    device_name: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[dt.datetime] = mapped_column(TS)
    used_at: Mapped[dt.datetime | None] = mapped_column(TS, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow)


class Certificate(Base):
    __tablename__ = "certificates"

    serial: Mapped[str] = mapped_column(String(64), primary_key=True)  # hex
    subject: Mapped[str] = mapped_column(String(255))
    profile: Mapped[str] = mapped_column(String(32), index=True)
    issuer: Mapped[str] = mapped_column(String(32))  # services | devices | events
    requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    not_before: Mapped[dt.datetime] = mapped_column(TS)
    not_after: Mapped[dt.datetime] = mapped_column(TS)
    status: Mapped[str] = mapped_column(String(16), default="VALID")
    revoked_at: Mapped[dt.datetime | None] = mapped_column(TS, nullable=True)
    reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pem: Mapped[str] = mapped_column(Text)


class SigningKey(Base):
    """Llaves de firma JWT; la privada cifrada con la KEK (RNF-07)."""

    __tablename__ = "signing_keys"

    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSON)
    encrypted_private_key: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|retired
    created_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow)
    retired_at: Mapped[dt.datetime | None] = mapped_column(TS, nullable=True)


class CaKey(Base):
    """Certificados de la jerarquía y llaves de las intermedias cifradas con la KEK.

    Ajuste a la planeación v1.1: la tabla 2.6 no indicaba dónde viven las intermedias
    (la 5.5 dice «esquema auth, cifradas con la KEK»). La raíz se guarda SIN llave
    privada (encrypted_private_key = NULL): la custodia la TTP.
    """

    __tablename__ = "ca_keys"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)  # root|services|devices|events
    cert_pem: Mapped[str] = mapped_column(Text)
    encrypted_private_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    crl_number: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(TS, default=utcnow)


class AuditLog(Base):
    """Bitácora de solo inserción: m1_app no tiene UPDATE ni DELETE (RF-18)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[dt.datetime] = mapped_column(TS, default=utcnow, index=True)
    tsa_token: Mapped[str | None] = mapped_column(Text, nullable=True)
