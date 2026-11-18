"""Sesiones: access token ES256 + refresh token rotativo (OG-05 · RF-02, RF-03, RF-04).

- El refresh token es opaco (32 bytes); en BD solo se guarda su SHA-256 y su family_id.
- Al usarlo se marca used_at y se emite otro de la misma familia.
- Si llega un refresh ya usado (o revocado), se revoca TODA la familia (posible robo).
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import as_utc
from app.core.errors import unauthorized
from app.crypto.keystore import KeyStore
from app.crypto.tokens import new_opaque_token, sha256_hex, sign_access_token
from app.models import RefreshToken, User, utcnow
from app.services import audit
from app.services.keys import active_signing_key


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int


def issue_access_token(db: Session, keystore: KeyStore, settings: Settings, user: User) -> str:
    kid, key = active_signing_key(db, keystore)
    return sign_access_token(
        private_key=key,
        kid=kid,
        sub=str(user.id),
        role=user.role,
        idh=user.idh,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=settings.access_token_ttl_seconds,
    ).token


def _new_refresh(db: Session, settings: Settings, user_id: uuid.UUID, family: uuid.UUID) -> str:
    raw = new_opaque_token()
    db.add(
        RefreshToken(
            user_id=user_id,
            token_hash=sha256_hex(raw),
            family_id=family,
            expires_at=utcnow() + dt.timedelta(days=settings.refresh_token_ttl_days),
        )
    )
    return raw


def start_session(db: Session, keystore: KeyStore, settings: Settings, user: User) -> TokenPair:
    access = issue_access_token(db, keystore, settings, user)
    refresh = _new_refresh(db, settings, user.id, uuid.uuid4())
    return TokenPair(access, refresh, settings.access_token_ttl_seconds)


def revoke_family(db: Session, family_id: uuid.UUID) -> None:
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


def rotate(
    db: Session, keystore: KeyStore, settings: Settings, raw_token: str, ip: str | None
) -> TokenPair:
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(raw_token)))
    if row is None:
        raise unauthorized("Refresh token inválido.", "invalid-refresh-token")
    now = utcnow()
    if row.used_at is not None or row.revoked_at is not None:
        # Reúso detectado: revocar toda la familia (sección 5.4).
        revoke_family(db, row.family_id)
        audit.record(
            db,
            actor=str(row.user_id),
            action=audit.Actions.REFRESH_REUSE,
            target=str(row.family_id),
            ip=ip,
        )
        db.commit()
        raise unauthorized(
            "Refresh token reutilizado; la sesión se revocó por seguridad.", "refresh-reuse"
        )
    expires = as_utc(row.expires_at)
    if expires is None or expires <= now:
        raise unauthorized("Refresh token expirado.", "invalid-refresh-token")
    # Marcado condicional: si otra petición lo usó en paralelo, este UPDATE no afecta filas.
    result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == row.id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
    )
    if getattr(result, "rowcount", 0) != 1:
        db.rollback()
        raise unauthorized("Refresh token ya utilizado.", "refresh-reuse")
    user = db.get(User, row.user_id)
    if user is None or user.status != "ACTIVE":
        revoke_family(db, row.family_id)
        db.commit()
        raise unauthorized("Cuenta no disponible.", "invalid-refresh-token")
    access = issue_access_token(db, keystore, settings, user)
    new_raw = _new_refresh(db, settings, user.id, row.family_id)
    db.commit()
    return TokenPair(access, new_raw, settings.access_token_ttl_seconds)


def logout(db: Session, user_id: uuid.UUID, raw_token: str, ip: str | None) -> None:
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(raw_token)))
    if row is not None and row.user_id == user_id:
        revoke_family(db, row.family_id)
    audit.record(db, actor=str(user_id), action=audit.Actions.LOGOUT, target=str(user_id), ip=ip)
    db.commit()
