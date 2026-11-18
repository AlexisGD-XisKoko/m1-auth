"""Lógica de identidades (OG-04, OG-06 · RF-01, RF-05, RF-06 · RNF-05, RNF-06, RNF-08)."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import as_utc
from app.core.errors import ProblemError, bad_request, conflict, forbidden, not_found
from app.crypto import passwords
from app.crypto.tokens import compute_idh
from app.models import RefreshToken, User, utcnow
from app.services import audit

ROLES = {"buyer", "admin", "staff"}
STATUSES = {"ACTIVE", "LOCKED", "DEACTIVATED"}


@lru_cache
def _common_passwords() -> frozenset[str]:
    text = resources.files("app.data").joinpath("common_passwords.txt").read_text("utf-8")
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


def validate_password(password: str, email: str, settings: Settings) -> None:
    """Política NIST SP 800-63B: longitud mínima, sin reglas de composición y
    verificación contra una lista de contraseñas comunes (RNF-08)."""
    if len(password) < settings.password_min_length:
        raise bad_request(
            f"La contraseña debe tener al menos {settings.password_min_length} caracteres.",
            "weak-password",
        )
    lowered = password.lower()
    local = email.split("@", 1)[0].lower()
    if lowered in _common_passwords() or (len(local) >= 4 and local in lowered):
        raise bad_request(
            "La contraseña es demasiado común o contiene tu correo; elige otra.",
            "weak-password",
        )


def normalize_email(email: str) -> str:
    return email.strip().lower()


def create_user(
    db: Session,
    settings: Settings,
    *,
    email: str,
    password: str,
    nombre: str,
    role: str = "buyer",
) -> User:
    email = normalize_email(email)
    if role not in ROLES:
        raise bad_request("Rol inválido.")
    validate_password(password, email, settings)
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise conflict("El correo ya está registrado.", "email-taken")
    uid = uuid.uuid4()
    user = User(
        id=uid,
        email=email,
        nombre=nombre.strip(),
        password_hash=passwords.hash_password(password),
        role=role,
        status="ACTIVE",
        idh=compute_idh(settings.pepper(), str(uid)),
    )
    db.add(user)
    return user


@dataclass
class LoginResult:
    user: User | None
    locked_for: int = 0  # segundos


def authenticate(db: Session, settings: Settings, email: str, password: str) -> LoginResult:
    """Verifica credenciales con tiempo uniforme y bloqueo progresivo."""
    user = db.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None:
        passwords.verify_dummy(password)  # mismo costo que un usuario real (RNF-06)
        return LoginResult(None)
    now = utcnow()
    locked_until = as_utc(user.locked_until)
    if locked_until and locked_until > now:
        passwords.verify_dummy(password)
        return LoginResult(None, int((locked_until - now).total_seconds()) + 1)
    if user.status != "ACTIVE" and user.status != "LOCKED":
        passwords.verify_dummy(password)
        return LoginResult(None)
    if not passwords.verify_password(user.password_hash, password):
        user.failed_attempts += 1
        over = user.failed_attempts - settings.lockout_threshold
        if over >= 0:
            wait = min(settings.lockout_base_seconds * (2**over), settings.lockout_max_seconds)
            user.locked_until = now + dt.timedelta(seconds=wait)
            user.status = "LOCKED"
            return LoginResult(None, wait)
        return LoginResult(None)
    # Éxito: limpiar contador y rehash si cambiaron los parámetros de Argon2id.
    user.failed_attempts = 0
    user.locked_until = None
    user.status = "ACTIVE"
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
    return LoginResult(user)


def list_users(
    db: Session, *, q: str | None, role: str | None, limit: int, offset: int
) -> tuple[list[User], int]:
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(func.lower(User.email).like(like), func.lower(User.nombre).like(like))
        )
    if role:
        stmt = stmt.where(User.role == role)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(User.created_at.desc()).limit(limit).offset(offset)).all()
    return list(rows), int(total)


def update_user(
    db: Session,
    settings: Settings,
    *,
    actor: User,
    user_id: uuid.UUID,
    role: str | None,
    status: str | None,
    ip: str | None,
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("Usuario no encontrado.")
    if user.id == actor.id and (role not in (None, "admin") or status == "DEACTIVATED"):
        raise forbidden("Un administrador no puede quitarse el rol ni desactivarse a sí mismo.")
    if role is not None and role != user.role:
        if role not in ROLES:
            raise bad_request("Rol inválido.")
        audit.record(
            db,
            actor=str(actor.id),
            action=audit.Actions.ROLE_CHANGED,
            target=str(user.id),
            ip=ip,
            details={"from": user.role, "to": role},
            tsa_url=settings.tsa_url,
        )
        user.role = role
    if status is not None and status != user.status:
        if status not in STATUSES:
            raise bad_request("Estado inválido.")
        audit.record(
            db,
            actor=str(actor.id),
            action=audit.Actions.STATUS_CHANGED,
            target=str(user.id),
            ip=ip,
            details={"from": user.status, "to": status},
        )
        user.status = status
        if status == "ACTIVE":
            user.failed_attempts = 0
            user.locked_until = None
        if status == "DEACTIVATED":
            revoke_all_sessions(db, user.id)
    return user


def revoke_all_sessions(db: Session, user_id: uuid.UUID) -> None:
    now = utcnow()
    for rt in db.scalars(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
    ):
        rt.revoked_at = now


def ensure_bootstrap_admin(db: Session, settings: Settings) -> None:
    """Crea el primer admin desde variables de entorno si no existe ninguno."""
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        return
    if db.scalar(select(User.id).where(User.role == "admin")) is not None:
        return
    try:
        create_user(
            db,
            settings,
            email=settings.bootstrap_admin_email,
            password=settings.bootstrap_admin_password,
            nombre="Administrador inicial",
            role="admin",
        )
        audit.record(
            db,
            actor="system",
            action=audit.Actions.USER_CREATED,
            target=settings.bootstrap_admin_email,
            details={"role": "admin", "bootstrap": True},
        )
        db.commit()
    except ProblemError:
        db.rollback()
        raise
