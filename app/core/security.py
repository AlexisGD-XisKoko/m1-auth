"""Dependencias de FastAPI: contexto del servicio, autenticación JWT y roles.

M1 valida sus propios tokens con las llaves de auth.signing_keys (mismas reglas que el
middleware publicado para los demás equipos: solo ES256, iss, aud, exp, nbf, kid).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import get_db
from app.core.errors import forbidden, unauthorized
from app.core.ratelimit import RateLimiter
from app.crypto.keystore import KeyStore
from app.crypto.tokens import TokenVerificationError, verify_access_token
from app.events.publisher import EventPublisher
from app.models import User
from app.services.keys import verification_keys

_bearer = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_keystore(request: Request) -> KeyStore:
    keystore: KeyStore = request.app.state.keystore
    return keystore


def get_limiter(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.limiter
    return limiter


def get_publisher(request: Request) -> EventPublisher:
    publisher: EventPublisher = request.app.state.publisher
    return publisher


def client_ip(request: Request) -> str:
    # Detrás de Traefik se respeta X-Forwarded-For (Uvicorn --proxy-headers).
    return request.client.host if request.client else "unknown"


DB = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
KeyStoreDep = Annotated[KeyStore, Depends(get_keystore)]
LimiterDep = Annotated[RateLimiter, Depends(get_limiter)]
PublisherDep = Annotated[EventPublisher, Depends(get_publisher)]
IP = Annotated[str, Depends(client_ip)]


@dataclass(frozen=True)
class Principal:
    user: User
    claims: dict[str, Any]

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def role(self) -> str:
        return self.user.role


def get_principal(
    db: DB,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized("Se requiere token Bearer.")
    try:
        claims = verify_access_token(
            credentials.credentials,
            public_keys=verification_keys(db, settings),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
        user_id = uuid.UUID(str(claims["sub"]))
    except (TokenVerificationError, ValueError) as exc:
        raise unauthorized("Token inválido o expirado.", "invalid-token") from exc
    user = db.get(User, user_id)
    if user is None or user.status == "DEACTIVATED":
        raise unauthorized("Cuenta no disponible.", "invalid-token")
    return Principal(user=user, claims=claims)


CurrentUser = Annotated[Principal, Depends(get_principal)]


def require_roles(*roles: str) -> Callable[[Principal], Principal]:
    def _checker(principal: CurrentUser) -> Principal:
        # El rol se toma de la BD (no solo del token) para que un cambio de rol aplique ya.
        if principal.role not in roles:
            raise forbidden("No tienes permisos suficientes para esta operación.")
        return principal

    return _checker


AdminUser = Annotated[Principal, Depends(require_roles("admin"))]
