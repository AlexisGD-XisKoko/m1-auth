"""[SOLO DESARROLLO] Emisión de JWT de prueba por rol (BT-02 · hito H1).

Se conserva el endpoint del stub para que M2–M6 sigan probando sin crear usuarios,
pero ahora firma con la llave real activa (la misma del JWKS). Desactivado en
producción y con ENABLE_DEV_STUB=false.
"""

from typing import Any
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.security import DB, KeyStoreDep, SettingsDep
from app.crypto.tokens import compute_idh, sign_access_token
from app.schemas.common import RoleEnum
from app.services.keys import active_signing_key

router = APIRouter(prefix="/dev", tags=["Dev Stub (Hito H1)"])


class DevTokenRequest(BaseModel):
    role: RoleEnum = Field(default=RoleEnum.buyer, description="buyer, admin o staff")
    user_id: str | None = Field(default=None, description="UUID opcional; si se omite se genera")
    ttl_seconds: int = Field(default=900, ge=10, le=86400, description="Vigencia en segundos")


class DevTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105
    alg: str = "ES256"
    kid: str
    claims: dict[str, Any]


@router.post(
    "/token",
    response_model=DevTokenResponse,
    summary="[SOLO DEV] Emite un JWT ES256 válido para buyer, admin o staff (BT-02)",
)
def issue_dev_token(
    payload: DevTokenRequest, db: DB, keystore: KeyStoreDep, settings: SettingsDep
) -> DevTokenResponse:
    kid, key = active_signing_key(db, keystore)
    sub = payload.user_id or str(uuid4())
    issued = sign_access_token(
        private_key=key,
        kid=kid,
        sub=sub,
        role=payload.role.value,
        idh=compute_idh(settings.pepper(), sub),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=payload.ttl_seconds,
    )
    return DevTokenResponse(access_token=issued.token, kid=kid, claims=issued.claims)
