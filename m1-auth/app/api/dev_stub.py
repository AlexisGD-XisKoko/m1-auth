from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.stub_keys import STUB_KID, sign_stub_jwt
from app.schemas.common import RoleEnum

router = APIRouter(prefix="/dev", tags=["Dev Stub (Hito H1)"])


class DevTokenRequest(BaseModel):
    role: RoleEnum = Field(default=RoleEnum.buyer, description="Rol del token: buyer, admin o staff")
    user_id: str | None = Field(default=None, description="UUID opcional; si se omite se genera uno nuevo")
    ttl_seconds: int = Field(default=900, ge=10, le=86400, description="Vigencia en segundos (default 900s = 15m)")


class DevTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    alg: str = "ES256"
    kid: str = STUB_KID
    claims: dict[str, Any]


@router.post(
    "/token",
    response_model=DevTokenResponse,
    summary="[SOLO STUB H1] Emite un JWT ES256 de prueba para buyer, admin o staff (BT-02)",
)
async def issue_dev_token(payload: DevTokenRequest) -> DevTokenResponse:
    token, claims = sign_stub_jwt(
        role=payload.role.value,
        user_id=payload.user_id,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=payload.ttl_seconds,
    )
    return DevTokenResponse(access_token=token, claims=claims)
