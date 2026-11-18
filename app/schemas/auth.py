from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.common import RoleEnum, UserStatusEnum


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["comprador@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["clave-segura-larga-123"])
    nombre: str = Field(..., min_length=2, max_length=120, examples=["Ana López"])


class UserProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    nombre: str
    role: RoleEnum
    status: UserStatusEnum
    idh: str = Field(..., description="Hash de identidad: HMAC-SHA256(pepper, user_id) (RF-09)")
    created_at: datetime


class RegisterResponse(UserProfileResponse):
    pass


class LoginRequest(BaseModel):
    # Sin validar formato: el login responde igual (401) para cualquier correo inexistente.
    email: str = Field(..., min_length=3, max_length=254, examples=["comprador@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["clave-segura-larga-123"])


class TokenPairResponse(BaseModel):
    access_token: str = Field(..., description="JWT firmado con ES256 (15 min)")
    refresh_token: str = Field(..., description="Token opaco rotativo (7 días)")
    token_type: str = Field(default="Bearer")
    expires_in: int = Field(default=900, description="Segundos de vigencia del access token")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=16, max_length=256)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=16, max_length=256)
