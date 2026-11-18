from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import RoleEnum, UserStatusEnum


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["comprador@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["clave-segura-larga-123"])
    nombre: str = Field(..., min_length=2, max_length=120, examples=["Ana López"])


class RegisterResponse(BaseModel):
    id: UUID
    email: EmailStr
    role: RoleEnum
    status: UserStatusEnum
    idh: str = Field(..., description="HMAC-SHA256(pepper, user_id)")
    created_at: datetime


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["comprador@example.com"])
    password: str = Field(..., min_length=1, max_length=128, examples=["clave-segura-larga-123"])


class TokenPairResponse(BaseModel):
    access_token: str = Field(..., description="JWT firmado con ES256 (15 min)")
    refresh_token: str = Field(..., description="Token opaco rotativo (7 días)")
    token_type: str = Field(default="Bearer")
    expires_in: int = Field(default=900, description="Segundos de vigencia del access token")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=16)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=16)


class UserProfileResponse(BaseModel):
    id: UUID
    email: EmailStr
    role: RoleEnum
    status: UserStatusEnum
    idh: str = Field(..., description="Hash de identidad del comprador (RF-09)")
    created_at: datetime
