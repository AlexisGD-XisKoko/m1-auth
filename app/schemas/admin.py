from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.common import RoleEnum, UserStatusEnum


class AdminUserCreateRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    nombre: str = Field(..., min_length=2, max_length=120)
    role: RoleEnum = RoleEnum.staff


class AdminUserUpdateRequest(BaseModel):
    role: RoleEnum | None = None
    status: UserStatusEnum | None = None


class AdminUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    nombre: str
    role: RoleEnum
    status: UserStatusEnum
    idh: str
    failed_attempts: int = 0
    created_at: datetime


class AdminUserListResponse(BaseModel):
    items: list[AdminUserResponse]
    total: int


class AuditLogEntry(BaseModel):
    id: int
    actor: str
    action: str
    target: str | None = None
    ip_address: str | None = None
    correlation_id: str | None = None
    timestamp: datetime
    details: dict[str, Any] | None = None
    tsa_token: str | None = None


class AuditLogListResponse(BaseModel):
    items: list[AuditLogEntry]
    total: int


class KeyRotationResponse(BaseModel):
    new_kid: str
    published_kids: list[str]
