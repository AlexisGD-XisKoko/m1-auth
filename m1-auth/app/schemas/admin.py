from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

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
    id: UUID
    email: EmailStr
    role: RoleEnum
    status: UserStatusEnum
    idh: str
    created_at: datetime


class AdminUserListResponse(BaseModel):
    items: list[AdminUserResponse]
    total: int


class AuditLogEntry(BaseModel):
    id: int
    actor: str
    action: str
    target: str
    ip_address: str
    correlation_id: UUID
    timestamp: datetime
    tsa_token: str | None = None


class AuditLogListResponse(BaseModel):
    items: list[AuditLogEntry]
    total: int
