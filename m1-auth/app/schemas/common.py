from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class RoleEnum(StrEnum):
    buyer = "buyer"
    admin = "admin"
    staff = "staff"


class UserStatusEnum(StrEnum):
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    DEACTIVATED = "DEACTIVATED"


class ProblemDetails(BaseModel):
    """Formato estándar de errores HTTP según RFC 7807 (ADR-0004)."""

    type: str = Field(
        default="about:blank", examples=["https://auth.boletera.local/errors/invalid-credentials"]
    )
    title: str = Field(..., examples=["Unauthorized"])
    status: int = Field(..., examples=[401])
    detail: str = Field(..., examples=["Credenciales inválidas."])
    instance: str | None = Field(default=None, examples=["/auth/login"])
    correlation_id: UUID | None = Field(default=None)


class HealthResponse(BaseModel):
    status: str = Field(..., examples=["ok"])
    service: str = Field(..., examples=["m1-auth"])
    version: str = Field(..., examples=["0.1.0-stub"])
    timestamp: datetime
