from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, status

from app.core.stub_keys import compute_stub_idh
from app.schemas.admin import (
    AdminUserCreateRequest,
    AdminUserListResponse,
    AdminUserResponse,
    AdminUserUpdateRequest,
    AuditLogEntry,
    AuditLogListResponse,
)
from app.schemas.common import ProblemDetails, RoleEnum, UserStatusEnum

router = APIRouter(prefix="/admin", tags=["Administración"])


@router.get(
    "/users",
    response_model=AdminUserListResponse,
    summary="Consulta de usuarios (solo admin, RF-06)",
    responses={403: {"model": ProblemDetails, "description": "Requiere rol admin"}},
)
async def list_users() -> AdminUserListResponse:
    uid = uuid4()
    return AdminUserListResponse(
        items=[
            AdminUserResponse(
                id=uid,
                email="admin@boletera.local",
                role=RoleEnum.admin,
                status=UserStatusEnum.ACTIVE,
                idh=compute_stub_idh(str(uid)),
                created_at=datetime.now(UTC),
            )
        ],
        total=1,
    )


@router.post(
    "/users",
    response_model=AdminUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Alta de usuario con rol asignado (solo admin, RF-06)",
    responses={403: {"model": ProblemDetails, "description": "Requiere rol admin"}},
)
async def create_user(payload: AdminUserCreateRequest) -> AdminUserResponse:
    uid = uuid4()
    return AdminUserResponse(
        id=uid,
        email=payload.email,
        role=payload.role,
        status=UserStatusEnum.ACTIVE,
        idh=compute_stub_idh(str(uid)),
        created_at=datetime.now(UTC),
    )


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserResponse,
    summary="Modificación de rol o desactivación de usuario (solo admin, RF-06)",
    responses={
        403: {"model": ProblemDetails, "description": "Requiere rol admin"},
        404: {"model": ProblemDetails, "description": "Usuario no encontrado"},
    },
)
async def update_user(user_id: UUID, payload: AdminUserUpdateRequest) -> AdminUserResponse:
    return AdminUserResponse(
        id=user_id,
        email="updated@boletera.local",
        role=payload.role or RoleEnum.staff,
        status=payload.status or UserStatusEnum.ACTIVE,
        idh=compute_stub_idh(str(user_id)),
        created_at=datetime.now(UTC),
    )


@router.get(
    "/audit",
    response_model=AuditLogListResponse,
    summary="Consulta de bitácora de seguridad (solo admin, RF-18)",
    responses={403: {"model": ProblemDetails, "description": "Requiere rol admin"}},
)
async def get_audit_log() -> AuditLogListResponse:
    return AuditLogListResponse(
        items=[
            AuditLogEntry(
                id=1,
                actor="system-stub",
                action="STUB_STARTED",
                target="m1-auth",
                ip_address="127.0.0.1",
                correlation_id=uuid4(),
                timestamp=datetime.now(UTC),
                tsa_token=None,
            )
        ],
        total=1,
    )
