"""Administración de usuarios, bitácora y llaves (OG-06, BT-04 · RF-06, RF-18 · RNF-04)."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from app.core.security import DB, IP, AdminUser, KeyStoreDep, SettingsDep
from app.models import AuditLog
from app.schemas.admin import (
    AdminUserCreateRequest,
    AdminUserListResponse,
    AdminUserResponse,
    AdminUserUpdateRequest,
    AuditLogEntry,
    AuditLogListResponse,
    KeyRotationResponse,
)
from app.schemas.common import RoleEnum, problem
from app.services import audit, keys, users

router = APIRouter(prefix="/admin", tags=["Administración"])

ADMIN_ONLY: dict[int | str, dict[str, Any]] = {403: problem("Requiere rol admin")}


@router.get(
    "/users",
    response_model=AdminUserListResponse,
    summary="Consulta de usuarios con búsqueda (solo admin, RF-06)",
    responses=ADMIN_ONLY,
)
def list_users(
    admin: AdminUser,
    db: DB,
    q: str | None = None,
    role: RoleEnum | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AdminUserListResponse:
    rows, total = users.list_users(
        db, q=q, role=role.value if role else None, limit=limit, offset=offset
    )
    return AdminUserListResponse(
        items=[AdminUserResponse.model_validate(u) for u in rows], total=total
    )


@router.post(
    "/users",
    response_model=AdminUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Alta de usuario con rol asignado (solo admin, RF-06)",
    responses={**ADMIN_ONLY, 409: problem("Correo ya registrado")},
)
def create_user(
    payload: AdminUserCreateRequest, admin: AdminUser, db: DB, settings: SettingsDep, ip: IP
) -> AdminUserResponse:
    user = users.create_user(
        db,
        settings,
        email=payload.email,
        password=payload.password,
        nombre=payload.nombre,
        role=payload.role.value,
    )
    audit.record(
        db,
        actor=str(admin.id),
        action=audit.Actions.USER_CREATED,
        target=user.email,
        ip=ip,
        details={"role": user.role},
        tsa_url=settings.tsa_url,
    )
    db.commit()
    return AdminUserResponse.model_validate(user)


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserResponse,
    summary="Cambio de rol, desbloqueo o desactivación de usuario (solo admin, RF-06)",
    responses={**ADMIN_ONLY, 404: problem("Usuario no encontrado")},
)
def update_user(
    user_id: UUID,
    payload: AdminUserUpdateRequest,
    admin: AdminUser,
    db: DB,
    settings: SettingsDep,
    ip: IP,
) -> AdminUserResponse:
    user = users.update_user(
        db,
        settings,
        actor=admin.user,
        user_id=user_id,
        role=payload.role.value if payload.role else None,
        status=payload.status.value if payload.status else None,
        ip=ip,
    )
    db.commit()
    return AdminUserResponse.model_validate(user)


@router.get(
    "/audit",
    response_model=AuditLogListResponse,
    summary="Consulta de la bitácora de seguridad (solo admin, RF-18)",
    responses=ADMIN_ONLY,
)
def get_audit_log(
    admin: AdminUser,
    db: DB,
    action: str | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditLogListResponse:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)).all()
    return AuditLogListResponse(
        items=[
            AuditLogEntry(
                id=r.id,
                actor=r.actor,
                action=r.action,
                target=r.target,
                ip_address=r.ip,
                correlation_id=r.correlation_id,
                timestamp=r.timestamp,
                details=r.details,
                tsa_token=r.tsa_token,
            )
            for r in rows
        ],
        total=int(total),
    )


@router.post(
    "/signing-keys/rotate",
    response_model=KeyRotationResponse,
    summary="Rota la llave de firma JWT; la anterior sigue publicada en el JWKS (RNF-04)",
    responses=ADMIN_ONLY,
)
def rotate_signing_key(
    admin: AdminUser, db: DB, keystore: KeyStoreDep, settings: SettingsDep, ip: IP
) -> KeyRotationResponse:
    new_kid = keys.rotate_signing_key(db, keystore, str(admin.id), ip)
    return KeyRotationResponse(
        new_kid=new_kid, published_kids=[k.kid for k in keys.published_keys(db, settings)]
    )
