"""Endpoints de dispositivos (BT-08 · RF-16, RF-17)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.security import DB, IP, AdminUser, KeyStoreDep, PublisherDep, SettingsDep
from app.models import Device
from app.schemas.common import problem
from app.schemas.devices import (
    DeviceEnrollRequest,
    DeviceEnrollResponse,
    DeviceResponse,
    EnrollmentCodeCreateRequest,
    EnrollmentCodeResponse,
)
from app.services import devices

router = APIRouter(prefix="/devices", tags=["Dispositivos"])


@router.post(
    "/enrollment-codes",
    response_model=EnrollmentCodeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Genera un código de enrolamiento de un solo uso, 15 min (RF-16)",
    responses={403: problem("Requiere rol admin")},
)
def create_enrollment_code(
    payload: EnrollmentCodeCreateRequest, admin: AdminUser, db: DB, settings: SettingsDep, ip: IP
) -> EnrollmentCodeResponse:
    row, raw = devices.create_code(
        db, settings, device_name=payload.device_name, admin_id=admin.id, ip=ip
    )
    return EnrollmentCodeResponse(
        id=row.id, device_name=row.device_name, enrollment_code=raw, expires_at=row.expires_at
    )


@router.post(
    "/enroll",
    response_model=DeviceEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    summary="El escáner envía su CSR y el código; recibe su certificado de dispositivo (RF-16)",
    responses={400: problem("Código inválido, expirado o ya utilizado, o CSR inválido")},
)
def enroll_device(
    payload: DeviceEnrollRequest, db: DB, keystore: KeyStoreDep, ip: IP
) -> DeviceEnrollResponse:
    device, cert, chain = devices.enroll(
        db, keystore, code=payload.code, csr_pem=payload.csr_pem, ip=ip
    )
    return DeviceEnrollResponse(
        device_id=device.id,
        nombre=device.nombre,
        cert_serial=cert.serial,
        certificate_pem=cert.pem,
        ca_chain_pem=chain,
        enrolled_at=device.enrolled_at,
    )


@router.get(
    "",
    response_model=list[DeviceResponse],
    summary="Lista de dispositivos enrolados (solo admin)",
    responses={403: problem("Requiere rol admin")},
)
def list_devices(admin: AdminUser, db: DB) -> list[DeviceResponse]:
    rows = db.scalars(select(Device).order_by(Device.enrolled_at.desc()).limit(200)).all()
    return [DeviceResponse.model_validate(r) for r in rows]


@router.post(
    "/{device_id}/revoke",
    response_model=DeviceResponse,
    summary="Desactiva un dispositivo y revoca su certificado (RF-17, deseable)",
    responses={403: problem("Requiere rol admin"), 404: problem("Dispositivo no encontrado")},
)
def revoke_device(
    device_id: UUID,
    admin: AdminUser,
    db: DB,
    keystore: KeyStoreDep,
    settings: SettingsDep,
    publisher: PublisherDep,
    ip: IP,
) -> DeviceResponse:
    device = devices.revoke_device(
        db, keystore, settings, publisher, device_id=device_id, actor=str(admin.id), ip=ip
    )
    return DeviceResponse.model_validate(device)
