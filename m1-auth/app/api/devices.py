from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, status

from app.api.pki import STUB_CA_CHAIN_PEM
from app.schemas.common import ProblemDetails
from app.schemas.devices import (
    DeviceEnrollRequest,
    DeviceEnrollResponse,
    EnrollmentCodeCreateRequest,
    EnrollmentCodeResponse,
)

router = APIRouter(prefix="/devices", tags=["Dispositivos"])


@router.post(
    "/enrollment-codes",
    response_model=EnrollmentCodeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Genera código de enrolamiento de un solo uso para escáner (RF-16)",
    responses={403: {"model": ProblemDetails, "description": "Requiere rol admin"}},
)
async def create_enrollment_code(payload: EnrollmentCodeCreateRequest) -> EnrollmentCodeResponse:
    now = datetime.now(UTC)
    return EnrollmentCodeResponse(
        id=uuid4(),
        enrollment_code="STUB-ENROLL-CODE-1234567890",
        expires_at=now + timedelta(minutes=15),
    )


@router.post(
    "/enroll",
    response_model=DeviceEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enrolamiento de escáner enviando CSR y código de un solo uso (RF-16)",
    responses={
        400: {"model": ProblemDetails, "description": "Código inválido, expirado o ya utilizado"},
    },
)
async def enroll_device(payload: DeviceEnrollRequest) -> DeviceEnrollResponse:
    return DeviceEnrollResponse(
        device_id=uuid4(),
        nombre="Escaner-Stub-01",
        cert_serial="0x9988776655",
        certificate_pem=STUB_CA_CHAIN_PEM,
        ca_chain_pem=STUB_CA_CHAIN_PEM,
        enrolled_at=datetime.now(UTC),
    )
