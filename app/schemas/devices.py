from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EnrollmentCodeCreateRequest(BaseModel):
    device_name: str = Field(
        ...,
        min_length=3,
        max_length=128,
        examples=["Escaner-Puerta-Norte-01"],
    )


class EnrollmentCodeResponse(BaseModel):
    id: UUID
    device_name: str
    enrollment_code: str = Field(..., description="Código de un solo uso (se muestra una sola vez)")
    expires_at: datetime


class DeviceEnrollRequest(BaseModel):
    code: str = Field(..., min_length=16, max_length=128, description="Código de un solo uso")
    csr_pem: str = Field(..., max_length=8192, description="CSR PKCS#10 generado por el escáner")


class DeviceEnrollResponse(BaseModel):
    device_id: UUID
    nombre: str
    cert_serial: str
    certificate_pem: str
    ca_chain_pem: str
    enrolled_at: datetime


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    nombre: str
    cert_serial: str | None
    status: str
    enrolled_by: UUID | None
    enrolled_at: datetime
