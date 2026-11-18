from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class EnrollmentCodeCreateRequest(BaseModel):
    device_name: str = Field(..., min_length=3, max_length=128, examples=["Escaner-Puerta-Norte-01"])


class EnrollmentCodeResponse(BaseModel):
    id: UUID
    enrollment_code: str = Field(..., description="Código de un solo uso (se muestra una sola vez)")
    expires_at: datetime


class DeviceEnrollRequest(BaseModel):
    code: str = Field(..., min_length=16, description="Código de enrolamiento de un solo uso")
    csr_pem: str = Field(..., description="CSR PKCS#10 generado por el dispositivo escáner")


class DeviceEnrollResponse(BaseModel):
    device_id: UUID
    nombre: str
    cert_serial: str
    certificate_pem: str
    ca_chain_pem: str
    enrolled_at: datetime
