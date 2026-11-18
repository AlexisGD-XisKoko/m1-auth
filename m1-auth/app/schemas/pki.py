from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class CertProfileEnum(StrEnum):
    service = "service"
    device = "device"
    event_signing = "event-signing"


class JWKItem(BaseModel):
    kty: str = Field(..., examples=["EC"])
    crv: str = Field(..., examples=["P-256"])
    use: str = Field(..., examples=["sig"])
    alg: str = Field(..., examples=["ES256"])
    kid: str = Field(..., examples=["m1-stub-key-2026-11"])
    x: str
    y: str


class JWKSResponse(BaseModel):
    keys: list[JWKItem]


class CSRRequest(BaseModel):
    csr_pem: str = Field(..., description="PKCS#10 Certificate Signing Request en formato PEM")
    profile: CertProfileEnum = Field(..., description="Perfil solicitado según la CA intermedia")


class CSRResponse(BaseModel):
    serial_number: str = Field(..., examples=["4a8f12c90e1b"])
    subject: str = Field(..., examples=["CN=m4-tickets-event-01"])
    profile: CertProfileEnum
    not_before: datetime
    not_after: datetime
    certificate_pem: str
    ca_chain_pem: str


class RevokeRequest(BaseModel):
    serial_number: str = Field(..., min_length=4, max_length=64)
    reason: str = Field(..., examples=["keyCompromise", "cessationOfOperation", "superseded"])


class RevokeResponse(BaseModel):
    serial_number: str
    status: str = Field(default="REVOKED")
    revoked_at: datetime
    reason: str
    crl_updated: bool = Field(default=True)
