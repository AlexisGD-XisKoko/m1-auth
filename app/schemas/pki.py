from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CertProfileEnum(StrEnum):
    service = "service"
    device = "device"
    event_signing = "event-signing"


class RevocationReasonEnum(StrEnum):
    unspecified = "unspecified"
    keyCompromise = "keyCompromise"  # noqa: N815 - nombres de RFC 5280
    affiliationChanged = "affiliationChanged"  # noqa: N815
    superseded = "superseded"
    cessationOfOperation = "cessationOfOperation"  # noqa: N815
    certificateHold = "certificateHold"  # noqa: N815


class JWKItem(BaseModel):
    kty: str = Field(..., examples=["EC"])
    crv: str = Field(..., examples=["P-256"])
    use: str = Field(..., examples=["sig"])
    alg: str = Field(..., examples=["ES256"])
    kid: str = Field(..., examples=["m1-20261118-a1b2c3d4"])
    x: str
    y: str


class JWKSResponse(BaseModel):
    keys: list[JWKItem]


class CSRRequest(BaseModel):
    csr_pem: str = Field(
        ..., max_length=8192, description="PKCS#10 Certificate Signing Request en formato PEM"
    )
    profile: CertProfileEnum = Field(..., description="Perfil solicitado según la CA intermedia")
    valid_days: int | None = Field(
        default=None,
        ge=1,
        le=400,
        description="Vigencia deseada (se recorta al máximo del perfil). Para event-signing: "
        "duración del evento + margen.",
    )


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
    reason: RevocationReasonEnum = Field(..., examples=["keyCompromise"])


class RevokeResponse(BaseModel):
    serial_number: str
    status: str = Field(default="REVOKED")
    revoked_at: datetime
    reason: str
    crl_updated: bool = Field(default=True)


class CertificateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    serial: str
    subject: str
    profile: str
    issuer: str
    requested_by: str | None
    not_before: datetime
    not_after: datetime
    status: str
    revoked_at: datetime | None
    reason: str | None
