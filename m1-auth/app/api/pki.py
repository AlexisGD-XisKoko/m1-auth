from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Response

from app.schemas.common import ProblemDetails
from app.schemas.pki import CSRRequest, CSRResponse, RevokeRequest, RevokeResponse

router = APIRouter(prefix="/pki", tags=["PKI"])

STUB_CA_CHAIN_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0STUBCACHAINPLACEHOLDER\n"
    "-----END CERTIFICATE-----\n"
)

STUB_CRL_PEM = (
    "-----BEGIN X509 CRL-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0STUBCRLPLACEHOLDER\n"
    "-----END X509 CRL-----\n"
)


@router.get(
    "/ca-chain",
    response_class=Response,
    summary="Cadena de certificados X.509 en PEM para validación offline (RF-15)",
    responses={200: {"content": {"application/x-pem-file": {}}, "description": "Cadena PEM"}},
)
async def get_ca_chain() -> Response:
    return Response(
        content=STUB_CA_CHAIN_PEM,
        media_type="application/x-pem-file",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@router.get(
    "/crl",
    response_class=Response,
    summary="Lista de revocación de certificados (CRL) firmada en PEM (RF-14)",
    responses={200: {"content": {"application/pkix-crl": {}}, "description": "CRL PEM"}},
)
async def get_crl() -> Response:
    return Response(
        content=STUB_CRL_PEM,
        media_type="application/pkix-crl",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.post(
    "/csr",
    response_model=CSRResponse,
    summary="Firma de CSR (PKCS#10) según perfil (RF-12, RF-13)",
    responses={
        400: {"model": ProblemDetails, "description": "CSR inválido"},
        403: {"model": ProblemDetails, "description": "Perfil no autorizado para el solicitante"},
    },
)
async def sign_csr(payload: CSRRequest) -> CSRResponse:
    now = datetime.now(timezone.utc)
    return CSRResponse(
        serial_number="0x1a2b3c4d5e6f",
        subject="CN=stub-subject",
        profile=payload.profile,
        not_before=now,
        not_after=now + timedelta(days=90),
        certificate_pem=STUB_CA_CHAIN_PEM,
        ca_chain_pem=STUB_CA_CHAIN_PEM,
    )


@router.post(
    "/revoke",
    response_model=RevokeResponse,
    summary="Revocación de certificado por número de serie (RF-14)",
    responses={
        403: {"model": ProblemDetails, "description": "Requiere rol admin"},
        404: {"model": ProblemDetails, "description": "Certificado no encontrado"},
    },
)
async def revoke_certificate(payload: RevokeRequest) -> RevokeResponse:
    return RevokeResponse(
        serial_number=payload.serial_number,
        status="REVOKED",
        revoked_at=datetime.now(timezone.utc),
        reason=payload.reason,
        crl_updated=True,
    )
