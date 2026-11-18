"""Endpoints de PKI (BT-07 · RF-12 a RF-15)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.errors import ProblemError, forbidden, unauthorized
from app.core.security import (
    DB,
    IP,
    AdminUser,
    KeyStoreDep,
    PublisherDep,
    SettingsDep,
    get_principal,
)
from app.schemas.common import problem
from app.schemas.pki import (
    CertificateResponse,
    CSRRequest,
    CSRResponse,
    RevokeRequest,
    RevokeResponse,
)
from app.services import pki
from app.services.keys import PKINotReadyError, chain_pem

router = APIRouter(prefix="/pki", tags=["PKI"])

CLIENT_CERT_HEADER = "X-Forwarded-Tls-Client-Cert"  # passTLSClientCert de Traefik
_bearer = HTTPBearer(auto_error=False)


@router.get(
    "/ca-chain",
    response_class=Response,
    summary="Cadena PEM: intermedias de M1 + raíz de la TTP, para validación offline (RF-15)",
    responses={200: {"content": {"application/x-pem-file": {}}, "description": "Cadena PEM"}},
)
def get_ca_chain(db: DB) -> Response:
    try:
        pem = chain_pem(db)
    except PKINotReadyError as exc:
        raise ProblemError(503, "Service Unavailable", str(exc), "pki-not-ready") from exc
    return Response(
        content=pem,
        media_type="application/x-pem-file",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get(
    "/crl",
    response_class=Response,
    summary="CRL v2 firmada por cada intermedia, en PEM (RF-14)",
    responses={200: {"content": {"application/pkix-crl": {}}, "description": "CRL(s) PEM"}},
)
def get_crl(db: DB, keystore: KeyStoreDep, settings: SettingsDep) -> Response:
    pem = pki.build_crls(db, keystore, settings)
    headers = {"Cache-Control": "public, max-age=300"}
    tsa = pki.crl_timestamp(settings, pem)
    if tsa:
        headers["X-TSA-Token"] = tsa  # sello RFC 3161 de la TTP (base64)
    return Response(content=pem, media_type="application/pkix-crl", headers=headers)


def _requester(
    request: Request,
    db: DB,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> pki.Requester:
    """Acceso «mTLS o admin» (contrato 2.5)."""
    header = request.headers.get(CLIENT_CERT_HEADER)
    if header and settings.trust_proxy_client_cert:
        requester = pki.requester_from_client_cert(db, header)
        if requester is None:
            raise unauthorized("Certificado de cliente inválido o revocado.", "invalid-client-cert")
        return requester
    principal = get_principal(db, settings, credentials)
    if principal.role != "admin":
        raise forbidden("Se requiere rol admin o un certificado de servicio (mTLS).")
    return pki.Requester("admin", str(principal.id))


@router.post(
    "/csr",
    response_model=CSRResponse,
    summary="Firma de CSR (PKCS#10) según perfil: service, device o event-signing (RF-12, RF-13)",
    responses={
        400: problem("CSR inválido (firma, curva o CN)"),
        401: problem("No autenticado"),
        403: problem("Perfil no autorizado para el solicitante"),
    },
)
def sign_csr(
    payload: CSRRequest,
    db: DB,
    keystore: KeyStoreDep,
    settings: SettingsDep,
    requester: Annotated[pki.Requester, Depends(_requester)],
    ip: IP,
) -> CSRResponse:
    pki.authorize_profile(settings, requester, payload.profile.value)
    cert, chain = pki.issue(
        db,
        keystore,
        csr_pem=payload.csr_pem,
        profile=payload.profile.value,
        requested_by=f"{requester.kind}:{requester.name}",
        valid_days=payload.valid_days,
        ip=ip,
    )
    db.commit()
    return CSRResponse(
        serial_number=cert.serial,
        subject=cert.subject,
        profile=payload.profile,
        not_before=cert.not_before,
        not_after=cert.not_after,
        certificate_pem=cert.pem,
        ca_chain_pem=chain,
    )


@router.post(
    "/revoke",
    response_model=RevokeResponse,
    summary="Revocación por número de serie; regenera la CRL y publica certificate.revoked (RF-14)",
    responses={
        403: problem("Requiere rol admin"),
        404: problem("Certificado no encontrado"),
        409: problem("Ya estaba revocado"),
    },
)
def revoke_certificate(
    payload: RevokeRequest,
    admin: AdminUser,
    db: DB,
    keystore: KeyStoreDep,
    settings: SettingsDep,
    publisher: PublisherDep,
    ip: IP,
) -> RevokeResponse:
    cert = pki.revoke(
        db,
        keystore,
        settings,
        publisher,
        serial=payload.serial_number,
        reason=payload.reason.value,
        actor=str(admin.id),
        ip=ip,
    )
    return RevokeResponse(
        serial_number=cert.serial,
        revoked_at=cert.revoked_at or datetime.now(UTC),
        reason=cert.reason or "",
    )


@router.get(
    "/certificates",
    response_model=list[CertificateResponse],
    summary="Inventario de certificados emitidos (solo admin; panel de administración)",
    responses={403: problem("Requiere rol admin")},
)
def list_certificates(
    admin: AdminUser,
    db: DB,
    profile: str | None = None,
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[CertificateResponse]:
    rows = pki.list_certificates(db, profile=profile, status=status, limit=limit, offset=offset)
    return [CertificateResponse.model_validate(r) for r in rows]
