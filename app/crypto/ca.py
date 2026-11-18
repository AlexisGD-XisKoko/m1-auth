"""Autoridad Certificadora (JO-02, JO-06, JO-07 · RF-10 a RF-15).

Jerarquía (sección 5.3 de la planeación):

    Raíz (TTP, offline) ──┬── Intermedia de Servicios    → perfil service (mTLS)
                          ├── Intermedia de Dispositivos → perfil device (escáneres M6)
                          └── Intermedia de Eventos      → perfil event-signing (M4)

Todo con ECDSA P-256 y SHA-256. M1 opera solo las intermedias; la raíz la custodia
la TTP. Para desarrollo local, `build_dev_hierarchy` simula la ceremonia.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

# OID interno del proyecto para firma de boletos/eventos (arco privado de ejemplo).
EVENT_SIGNING_EKU = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")

CN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")


class CSRValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Profile:
    name: str
    issuer: str  # nombre de la intermedia que firma
    key_usage: dict[str, bool]
    eku: tuple[ObjectIdentifier, ...]
    default_days: int
    max_days: int
    san_dns: bool


_KU_SIGN = {"digital_signature": True}

PROFILES: dict[str, Profile] = {
    "service": Profile(
        "service",
        "services",
        _KU_SIGN,
        (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
        90,
        90,
        True,
    ),
    "device": Profile(
        "device", "devices", _KU_SIGN, (ExtendedKeyUsageOID.CLIENT_AUTH,), 365, 365, False
    ),
    "event-signing": Profile(
        "event-signing", "events", _KU_SIGN, (EVENT_SIGNING_EKU,), 120, 400, False
    ),
}

INTERMEDIATES = {
    "services": "Boletera M1 Intermedia de Servicios",
    "devices": "Boletera M1 Intermedia de Dispositivos",
    "events": "Boletera M1 Intermedia de Eventos",
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _key_usage(
    *,
    digital_signature: bool = False,
    key_cert_sign: bool = False,
    crl_sign: bool = False,
) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=crl_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _name(cn: str, ou: str = "Modulo 1") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Boletera Auditorio"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


# --- Raíz e intermedias ---------------------------------------------------------------


def build_root(key: ec.EllipticCurvePrivateKey, years: int = 10) -> x509.Certificate:
    """Certificado raíz autofirmado (lo emite la TTP en la ceremonia)."""
    name = _name("Boletera TTP Root CA", "Tercera Entidad de Confianza")
    now = _now()
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )


def build_intermediate_csr(
    key: ec.EllipticCurvePrivateKey, common_name: str
) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_name(common_name))
        .sign(key, hashes.SHA256())
    )


def sign_intermediate(
    csr: x509.CertificateSigningRequest,
    root_cert: x509.Certificate,
    root_key: ec.EllipticCurvePrivateKey,
    years: int = 3,
) -> x509.Certificate:
    """Firma de una intermedia por la raíz (lado TTP de la ceremonia, sección 4.4)."""
    if not csr.is_signature_valid:
        raise CSRValidationError("Firma del CSR inválida.")
    now = _now()
    pub = csr.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise CSRValidationError("Solo se aceptan llaves ECDSA P-256.")
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_ec_pub(root_cert)),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )


@dataclass
class DevHierarchy:
    root_cert: x509.Certificate
    root_key: ec.EllipticCurvePrivateKey
    intermediates: dict[str, tuple[x509.Certificate, ec.EllipticCurvePrivateKey]]


def build_dev_hierarchy() -> DevHierarchy:
    """Simula la ceremonia completa (raíz + 3 intermedias). SOLO desarrollo/pruebas."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_cert = build_root(root_key)
    inter: dict[str, tuple[x509.Certificate, ec.EllipticCurvePrivateKey]] = {}
    for name, cn in INTERMEDIATES.items():
        key = ec.generate_private_key(ec.SECP256R1())
        cert = sign_intermediate(build_intermediate_csr(key, cn), root_cert, root_key)
        inter[name] = (cert, key)
    return DevHierarchy(root_cert, root_key, inter)


# --- Firma de CSR por perfil (RF-12, RF-13) ---------------------------------------------


def load_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except ValueError as exc:
        raise CSRValidationError("El CSR no es un PKCS#10 PEM válido.") from exc
    if not csr.is_signature_valid:
        raise CSRValidationError("Firma del CSR inválida.")
    pub = csr.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise CSRValidationError("Solo se aceptan llaves ECDSA P-256 (secp256r1).")
    return csr


def csr_common_name(csr: x509.CertificateSigningRequest) -> str:
    attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise CSRValidationError("El CSR debe incluir un Common Name (CN).")
    cn = str(attrs[0].value)
    if not CN_PATTERN.match(cn):
        raise CSRValidationError("CN inválido: usa letras, números, punto, guion o guion bajo.")
    return cn


def _ec_pub(cert: x509.Certificate) -> ec.EllipticCurvePublicKey:
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("El certificado emisor no tiene llave EC.")
    return pub


def issue_certificate(
    csr: x509.CertificateSigningRequest,
    profile_name: str,
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    common_name: str | None = None,
    valid_days: int | None = None,
) -> x509.Certificate:
    """Firma un CSR aplicando las extensiones exactas del perfil.

    El sujeto se reconstruye (no se copia el del CSR) y la llave pública se toma del
    CSR: la llave privada del solicitante nunca sale de él (RF-12).
    """
    profile = PROFILES[profile_name]
    cn = common_name or csr_common_name(csr)
    days = min(valid_days or profile.default_days, profile.max_days)
    pub = csr.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise CSRValidationError("Solo se aceptan llaves ECDSA P-256.")
    now = _now()
    not_after = min(now + dt.timedelta(days=days), issuer_cert.not_valid_after_utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn, f"Perfil {profile.name}"))
        .issuer_name(issuer_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(**profile.key_usage), critical=True)
        .add_extension(x509.ExtendedKeyUsage(list(profile.eku)), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_ec_pub(issuer_cert)),
            critical=False,
        )
    )
    san: list[x509.GeneralName] = (
        [x509.DNSName(cn)]
        if profile.san_dns
        else [x509.UniformResourceIdentifier(f"urn:boletera:{profile.name}:{cn}")]
    )
    builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


# --- CRL v2 (RF-14) ------------------------------------------------------------------

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
}


def build_crl(
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    revoked: Iterable[tuple[int, dt.datetime, str]],
    *,
    crl_number: int,
    next_update_hours: int = 24,
) -> x509.CertificateRevocationList:
    now = _now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(hours=next_update_hours))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_ec_pub(issuer_cert)),
            critical=False,
        )
    )
    for serial, when, reason in revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(when)
            .add_extension(
                x509.CRLReason(REASONS.get(reason, x509.ReasonFlags.unspecified)), critical=False
            )
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(issuer_key, hashes.SHA256())


# --- Utilidades ----------------------------------------------------------------------


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def pem_to_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def serial_hex(serial: int) -> str:
    return format(serial, "x")


def fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def verify_issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verifica firma, nombre del emisor y vigencia de un eslabón de la cadena."""
    try:
        child.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, Exception):  # noqa: BLE001 - cualquier fallo = inválido
        return False
    now = _now()
    return child.not_valid_before_utc <= now <= child.not_valid_after_utc
