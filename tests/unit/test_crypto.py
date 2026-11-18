"""Pruebas unitarias del código criptográfico (JO-03, JO-04, JO-05, JO-07, JO-08)."""

from __future__ import annotations

import base64
import os

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto import ca, passwords, tokens
from app.crypto.keystore import KeyStore
from app.crypto.tsa_client import build_timestamp_request
from tests.conftest import make_csr


# --- Argon2id -----------------------------------------------------------------------------
def test_argon2id_hash_formato_phc_y_verificacion() -> None:
    h = passwords.hash_password("una-clave-larga")
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert passwords.verify_password(h, "una-clave-larga")
    assert not passwords.verify_password(h, "otra-clave")
    assert not passwords.verify_password("no-es-un-hash", "x")
    assert not passwords.needs_rehash(h)
    assert passwords.needs_rehash("$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaA")


def test_mismo_password_produce_hashes_distintos_por_salt() -> None:
    assert passwords.hash_password("x" * 12) != passwords.hash_password("x" * 12)


# --- KEK / AES-256-GCM ----------------------------------------------------------------------
def test_keystore_cifra_y_descifra_con_aad() -> None:
    ks = KeyStore(os.urandom(32))
    blob = ks.encrypt(b"secreto", "kid-1")
    assert ks.decrypt(blob, "kid-1") == b"secreto"
    with pytest.raises(InvalidTag):
        ks.decrypt(blob, "kid-2")  # el blob no puede moverse a otra fila
    with pytest.raises(InvalidTag):
        KeyStore(os.urandom(32)).decrypt(blob, "kid-1")  # otra KEK


def test_keystore_nonce_distinto_por_operacion() -> None:
    ks = KeyStore(os.urandom(32))
    assert ks.encrypt(b"a", "k") != ks.encrypt(b"a", "k")


def test_keystore_envuelve_llaves_ec() -> None:
    ks = KeyStore(os.urandom(32))
    key = ec.generate_private_key(ec.SECP256R1())
    restored = ks.unwrap_private_key(ks.wrap_private_key(key, "k"), "k")
    assert restored.public_key().public_numbers() == key.public_key().public_numbers()


def test_keystore_rechaza_kek_de_tamano_incorrecto() -> None:
    with pytest.raises(ValueError):
        KeyStore(b"corta")


# --- JWT ES256 ---------------------------------------------------------------------------
def _issue(**kw: object) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    args = dict(
        private_key=key,
        kid="k1",
        sub="u1",
        role="buyer",
        idh="ab" * 32,
        issuer="iss",
        audience="aud",
        ttl_seconds=60,
    )
    args.update(kw)
    return tokens.sign_access_token(**args).token, key  # type: ignore[arg-type]


def test_jwt_es256_claims_y_header() -> None:
    token, key = _issue()
    claims = tokens.verify_access_token(
        token, public_keys={"k1": key.public_key()}, issuer="iss", audience="aud"
    )
    assert set(tokens.REQUIRED_CLAIMS) <= set(claims)
    import jwt

    assert jwt.get_unverified_header(token) == {"alg": "ES256", "kid": "k1", "typ": "JWT"}


def test_jwk_publico_tiene_coordenadas_de_32_bytes() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = tokens.public_jwk(key.public_key(), "k")
    for coord in ("x", "y"):
        assert len(base64.urlsafe_b64decode(jwk[coord] + "==")) == 32


def test_idh_es_hmac_sha256_hex() -> None:
    import hashlib
    import hmac

    pepper = os.urandom(32)
    assert tokens.compute_idh(pepper, "u") == hmac.new(pepper, b"u", hashlib.sha256).hexdigest()


def test_opaque_token_entropia_y_hash() -> None:
    t = tokens.new_opaque_token()
    assert len(base64.urlsafe_b64decode(t + "=")) == 32
    assert len(tokens.sha256_hex(t)) == 64
    assert tokens.constant_time_equals("a", "a") and not tokens.constant_time_equals("a", "b")


# --- CA ------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def hierarchy() -> ca.DevHierarchy:
    return ca.build_dev_hierarchy()


def test_jerarquia_raiz_e_intermedias(hierarchy: ca.DevHierarchy) -> None:
    root = hierarchy.root_cert
    bc = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 1
    for cert, _ in hierarchy.intermediates.values():
        assert ca.verify_issued_by(cert, root)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca and bc.path_length == 0
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign and ku.crl_sign and not ku.digital_signature


@pytest.mark.parametrize(
    ("profile", "eku"),
    [
        (
            "service",
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
        ),
        ("device", [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
        ("event-signing", [ca.EVENT_SIGNING_EKU]),
    ],
)
def test_perfiles_con_extensiones_correctas(
    hierarchy: ca.DevHierarchy, profile: str, eku: list[x509.ObjectIdentifier]
) -> None:
    issuer_cert, issuer_key = hierarchy.intermediates[ca.PROFILES[profile].issuer]
    cert = ca.issue_certificate(ca.load_csr(make_csr("svc-a")), profile, issuer_cert, issuer_key)
    ext = cert.extensions
    assert ext.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert ext.get_extension_for_class(x509.BasicConstraints).critical
    ku = ext.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_cert_sign
    assert list(ext.get_extension_for_class(x509.ExtendedKeyUsage).value) == eku
    ext.get_extension_for_class(x509.SubjectAlternativeName)
    ext.get_extension_for_class(x509.SubjectKeyIdentifier)
    ext.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert ca.verify_issued_by(cert, issuer_cert)
    assert not ca.verify_issued_by(cert, hierarchy.root_cert)  # no la firma la raíz
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days <= ca.PROFILES[
        profile
    ].max_days


def test_vigencia_se_recorta_al_maximo_del_perfil(hierarchy: ca.DevHierarchy) -> None:
    issuer_cert, issuer_key = hierarchy.intermediates["services"]
    cert = ca.issue_certificate(
        ca.load_csr(make_csr()), "service", issuer_cert, issuer_key, valid_days=999
    )
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days <= 91


def test_crl_v2_contiene_serial_revocado(hierarchy: ca.DevHierarchy) -> None:
    import datetime as dt

    cert, key = hierarchy.intermediates["events"]
    crl = ca.build_crl(cert, key, [(1234, dt.datetime.now(dt.UTC), "keyCompromise")], crl_number=7)
    assert crl.is_signature_valid(cert.public_key())  # type: ignore[arg-type]
    assert crl.get_revoked_certificate_by_serial_number(1234) is not None
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 7


def test_csr_con_cn_invalido_se_rechaza() -> None:
    with pytest.raises(ca.CSRValidationError):
        ca.csr_common_name(ca.load_csr(make_csr("CN con espacios; DROP")))


# --- TSA ------------------------------------------------------------------------------------
def test_timestamp_request_der_contiene_sha256() -> None:
    import hashlib

    req = build_timestamp_request(b"crl", nonce=5)
    assert req[0] == 0x30
    assert hashlib.sha256(b"crl").digest() in req
    assert bytes.fromhex("608648016503040201") in req  # OID sha256
