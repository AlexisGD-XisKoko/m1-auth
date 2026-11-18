"""Casos negativos obligatorios (sección 4.5 de la planeación · AG-04, AG-07)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.models import EnrollmentCode, utcnow
from tests.conftest import STRONG_PASSWORD, bearer, make_csr, register_and_login, unique_email


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parts(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    h, p, s = token.split(".")
    dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))  # noqa: E731
    return dec(h), dec(p), s


def _me(client: TestClient, token: str) -> int:
    return client.get("/auth/me", headers=bearer(token)).status_code


# --- JWT -------------------------------------------------------------------------------------
def test_jwt_alg_none_rechazado(client: TestClient) -> None:
    s = register_and_login(client)
    h, p, _ = _parts(s["access_token"])
    forged = f"{_b64u(json.dumps(h | {'alg': 'none'}).encode())}.{_b64u(json.dumps(p).encode())}."
    assert _me(client, forged) == 401


def test_jwt_hs256_con_llave_publica_rechazado(client: TestClient) -> None:
    s = register_and_login(client)
    h, p, _ = _parts(s["access_token"])
    jwk = next(
        k for k in client.get("/.well-known/jwks.json").json()["keys"] if k["kid"] == h["kid"]
    )
    pub = jwt.algorithms.ECAlgorithm.from_jwk(jwk)
    pem = pub.public_bytes(
        serialization.Encoding.PEM,  # type: ignore[union-attr]
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": h["kid"]}).encode())
    body = _b64u(json.dumps(p | {"role": "admin"}).encode())
    sig = _b64u(hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    assert _me(client, f"{head}.{body}.{sig}") == 401


def _forge(client: TestClient, app: Any, **changes: Any) -> str:
    """Firma con la llave REAL de M1 pero alterando claims (iss, aud, exp, kid...)."""
    from app.services.keys import active_signing_key

    s = register_and_login(client)
    _, p, _ = _parts(s["access_token"])
    with app.state.sessionmaker() as db:
        kid, key = active_signing_key(db, app.state.keystore)
    headers = {"kid": changes.pop("kid", kid), "typ": "JWT"}
    for k in [k for k, v in changes.items() if v is None]:
        p.pop(k)
        changes.pop(k)
    return jwt.encode(p | changes, key, algorithm="ES256", headers=headers)


@pytest.mark.parametrize(
    "changes",
    [
        {"exp": int(time.time()) - 60},
        {"aud": "otra-api"},
        {"iss": "https://atacante.example"},
        {"kid": "kid-desconocido"},
        {"nbf": int(time.time()) + 3600},
        {"idh": None},  # claim obligatorio faltante
    ],
    ids=["expirado", "aud", "iss", "kid", "nbf-futuro", "sin-idh"],
)
def test_jwt_claims_invalidos_rechazados(
    client: TestClient, app: Any, changes: dict[str, Any]
) -> None:
    assert _me(client, _forge(client, app, **changes)) == 401


def test_jwt_firmado_con_otra_llave_rechazado(client: TestClient) -> None:
    s = register_and_login(client)
    h, p, _ = _parts(s["access_token"])
    other = ec.generate_private_key(ec.SECP256R1())
    assert _me(client, jwt.encode(p, other, algorithm="ES256", headers={"kid": h["kid"]})) == 401


def test_jwt_payload_alterado_rechazado(client: TestClient) -> None:
    s = register_and_login(client)
    h, p, sig = _parts(s["access_token"])
    head = s["access_token"].split(".")[0]
    tampered = f"{head}.{_b64u(json.dumps(p | {'role': 'admin'}).encode())}.{sig}"
    assert _me(client, tampered) == 401


# --- Refresh tokens --------------------------------------------------------------------------
def test_refresh_reutilizado_revoca_toda_la_familia(client: TestClient) -> None:
    s = register_and_login(client)
    first = client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]}).json()
    reuse = client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]})
    assert reuse.status_code == 401
    assert reuse.json()["type"].endswith("refresh-reuse")
    # el token legítimo más reciente de la familia también quedó revocado
    assert (
        client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code
        == 401
    )


def test_refresh_inventado_rechazado(client: TestClient) -> None:
    assert client.post("/auth/refresh", json={"refresh_token": "x" * 43}).status_code == 401


# --- Fuerza bruta y enumeración --------------------------------------------------------------
def test_rate_limit_responde_429(
    app: Any, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "rate_limit_login_per_ip", 3)
    c = TestClient(app, client=("203.0.113.9", 4000))
    codes = [
        c.post("/auth/login", json={"email": unique_email(), "password": "x"}).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [401, 401, 401] and codes[-1] == 429
    r = c.post("/auth/login", json={"email": unique_email(), "password": "x"})
    assert "retry-after" in r.headers


def test_bloqueo_progresivo_por_cuenta(client: TestClient, settings: Settings) -> None:
    s = register_and_login(client)
    for _ in range(settings.lockout_threshold - 1):
        assert (
            client.post("/auth/login", json={"email": s["email"], "password": "mala"}).status_code
            == 401
        )
    r = client.post("/auth/login", json={"email": s["email"], "password": "mala"})
    assert r.status_code == 429  # se alcanzó el umbral → bloqueo temporal
    # Ni la contraseña correcta funciona mientras dura el bloqueo
    r = client.post("/auth/login", json={"email": s["email"], "password": STRONG_PASSWORD})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_mismo_mensaje_para_usuario_inexistente_y_password_incorrecta(client: TestClient) -> None:
    s = register_and_login(client)
    a = client.post("/auth/login", json={"email": unique_email(), "password": "x" * 10})
    b = client.post("/auth/login", json={"email": s["email"], "password": "x" * 10})
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"] == b.json()["detail"] and a.json()["type"] == b.json()["type"]


# --- PKI -------------------------------------------------------------------------------------
def test_csr_sin_autenticacion_o_como_comprador(client: TestClient) -> None:
    body = {"csr_pem": make_csr(), "profile": "service"}
    assert client.post("/pki/csr", json=body).status_code == 401
    s = register_and_login(client)
    assert client.post("/pki/csr", json=body, headers=bearer(s["access_token"])).status_code == 403


def test_csr_con_firma_invalida(client: TestClient, admin_headers: dict[str, str]) -> None:
    pem = make_csr("svc")
    der = bytearray(x509.load_pem_x509_csr(pem.encode()).public_bytes(serialization.Encoding.DER))
    der[-5] ^= 0xFF  # altera la firma
    bad = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.encodebytes(bytes(der)).decode()
        + "-----END CERTIFICATE REQUEST-----\n"
    )
    r = client.post("/pki/csr", headers=admin_headers, json={"csr_pem": bad, "profile": "service"})
    assert r.status_code == 400


def test_csr_rsa_o_curva_distinta_rechazado(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    for key in (rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP384R1())):
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc")]))
            .sign(key, hashes.SHA256())
        )
        pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        r = client.post(
            "/pki/csr", headers=admin_headers, json={"csr_pem": pem, "profile": "service"}
        )
        assert r.status_code == 400


def test_servicio_no_autorizado_para_perfil(settings: Settings) -> None:
    from app.core.errors import ProblemError
    from app.services.pki import Requester, authorize_profile

    with pytest.raises(ProblemError) as exc:
        authorize_profile(settings, Requester("service", "m2-catalog"), "event-signing")
    assert exc.value.status == 403
    with pytest.raises(ProblemError):
        authorize_profile(settings, Requester("service", "m4-tickets"), "device")
    authorize_profile(settings, Requester("service", "m4-tickets"), "event-signing")


def test_certificado_revocado_en_crl_falla_validacion(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/pki/csr",
        headers=admin_headers,
        json={"csr_pem": make_csr("svc-rev"), "profile": "service"},
    )
    serial = int(r.json()["serial_number"], 16)
    client.post(
        "/pki/revoke",
        headers=admin_headers,
        json={"serial_number": r.json()["serial_number"], "reason": "superseded"},
    )
    pem = client.get("/pki/crl").text
    crls = [
        x509.load_pem_x509_crl((b + "-----END X509 CRL-----\n").strip().encode())
        for b in pem.split("-----END X509 CRL-----")
        if "BEGIN" in b
    ]
    assert any(c.get_revoked_certificate_by_serial_number(serial) for c in crls)


# --- Enrolamiento ------------------------------------------------------------------------------
def test_codigo_de_enrolamiento_usado_o_expirado(
    client: TestClient, admin_headers: dict[str, str], db: Any
) -> None:
    code = client.post(
        "/devices/enrollment-codes", headers=admin_headers, json={"device_name": "Puerta-1"}
    ).json()
    ok = client.post(
        "/devices/enroll", json={"code": code["enrollment_code"], "csr_pem": make_csr()}
    )
    assert ok.status_code == 201
    again = client.post(
        "/devices/enroll", json={"code": code["enrollment_code"], "csr_pem": make_csr()}
    )
    assert again.status_code == 400

    code2 = client.post(
        "/devices/enrollment-codes", headers=admin_headers, json={"device_name": "Puerta-2"}
    ).json()
    row = db.get(EnrollmentCode, __import__("uuid").UUID(code2["id"]))
    row.expires_at = utcnow().replace(year=2020)
    db.commit()
    r = client.post(
        "/devices/enroll", json={"code": code2["enrollment_code"], "csr_pem": make_csr()}
    )
    assert r.status_code == 400


def test_codigo_no_se_consume_si_el_csr_es_invalido(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    code = client.post(
        "/devices/enrollment-codes", headers=admin_headers, json={"device_name": "Puerta-3"}
    ).json()["enrollment_code"]
    assert (
        client.post("/devices/enroll", json={"code": code, "csr_pem": "basura"}).status_code == 400
    )
    assert (
        client.post("/devices/enroll", json={"code": code, "csr_pem": make_csr()}).status_code
        == 201
    )


def test_codigo_inventado(client: TestClient) -> None:
    r = client.post("/devices/enroll", json={"code": "c" * 43, "csr_pem": make_csr()})
    assert r.status_code == 400
