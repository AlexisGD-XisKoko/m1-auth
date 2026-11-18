"""Integración de identidades: registro, login, sesión, roles y bitácora (S2)."""

from __future__ import annotations

import jwt
from fastapi.testclient import TestClient

from tests.conftest import (
    ADMIN_EMAIL,
    STRONG_PASSWORD,
    bearer,
    register_and_login,
    unique_email,
)


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["checks"]["db"] == "ok"
    assert "X-Correlation-ID" in r.headers


def test_registro_login_me_con_claims_rnf03(client: TestClient) -> None:
    s = register_and_login(client)
    header = jwt.get_unverified_header(s["access_token"])
    claims = jwt.decode(s["access_token"], options={"verify_signature": False})
    assert header["alg"] == "ES256" and header["kid"]
    for c in ("sub", "role", "iss", "aud", "iat", "nbf", "exp", "jti", "idh"):
        assert c in claims
    assert claims["exp"] - claims["iat"] == 900
    me = client.get("/auth/me", headers=bearer(s["access_token"]))
    assert me.status_code == 200
    body = me.json()
    assert body["role"] == "buyer" and body["idh"] == claims["idh"]
    assert "password_hash" not in body


def test_kid_del_token_esta_en_el_jwks(client: TestClient) -> None:
    s = register_and_login(client)
    kid = jwt.get_unverified_header(s["access_token"])["kid"]
    jwks = client.get("/.well-known/jwks.json")
    assert "max-age=600" in jwks.headers["cache-control"]
    assert kid in [k["kid"] for k in jwks.json()["keys"]]


def test_correo_duplicado_409_formato_rfc7807(client: TestClient) -> None:
    email = unique_email()
    body = {"email": email, "password": STRONG_PASSWORD, "nombre": "Uno"}
    assert client.post("/auth/register", json=body).status_code == 201
    r = client.post("/auth/register", json=body | {"email": email.upper()})
    assert r.status_code == 409
    assert r.headers["content-type"].startswith("application/problem+json")
    p = r.json()
    assert {"type", "title", "status", "detail", "instance", "correlation_id"} <= set(p)


def test_politica_nist_rechaza_comunes_y_cortas(client: TestClient) -> None:
    for pwd in ("password123", "qwerty123", "corta"):
        r = client.post(
            "/auth/register", json={"email": unique_email(), "password": pwd, "nombre": "X"}
        )
        assert r.status_code in (400, 422), pwd


def test_refresh_rota_y_logout_revoca(client: TestClient) -> None:
    s = register_and_login(client)
    r = client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["refresh_token"] != s["refresh_token"]
    r = client.post(
        "/auth/logout",
        json={"refresh_token": new["refresh_token"]},
        headers=bearer(new["access_token"]),
    )
    assert r.status_code == 204
    r = client.post("/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert r.status_code == 401


def test_logout_requiere_autenticacion(client: TestClient) -> None:
    r = client.post("/auth/logout", json={"refresh_token": "x" * 40})
    assert r.status_code == 401


def test_admin_gestiona_usuarios_y_roles(client: TestClient, admin_headers: dict[str, str]) -> None:
    email = unique_email("staff")
    r = client.post(
        "/admin/users",
        headers=admin_headers,
        json={"email": email, "password": STRONG_PASSWORD, "nombre": "Staff", "role": "staff"},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    r = client.get("/admin/users", headers=admin_headers, params={"q": email})
    assert r.json()["total"] == 1
    r = client.patch(f"/admin/users/{uid}", headers=admin_headers, json={"role": "buyer"})
    assert r.json()["role"] == "buyer"
    # Al desactivarlo ya no puede iniciar sesión
    client.patch(f"/admin/users/{uid}", headers=admin_headers, json={"status": "DEACTIVATED"})
    r = client.post("/auth/login", json={"email": email, "password": STRONG_PASSWORD})
    assert r.status_code == 401


def test_cambio_de_rol_aplica_de_inmediato(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    s = register_and_login(client)
    me = client.get("/auth/me", headers=bearer(s["access_token"])).json()
    client.patch(f"/admin/users/{me['id']}", headers=admin_headers, json={"role": "admin"})
    r = client.get("/admin/users", headers=bearer(s["access_token"]))
    assert r.status_code == 200  # el rol se lee de la BD, no solo del token


def test_admin_no_puede_quitarse_el_rol(client: TestClient, admin_headers: dict[str, str]) -> None:
    me = client.get("/auth/me", headers=admin_headers).json()
    assert me["email"] == ADMIN_EMAIL
    r = client.patch(f"/admin/users/{me['id']}", headers=admin_headers, json={"role": "buyer"})
    assert r.status_code == 403


def test_comprador_no_accede_a_admin(client: TestClient) -> None:
    s = register_and_login(client)
    for path in ("/admin/users", "/admin/audit", "/pki/certificates", "/devices"):
        assert client.get(path, headers=bearer(s["access_token"])).status_code == 403


def test_bitacora_registra_eventos(client: TestClient, admin_headers: dict[str, str]) -> None:
    register_and_login(client)
    r = client.get("/admin/audit", headers=admin_headers, params={"action": "login.success"})
    assert r.status_code == 200
    items = r.json()["items"]
    assert items and items[0]["correlation_id"]
    text = r.text.lower()
    assert "password" not in text and "refresh_token" not in text


def test_rotacion_de_llave_publica_ambas(client: TestClient, admin_headers: dict[str, str]) -> None:
    old = register_and_login(client)
    r = client.post("/admin/signing-keys/rotate", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["new_kid"] in data["published_kids"] and len(data["published_kids"]) >= 2
    # El token firmado con la llave anterior sigue siendo válido durante la transición
    assert client.get("/auth/me", headers=bearer(old["access_token"])).status_code == 200
    new = register_and_login(client)
    assert jwt.get_unverified_header(new["access_token"])["kid"] == data["new_kid"]


def test_dev_stub_emite_token_valido(client: TestClient) -> None:
    r = client.post("/dev/token", json={"role": "staff"})
    assert r.status_code == 200
    kid = r.json()["kid"]
    assert kid in [k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]]
