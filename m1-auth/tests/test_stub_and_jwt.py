"""Pruebas del Stub (BT-02) y del Middleware JWT (BT-03) incluyendo casos negativos (Sección 4.5)."""

import time
from unittest.mock import patch

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.stub_keys import STUB_KID, STUB_PUBLIC_JWK, sign_stub_jwt
from app.main import app
from middleware.python.jwt_auth import JWKSVerifier

client = TestClient(app)


def test_health_and_jwks():
    resp_h = client.get("/health")
    assert resp_h.status_code == 200
    assert resp_h.json()["status"] == "ok"

    resp_jwks = client.get("/.well-known/jwks.json")
    assert resp_jwks.status_code == 200
    assert "max-age=600" in resp_jwks.headers.get("cache-control", "")
    keys = resp_jwks.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == STUB_KID
    assert keys[0]["alg"] == "ES256"


@pytest.mark.parametrize("role", ["buyer", "admin", "staff"])
def test_dev_token_and_python_middleware_valid(role: str):
    resp = client.post("/dev/token", json={"role": role})
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    verifier = JWKSVerifier(
        jwks_url="http://test/.well-known/jwks.json",
        issuer="https://auth.boletera.local",
        audience="boletera-api",
    )
    with patch.object(verifier, "_fetch_jwks", return_value={STUB_KID: jwt.PyJWK.from_dict(STUB_PUBLIC_JWK)}):
        user = verifier.verify(token)
        assert user.role == role
        assert len(user.idh) == 64


def test_reject_alg_none():
    token = jwt.encode({"sub": "1", "role": "admin"}, None, algorithm=None)
    verifier = JWKSVerifier("http://test", "https://auth.boletera.local", "boletera-api")
    with pytest.raises(HTTPException) as exc:
        verifier.verify(token)
    assert exc.value.status_code == 401


def test_reject_expired_wrong_iss_aud_unknown_kid():
    verifier = JWKSVerifier("http://test", "https://auth.boletera.local", "boletera-api")
    jwks_map = {STUB_KID: jwt.PyJWK.from_dict(STUB_PUBLIC_JWK)}

    with patch.object(verifier, "_fetch_jwks", return_value=jwks_map):
        # Expirado
        expired_tok, _ = sign_stub_jwt(role="buyer", ttl_seconds=-10)
        with pytest.raises(HTTPException) as exc1:
            verifier.verify(expired_tok)
        assert exc1.value.status_code == 401

        # iss incorrecto
        bad_iss, _ = sign_stub_jwt(role="buyer", issuer="https://evil.local")
        with pytest.raises(HTTPException) as exc2:
            verifier.verify(bad_iss)
        assert exc2.value.status_code == 401

        # aud incorrecto
        bad_aud, _ = sign_stub_jwt(role="buyer", audience="otra-api")
        with pytest.raises(HTTPException) as exc3:
            verifier.verify(bad_aud)
        assert exc3.value.status_code == 401

        # kid desconocido
        unknown_kid_tok = jwt.encode(
            {"sub": "1", "role": "buyer", "iss": "https://auth.boletera.local", "aud": "boletera-api", "exp": int(time.time()) + 60, "iat": int(time.time()), "jti": "x", "idh": "y"},
            key=open if False else __import__("app.core.stub_keys", fromlist=["STUB_PRIVATE_KEY_PEM"]).STUB_PRIVATE_KEY_PEM,
            algorithm="ES256",
            headers={"kid": "kid-inexistente"},
        )
        with pytest.raises(HTTPException) as exc4:
            verifier.verify(unknown_kid_tok)
        assert exc4.value.status_code == 401
