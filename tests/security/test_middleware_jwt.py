"""Middleware de validación JWT para los demás módulos (BT-03, Brandon) contra M1 real.

Adaptado del PR #1: ahora se valida contra el JWKS que publica el servicio y contra los
vectores compartidos (JO-01), no contra una llave fija embebida en el código.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from middleware.python.jwt_auth import JWKSVerifier
from tests.conftest import register_and_login

VECTORS = Path(__file__).resolve().parents[2] / "contracts" / "test-vectors"


def _verifier(jwks: dict[str, Any], audience: str = "boletera-api") -> JWKSVerifier:
    v = JWKSVerifier("http://m1/.well-known/jwks.json", "https://auth.boletera.local", audience)
    keys = {k["kid"]: jwt.PyJWK.from_dict(k) for k in jwks["keys"]}
    patcher = patch.object(v, "_fetch_jwks", return_value=keys)
    patcher.start()
    return v


@pytest.mark.parametrize("role", ["buyer", "admin", "staff"])
def test_middleware_valida_tokens_del_stub(client: TestClient, role: str) -> None:
    token = client.post("/dev/token", json={"role": role}).json()["access_token"]
    user = _verifier(client.get("/.well-known/jwks.json").json()).verify(token)
    assert user.role == role and len(user.idh) == 64


def test_middleware_valida_token_de_login_real(client: TestClient) -> None:
    s = register_and_login(client)
    user = _verifier(client.get("/.well-known/jwks.json").json()).verify(s["access_token"])
    assert user.role == "buyer"


def test_middleware_con_vectores_compartidos() -> None:
    vec = json.loads((VECTORS / "jwt_es256.json").read_text())
    v = _verifier(vec["jwks"])
    assert v.verify(vec["token"]).sub == vec["expected_claims"]["sub"]
    neg = json.loads((VECTORS / "jwt_negative.json").read_text())
    for name in ("alg_none", "hs256_with_public_key", "tampered_payload"):
        with pytest.raises(HTTPException) as exc:
            v.verify(neg[name])
        assert exc.value.status_code == 401, name


def test_middleware_rechaza_audiencia_ajena(client: TestClient) -> None:
    token = client.post("/dev/token", json={"role": "buyer"}).json()["access_token"]
    with pytest.raises(HTTPException):
        _verifier(client.get("/.well-known/jwks.json").json(), audience="otra-api").verify(token)
