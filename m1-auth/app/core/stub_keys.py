"""Llave ECDSA P-256 fija EXCLUSIVA para el stub de desarrollo (BT-02 / Hito H1).

ADVERTENCIA DE SEGURIDAD:
Esta llave es únicamente para el entorno de pruebas del stub (H1).
En producción / S2+, las llaves se generan en ceremonia, se cifran con KEK (AES-256-GCM)
y se almacenan en auth.signing_keys (RNF-07).
"""

import hashlib
import hmac
import time
import uuid
from typing import Literal

import jwt

STUB_KID = "m1-stub-key-2026-11"

# Llave pública en formato JWK (RFC 7517) para /.well-known/jwks.json
STUB_PUBLIC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "use": "sig",
    "alg": "ES256",
    "kid": STUB_KID,
    "x": "DwHLJR0TPMpPwNqpzpq4uo9b3CHXmyamkYjqi6y3gZo",
    "y": "YGqTNUbIDYL9CSqsFUWvSm6gOg269lVGmfbcjMWSwHk",
}

# Llave privada P-256 de prueba (solo para firmar tokens en el stub de desarrollo BT-02)
STUB_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+WizLU+DvCKQO9ki
PpILD041wbcnb/2oxN9O31eAGsyhRANCAAQPAcslHRM8yk/A2qnOmri6j1vcIdeb
JqaRiOqLrLeBmmBqkzVGyA2C/QkqrBVFr0puoDoNuvZVRpn23IzFksB5
-----END PRIVATE KEY-----"""

STUB_DEV_PEPPER = b"m1-stub-dev-pepper-32-bytes-only"


def compute_stub_idh(user_id: str) -> str:
    """Calcula el hash de identidad del comprador: HMAC-SHA256(pepper, user_id) (RF-09)."""
    return hmac.new(STUB_DEV_PEPPER, user_id.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_stub_jwt(
    *,
    role: Literal["buyer", "admin", "staff"],
    user_id: str | None = None,
    issuer: str = "https://auth.boletera.local",
    audience: str = "boletera-api",
    ttl_seconds: int = 900,
) -> tuple[str, dict]:
    """Firma un JWT ES256 válido para pruebas de integración (BT-02 / RNF-03)."""
    now = int(time.time())
    sub = user_id or str(uuid.uuid4())
    jti = str(uuid.uuid4())
    idh = compute_stub_idh(sub)

    claims = {
        "sub": sub,
        "role": role,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": jti,
        "idh": idh,
    }
    token = jwt.encode(
        claims,
        STUB_PRIVATE_KEY_PEM,
        algorithm="ES256",
        headers={"kid": STUB_KID, "typ": "JWT"},
    )
    return token, claims
