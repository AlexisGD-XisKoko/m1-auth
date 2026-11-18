"""Token Service (JO-04 · RF-02, RF-08, RF-09 · RNF-02, RNF-03, RNF-04).

- JWT firmados con ES256 (ECDSA P-256 + SHA-256); algoritmo fijo en la verificación.
- Claims: sub, role, iss, aud, iat, nbf, exp, jti, idh. Header con kid y typ=JWT.
- Hash de identidad del comprador: idh = HMAC-SHA256(pepper, user_id) en hex.
- Refresh tokens y códigos: 32 bytes del CSPRNG, almacenados solo como SHA-256.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ALGORITHM = "ES256"
REQUIRED_CLAIMS = ["sub", "role", "iss", "aud", "iat", "nbf", "exp", "jti", "idh"]


def b64url_uint(value: int) -> str:
    raw = value.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwk(public_key: ec.EllipticCurvePublicKey, kid: str) -> dict[str, str]:
    nums = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": ALGORITHM,
        "kid": kid,
        "x": b64url_uint(nums.x),
        "y": b64url_uint(nums.y),
    }


def new_kid() -> str:
    return f"m1-{time.strftime('%Y%m%d', time.gmtime())}-{secrets.token_hex(4)}"


def compute_idh(pepper: bytes, user_id: str) -> str:
    return hmac.new(pepper, user_id.encode(), hashlib.sha256).hexdigest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_opaque_token() -> str:
    """32 bytes aleatorios en base64url (refresh tokens y códigos de enrolamiento)."""
    return secrets.token_urlsafe(32)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


@dataclass(frozen=True)
class IssuedToken:
    token: str
    claims: dict[str, Any]


def sign_access_token(
    *,
    private_key: ec.EllipticCurvePrivateKey,
    kid: str,
    sub: str,
    role: str,
    idh: str,
    issuer: str,
    audience: str,
    ttl_seconds: int,
    now: int | None = None,
) -> IssuedToken:
    issued_at = int(time.time()) if now is None else now
    claims: dict[str, Any] = {
        "sub": sub,
        "role": role,
        "iss": issuer,
        "aud": audience,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "idh": idh,
    }
    token = jwt.encode(claims, private_key, algorithm=ALGORITHM, headers={"kid": kid, "typ": "JWT"})
    return IssuedToken(token=token, claims=claims)


class TokenVerificationError(Exception):
    pass


def verify_access_token(
    token: str,
    *,
    public_keys: dict[str, ec.EllipticCurvePublicKey],
    issuer: str,
    audience: str,
    leeway_seconds: int = 5,
) -> dict[str, Any]:
    """Verifica un JWT con la lista blanca {ES256}. Lanza TokenVerificationError."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenVerificationError("Token mal formado.") from exc
    if header.get("alg") != ALGORITHM:
        raise TokenVerificationError("Algoritmo no permitido.")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in public_keys:
        raise TokenVerificationError("kid desconocido.")
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            public_keys[kid],
            algorithms=[ALGORITHM],
            issuer=issuer,
            audience=audience,
            leeway=leeway_seconds,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise TokenVerificationError("Token inválido o expirado.") from exc
    return claims
