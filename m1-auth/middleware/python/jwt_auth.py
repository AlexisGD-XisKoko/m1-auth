"""Middleware / Dependencia FastAPI reutilizable para validación JWT (BT-03).

Diseñado para ser compartido con M2, M3, M4 y M6 (Python / FastAPI).
Cumple RNF-02, RNF-03 y Sección 4.5:
- Acepta exclusivamente ES256 (rechaza 'none', 'HS256', etc.)
- Caché de JWKS de 10 minutos (600 s) con refresco único ante kid desconocido
- Valida iss, aud, exp, nbf y presencia de sub, role e idh
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedUser:
    sub: str
    role: str
    idh: str
    jti: str
    iss: str
    aud: str | list[str]


class JWKSVerifier:
    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str,
        cache_ttl_seconds: int = 600,
    ) -> None:
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.cache_ttl_seconds = cache_ttl_seconds
        self._lock = threading.Lock()
        self._keys_by_kid: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float = 0.0

    def _fetch_jwks(self) -> dict[str, jwt.PyJWK]:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(self.jwks_url)
            resp.raise_for_status()
            data = resp.json()
        keys: dict[str, jwt.PyJWK] = {}
        for jwk_dict in data.get("keys", []):
            kid = jwk_dict.get("kid")
            if kid:
                keys[kid] = jwt.PyJWK.from_dict(jwk_dict)
        return keys

    def _get_signing_key(self, kid: str) -> jwt.PyJWK:
        now = time.monotonic()
        with self._lock:
            cache_expired = (now - self._fetched_at) >= self.cache_ttl_seconds
            if cache_expired or not self._keys_by_kid:
                self._keys_by_kid = self._fetch_jwks()
                self._fetched_at = now

            if kid not in self._keys_by_kid:
                # Refresco único para soportar rotación de llaves por kid (Sección 5.4)
                self._keys_by_kid = self._fetch_jwks()
                self._fetched_at = time.monotonic()

            key = self._keys_by_kid.get(kid)
            if key is None:
                raise jwt.InvalidTokenError(f"kid desconocido: {kid}")
            return key

    def verify(self, token: str) -> AuthenticatedUser:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Header JWT inválido.",
            ) from exc

        if header.get("alg") != "ES256":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Algoritmo JWT no permitido; solo se acepta ES256.",
            )

        kid = header.get("kid")
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Falta el identificador de llave (kid) en el header.",
            )

        try:
            jwk_key = self._get_signing_key(kid)
            payload = jwt.decode(
                token,
                jwk_key.key,
                algorithms=["ES256"],  # Lista blanca fija (RNF-02)
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": ["sub", "role", "iss", "aud", "exp", "iat", "jti", "idh"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except HTTPException:
            raise
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token inválido o expirado: {exc}",
            ) from exc

        return AuthenticatedUser(
            sub=str(payload["sub"]),
            role=str(payload["role"]),
            idh=str(payload["idh"]),
            jti=str(payload["jti"]),
            iss=str(payload["iss"]),
            aud=payload["aud"],
        )


def create_jwt_verifier(
    jwks_url: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    cache_ttl_seconds: int = 600,
) -> JWKSVerifier:
    return JWKSVerifier(
        jwks_url=jwks_url or os.getenv("M1_JWKS_URL", "http://m1-auth:8000/.well-known/jwks.json"),
        issuer=issuer or os.getenv("JWT_ISSUER", "https://auth.boletera.local"),
        audience=audience or os.getenv("JWT_AUDIENCE", "boletera-api"),
        cache_ttl_seconds=cache_ttl_seconds,
    )


_default_verifier = create_jwt_verifier()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Se requiere token Bearer.",
        )
    return _default_verifier.verify(credentials.credentials)


def require_roles(*allowed_roles: str) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    async def _checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos suficientes para esta operación.",
            )
        return user

    return _checker
