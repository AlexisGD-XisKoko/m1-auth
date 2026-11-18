"""Password Service (JO-03 · RF-07 · RNF-01).

Hash y verificación con Argon2id usando los valores por defecto de argon2-cffi
(m = 64 MiB, t = 3, p = 4), por encima del mínimo de OWASP. El hash se guarda en
formato PHC, que incluye algoritmo, parámetros y salt.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # Argon2id por defecto

# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe (RNF-06).
_DUMMY_HASH = _hasher.hash("usuario-inexistente-para-igualar-tiempos")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_dummy(password: str) -> None:
    """Ejecuta una verificación completa contra un hash ficticio (anti-enumeración)."""
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    """True si el hash se creó con parámetros distintos a los actuales."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
