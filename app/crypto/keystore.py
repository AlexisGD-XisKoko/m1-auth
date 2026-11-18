"""Key Manager (JO-05 · RNF-07).

Las llaves privadas (firma JWT e intermedias de la CA) se guardan cifradas con
AES-256-GCM bajo la KEK. Cada operación usa un nonce aleatorio de 96 bits y el
identificador de la llave como dato asociado (AAD), de modo que un blob cifrado no
puede moverse de una fila a otra sin que falle la verificación.

Formato almacenado: base64( nonce(12) || ciphertext || tag(16) ).
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12


class KeyStore:
    def __init__(self, kek: bytes) -> None:
        if len(kek) != 32:
            raise ValueError("La KEK debe medir 32 bytes (AES-256).")
        self._aead = AESGCM(kek)

    def encrypt(self, plaintext: bytes, key_id: str) -> str:
        nonce = os.urandom(NONCE_BYTES)
        ct = self._aead.encrypt(nonce, plaintext, key_id.encode())
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, blob: str, key_id: str) -> bytes:
        raw = base64.b64decode(blob)
        nonce, ct = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
        return self._aead.decrypt(nonce, ct, key_id.encode())

    # --- Llaves EC P-256 ---------------------------------------------------------
    def wrap_private_key(self, key: ec.EllipticCurvePrivateKey, key_id: str) -> str:
        der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return self.encrypt(der, key_id)

    def unwrap_private_key(self, blob: str, key_id: str) -> ec.EllipticCurvePrivateKey:
        key = serialization.load_der_private_key(self.decrypt(blob, key_id), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("La llave almacenada no es ECDSA.")
        return key


def generate_p256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())
