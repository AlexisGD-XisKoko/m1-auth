"""Cliente de sellado de tiempo RFC 3161 (JO-08 · RF-14, RF-18 · TSA de la TTP).

M1 envía a la TTP solo el SHA-256 del dato (la CRL o un evento de la bitácora) y
guarda el token de sello que devuelve. Si TSA_URL no está configurada, el sellado se
omite y la columna tsa_token queda en NULL (la funcionalidad es «deseable»).

La verificación criptográfica del token contra el certificado tsa de la TTP queda
pendiente para JO-08 (`openssl ts -verify` o rfc3161ng), ver README.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets

import httpx

log = logging.getLogger(__name__)

_SHA256_OID_DER = bytes.fromhex("0609608648016503040201")  # 2.16.840.1.101.3.4.2.1


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
    return _tlv(0x02, raw)


def build_timestamp_request(data: bytes, nonce: int | None = None) -> bytes:
    """TimeStampReq DER: version 1, messageImprint(SHA-256), nonce y certReq=TRUE."""
    digest = hashlib.sha256(data).digest()
    algorithm = _tlv(0x30, _SHA256_OID_DER + b"\x05\x00")
    imprint = _tlv(0x30, algorithm + _tlv(0x04, digest))
    body = _der_int(1) + imprint + _der_int(nonce or secrets.randbits(63)) + b"\x01\x01\xff"
    return _tlv(0x30, body)


def request_timestamp(tsa_url: str, data: bytes, timeout: float = 3.0) -> str | None:
    """Devuelve el TimeStampResp en base64, o None si la TTP no respondió."""
    if not tsa_url:
        return None
    try:
        resp = httpx.post(
            tsa_url,
            content=build_timestamp_request(data),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=timeout,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("No se obtuvo sello de tiempo de la TTP: %s", exc.__class__.__name__)
        return None
    return base64.b64encode(resp.content).decode()
