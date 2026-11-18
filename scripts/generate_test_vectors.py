"""Vectores de prueba compartidos (JO-01) → contracts/test-vectors/*.json.

Usa una llave P-256 FIJA y PÚBLICA (tests/vectors/test_key_p256.pem), solo de prueba,
para que M4 (Java), M5 (WebCrypto) y M6 comprueben que verifican igual que M1:
JWT ES256, firma en DER y en R‖S, idh de ejemplo, payload canónico y casos negativos.
Copiar la carpeta a platform/contracts/test-vectors y avisar a M4 y M5.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "contracts" / "test-vectors"
KEY_PATH = ROOT / "tests" / "vectors" / "test_key_p256.pem"

KID = "m1-test-vector-key"
ISS, AUD = "https://auth.boletera.local", "boletera-api"
IAT, EXP = 1_763_000_000, 4_102_444_800  # 2025-11-13 → 2100-01-01 (no expira en el curso)
TEST_PEPPER = b"pepper-de-prueba-32-bytes-exacto"  # 32 bytes, solo vectores


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> None:
    key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)  # noqa: S101
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": KID,
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }
    user_id = "6f1f2a8e-1c2b-4d3e-9f40-123456789abc"
    idh = hmac.new(TEST_PEPPER, user_id.encode(), hashlib.sha256).hexdigest()
    claims = {
        "sub": user_id,
        "role": "buyer",
        "iss": ISS,
        "aud": AUD,
        "iat": IAT,
        "nbf": IAT,
        "exp": EXP,
        "jti": "00000000-0000-4000-8000-000000000001",
        "idh": idh,
    }
    token = jwt.encode(claims, key, algorithm="ES256", headers={"kid": KID, "typ": "JWT"})

    payload = {"ticket_id": "T-0001", "event_id": "E-01", "seat": "A-12", "owner_idh": idh}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    der = key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    pub_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    header_none = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = token.split(".")[1]
    # Confusión de algoritmo: HS256 usando la llave PÚBLICA como secreto (PyJWT lo prohíbe,
    # por eso se arma a mano).
    hs_head = b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    hs_sig = hmac.new(pub_pem.encode(), f"{hs_head}.{body}".encode(), hashlib.sha256).digest()
    hs256 = f"{hs_head}.{body}.{b64u(hs_sig)}"

    OUT.mkdir(parents=True, exist_ok=True)
    vectors = {
        "jwt_es256.json": {
            "description": "JWT ES256 válido emitido por M1 (llave de prueba).",
            "jwks": {"keys": [jwk]},
            "token": token,
            "expected_claims": claims,
            "verify_with": {"algorithms": ["ES256"], "issuer": ISS, "audience": AUD},
        },
        "ecdsa_der_vs_raw.json": {
            "description": "Misma firma ECDSA P-256/SHA-256 en DER (OpenSSL/Java) "
            "y R||S (JWS/WebCrypto).",
            "public_key_pem": pub_pem,
            "message_utf8": canonical.decode(),
            "signature_der_b64": base64.b64encode(der).decode(),
            "signature_raw_rs_b64url": b64u(raw),
        },
        "idh.json": {
            "description": "idh = HMAC-SHA256(pepper, user_id) en hex minúsculas.",
            "pepper_b64": base64.b64encode(TEST_PEPPER).decode(),
            "user_id": user_id,
            "idh": idh,
        },
        "canonical_payload.json": {
            "description": "Payload canónico: JSON con llaves ordenadas y sin espacios, UTF-8.",
            "input": payload,
            "canonical_utf8": canonical.decode(),
            "sha256_hex": hashlib.sha256(canonical).hexdigest(),
        },
        "jwt_negative.json": {
            "description": "Tokens que TODO verificador debe rechazar.",
            "alg_none": f"{header_none}.{body}.",
            "hs256_with_public_key": hs256,
            "tampered_payload": token.split(".")[0]
            + "."
            + b64u(json.dumps(claims | {"role": "admin"}).encode())
            + "."
            + token.split(".")[2],
        },
    }
    for name, content in vectors.items():
        (OUT / name).write_text(json.dumps(content, indent=2, ensure_ascii=False) + "\n")
        print(f"escrito {OUT.relative_to(ROOT) / name}")


if __name__ == "__main__":
    main()
