"""Los vectores publicados (JO-01) son consistentes entre sí y con el código de M1."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from jwt.algorithms import ECAlgorithm

from app.crypto.tokens import compute_idh, verify_access_token

VEC = Path(__file__).resolve().parents[2] / "contracts" / "test-vectors"


def load(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((VEC / name).read_text())


def test_jwt_vector_verifica_con_token_service() -> None:
    v = load("jwt_es256.json")
    jwk = v["jwks"]["keys"][0]
    claims = verify_access_token(
        v["token"],
        public_keys={jwk["kid"]: ECAlgorithm.from_jwk(jwk)},  # type: ignore[dict-item]
        issuer=v["verify_with"]["issuer"],
        audience=v["verify_with"]["audience"],
    )
    assert claims == v["expected_claims"]


def test_firma_der_y_raw_son_la_misma() -> None:
    v = load("ecdsa_der_vs_raw.json")
    pub = serialization.load_pem_public_key(v["public_key_pem"].encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    msg = v["message_utf8"].encode()
    der = base64.b64decode(v["signature_der_b64"])
    raw = base64.urlsafe_b64decode(v["signature_raw_rs_b64url"] + "==")
    pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
    rebuilt = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    pub.verify(rebuilt, msg, ec.ECDSA(hashes.SHA256()))


def test_idh_y_payload_canonico() -> None:
    v = load("idh.json")
    assert compute_idh(base64.b64decode(v["pepper_b64"]), v["user_id"]) == v["idh"]
    c = load("canonical_payload.json")
    canon = json.dumps(c["input"], sort_keys=True, separators=(",", ":"))
    assert canon == c["canonical_utf8"]
    assert hashlib.sha256(canon.encode()).hexdigest() == c["sha256_hex"]
