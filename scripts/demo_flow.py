"""Recorrido punta a punta del Módulo 1 contra un servicio en marcha (guion de la demo).

Uso:
    python scripts/demo_flow.py --base http://localhost:8000 \
        --admin-email admin@example.com --admin-password '<BOOTSTRAP_ADMIN_PASSWORD>'

Cada paso imprime OK/FALLO. Termina con código 1 si algo falla.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

failures = 0


def step(name: str, ok: bool, extra: str = "") -> None:
    global failures
    failures += 0 if ok else 1
    print(f"[{'OK ' if ok else 'FALLO'}] {name}{(' · ' + extra) if extra else ''}")


def csr(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return req.public_bytes(serialization.Encoding.PEM).decode()


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    def part(p: str) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        return data

    h, p, _ = token.split(".")
    return part(h), part(p)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--admin-email", required=True)
    ap.add_argument("--admin-password", required=True)
    args = ap.parse_args()
    c = httpx.Client(base_url=args.base, timeout=10)

    r = c.get("/health")
    step("Servicio arriba (/health)", r.status_code == 200, str(r.json().get("checks")))

    jwks = c.get("/.well-known/jwks.json").json()
    step("JWKS publicado", bool(jwks.get("keys")), f"kids={[k['kid'] for k in jwks['keys']]}")

    email = f"comprador.{secrets.token_hex(3)}@example.com"
    pwd = "boletos-seguros-" + secrets.token_hex(4)
    r = c.post("/auth/register", json={"email": email, "password": pwd, "nombre": "Ana Demo"})
    step("Registro de comprador (Argon2id)", r.status_code == 201, email)

    r = c.post(
        "/auth/register",
        json={"email": "x@example.com", "password": "password123", "nombre": "Débil"},
    )
    step("Contraseña común rechazada (NIST)", r.status_code == 400)

    r = c.post("/auth/login", json={"email": email, "password": pwd})
    tokens = r.json()
    step("Login emite JWT ES256 + refresh", r.status_code == 200)
    header, claims = decode_jwt(tokens["access_token"])
    step(
        "JWT con alg=ES256, kid e idh",
        header["alg"] == "ES256" and "idh" in claims,
        f"kid={header['kid']} idh={claims['idh'][:12]}…",
    )

    r = c.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    step("/auth/me con el token", r.status_code == 200 and r.json()["role"] == "buyer")

    r1 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    step("Refresh rota el token", r1.status_code == 200)
    r2 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    step("Refresh reutilizado → 401 y familia revocada", r2.status_code == 401)
    r3 = c.post("/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]})
    step("El token nuevo de esa familia también quedó revocado", r3.status_code == 401)

    forged = header | {"alg": "none"}
    none_tok = (
        base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
        + "."
        + tokens["access_token"].split(".")[1]
        + "."
    )
    r = c.get("/auth/me", headers={"Authorization": f"Bearer {none_tok}"})
    step("Token con alg=none rechazado", r.status_code == 401)

    r = c.post("/auth/login", json={"email": args.admin_email, "password": args.admin_password})
    step("Login de admin", r.status_code == 200)
    admin = {"Authorization": f"Bearer {r.json().get('access_token', '')}"}

    r = c.post(
        "/pki/csr",
        headers=admin,
        json={
            "csr_pem": csr("m4-tickets-evento-demo"),
            "profile": "event-signing",
            "valid_days": 30,
        },
    )
    step(
        "CSR event-signing firmado por la intermedia de eventos",
        r.status_code == 200,
        r.json().get("serial_number", r.text[:80]),
    )
    serial = r.json().get("serial_number", "")

    r = c.post("/devices/enrollment-codes", headers=admin, json={"device_name": "Puerta-Norte-01"})
    code = r.json().get("enrollment_code", "")
    step("Código de enrolamiento de un solo uso", r.status_code == 201)
    r = c.post("/devices/enroll", json={"code": code, "csr_pem": csr("scanner")})
    step(
        "Escáner enrolado con su certificado",
        r.status_code == 201,
        r.json().get("cert_serial", r.text[:80]),
    )
    r = c.post("/devices/enroll", json={"code": code, "csr_pem": csr("scanner")})
    step("El mismo código no funciona dos veces", r.status_code == 400)

    r = c.post(
        "/pki/revoke", headers=admin, json={"serial_number": serial, "reason": "keyCompromise"}
    )
    step("Revocación del certificado de evento", r.status_code == 200)
    crls = c.get("/pki/crl").text
    found = False
    for block in crls.split("-----END X509 CRL-----"):
        if "BEGIN X509 CRL" in block:
            crl = x509.load_pem_x509_crl((block + "-----END X509 CRL-----\n").strip().encode())
            found |= crl.get_revoked_certificate_by_serial_number(int(serial, 16)) is not None
    step("El serial revocado aparece en la CRL", found)

    r = c.get("/admin/audit", headers=admin, params={"limit": 5})
    step(
        "Bitácora de seguridad consultable",
        r.status_code == 200,
        f"{r.json().get('total')} eventos",
    )

    print(f"\n{'Todo correcto' if failures == 0 else f'{failures} paso(s) fallaron'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
