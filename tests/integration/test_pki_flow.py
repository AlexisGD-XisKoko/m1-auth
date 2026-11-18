"""Integración de PKI: CSR por perfil, cadena hasta la raíz, revocación y CRL (S3)."""

from __future__ import annotations

from cryptography import x509
from fastapi.testclient import TestClient

from app.crypto import ca
from tests.conftest import make_csr, split_pem


def test_cadena_publica_intermedias_y_raiz(client: TestClient) -> None:
    r = client.get("/pki/ca-chain")
    assert r.status_code == 200
    certs = [x509.load_pem_x509_certificate(p.encode()) for p in split_pem(r.text)]
    assert len(certs) == 4
    root = certs[-1]
    assert root.subject == root.issuer  # autofirmada (TTP)
    for inter in certs[:-1]:
        assert ca.verify_issued_by(inter, root)


def test_m4_obtiene_certificado_event_signing(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/pki/csr",
        headers=admin_headers,
        json={
            "csr_pem": make_csr("m4-tickets-evento-1"),
            "profile": "event-signing",
            "valid_days": 30,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    chain = [x509.load_pem_x509_certificate(p.encode()) for p in split_pem(body["ca_chain_pem"])]
    assert len(chain) == 2  # intermedia de eventos + raíz
    assert ca.verify_issued_by(cert, chain[0]) and ca.verify_issued_by(chain[0], chain[1])
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ca.EVENT_SIGNING_EKU in list(eku)


def test_revocacion_aparece_en_crl_y_publica_evento(
    client: TestClient, admin_headers: dict[str, str], app: object
) -> None:
    r = client.post(
        "/pki/csr", headers=admin_headers, json={"csr_pem": make_csr("svc-x"), "profile": "service"}
    )
    serial = r.json()["serial_number"]
    r = client.post(
        "/pki/revoke",
        headers=admin_headers,
        json={"serial_number": serial, "reason": "keyCompromise"},
    )
    assert r.status_code == 200
    crls = [
        x509.load_pem_x509_crl(p.encode())
        for p in split_pem(client.get("/pki/crl").text, "X509 CRL")
    ]
    assert len(crls) == 3
    assert any(c.get_revoked_certificate_by_serial_number(int(serial, 16)) for c in crls)
    sent = app.state.publisher.sent  # type: ignore[attr-defined]
    assert any(e["event"] == "certificate.revoked" and serial in e["payload"] for e in sent)
    r = client.post(
        "/pki/revoke",
        headers=admin_headers,
        json={"serial_number": serial, "reason": "keyCompromise"},
    )
    assert r.status_code == 409


def test_enrolamiento_de_escaner(client: TestClient, admin_headers: dict[str, str]) -> None:
    r = client.post(
        "/devices/enrollment-codes", headers=admin_headers, json={"device_name": "Puerta-Sur-02"}
    )
    assert r.status_code == 201
    code = r.json()["enrollment_code"]
    r = client.post("/devices/enroll", json={"code": code, "csr_pem": make_csr("scanner")})
    assert r.status_code == 201, r.text
    body = r.json()
    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    eku = list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    assert eku == [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
    devices = client.get("/devices", headers=admin_headers).json()
    assert any(d["id"] == body["device_id"] for d in devices)
    # RF-17: desactivar el dispositivo revoca su certificado
    r = client.post(f"/devices/{body['device_id']}/revoke", headers=admin_headers)
    assert r.json()["status"] == "REVOKED"
    certs = client.get(
        "/pki/certificates", headers=admin_headers, params={"status": "REVOKED"}
    ).json()
    assert body["cert_serial"] in [c["serial"] for c in certs]


def test_servicio_con_certificado_mtls_solicita_su_perfil(
    client: TestClient, admin_headers: dict[str, str], settings: object, monkeypatch: object
) -> None:
    """Acceso «mTLS o admin»: el gateway reenvía el certificado del cliente (BT-09)."""
    import urllib.parse

    monkeypatch.setattr(settings, "trust_proxy_client_cert", True)  # type: ignore[attr-defined]

    def service_cert(cn: str) -> str:
        r = client.post(
            "/pki/csr", headers=admin_headers, json={"csr_pem": make_csr(cn), "profile": "service"}
        )
        return urllib.parse.quote(r.json()["certificate_pem"])

    m4 = {"X-Forwarded-Tls-Client-Cert": service_cert("m4-tickets")}
    r = client.post(
        "/pki/csr",
        headers=m4,
        json={"csr_pem": make_csr("evento-mtls"), "profile": "event-signing"},
    )
    assert r.status_code == 200, r.text
    m2 = {"X-Forwarded-Tls-Client-Cert": service_cert("m2-catalog")}
    r = client.post(
        "/pki/csr", headers=m2, json={"csr_pem": make_csr("evento-x"), "profile": "event-signing"}
    )
    assert r.status_code == 403
    r = client.post(
        "/pki/csr",
        headers={"X-Forwarded-Tls-Client-Cert": "basura"},
        json={"csr_pem": make_csr("x"), "profile": "service"},
    )
    assert r.status_code == 401
