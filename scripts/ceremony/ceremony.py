"""Scripts de la ceremonia de llaves (JO-06 · DF-07 · sección 4.4 de la planeación).

Pasos (cada uno se corre en la máquina limpia de la ceremonia, con testigos):

  1. ttp-root   [TTP] genera la llave raíz P-256 (PKCS#8 cifrado) y su certificado (10 años).
  2. m1-csr     [M1]  genera las llaves de las 3 intermedias (PKCS#8 cifrado) y sus CSR.
  3. ttp-sign   [TTP] firma los CSR con la raíz (intermedias de 3 años, pathLen=0).
  4. m1-load    [M1]  carga raíz (solo certificado) + intermedias en auth.ca_keys,
                      con las llaves cifradas bajo la KEK. Requiere DATABASE_URL y KEK_BASE64.
  5. acta       imprime las huellas SHA-256 para el acta de la ceremonia.

Ejemplo (ensayo local):
  export CEREMONY_PASSPHRASE='frase-larga-de-los-custodios'
  python scripts/ceremony/ceremony.py ttp-root --out ceremony-out
  python scripts/ceremony/ceremony.py m1-csr   --out ceremony-out
  python scripts/ceremony/ceremony.py ttp-sign --out ceremony-out
  python scripts/ceremony/ceremony.py m1-load  --out ceremony-out
  python scripts/ceremony/ceremony.py acta     --out ceremony-out

La carpeta de salida NUNCA se sube a Git (está en .gitignore). La llave raíz cifrada se
entrega a los custodios de la TTP y se borra de la máquina de la ceremonia.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.crypto import ca  # noqa: E402

NAMES = list(ca.INTERMEDIATES)


def _passphrase() -> bytes:
    value = os.getenv("CEREMONY_PASSPHRASE", "")
    if len(value) < 16:
        sys.exit("Define CEREMONY_PASSPHRASE (mínimo 16 caracteres) antes de correr la ceremonia.")
    return value.encode()


def _save_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(_passphrase()),
        )
    )
    path.chmod(0o600)


def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())
    assert isinstance(key, ec.EllipticCurvePrivateKey)  # noqa: S101
    return key


def _fp(cert: x509.Certificate) -> str:
    return ca.fingerprint_sha256(cert)


def ttp_root(out: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = ca.build_root(key)
    _save_key(key, out / "root.key.enc.pem")
    (out / "root.crt.pem").write_text(ca.cert_to_pem(cert))
    print(f"Raíz creada. SHA-256: {_fp(cert)}")


def m1_csr(out: Path) -> None:
    for name, cn in ca.INTERMEDIATES.items():
        key = ec.generate_private_key(ec.SECP256R1())
        csr = ca.build_intermediate_csr(key, cn)
        _save_key(key, out / f"{name}.key.enc.pem")
        (out / f"{name}.csr.pem").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        digest = hashes.Hash(hashes.SHA256())
        digest.update(csr.public_bytes(serialization.Encoding.DER))
        print(f"CSR {name}: SHA-256 {digest.finalize().hex(':').upper()}")


def ttp_sign(out: Path) -> None:
    root_cert = ca.pem_to_cert((out / "root.crt.pem").read_text())
    root_key = _load_key(out / "root.key.enc.pem")
    for name in NAMES:
        csr = x509.load_pem_x509_csr((out / f"{name}.csr.pem").read_bytes())
        cert = ca.sign_intermediate(csr, root_cert, root_key)
        (out / f"{name}.crt.pem").write_text(ca.cert_to_pem(cert))
        print(f"Intermedia {name} firmada. SHA-256: {_fp(cert)}")


def m1_load(out: Path) -> None:
    from app.core.config import get_settings
    from app.core.database import build_engine, build_sessionmaker
    from app.crypto.keystore import KeyStore
    from app.services.keys import store_hierarchy

    settings = get_settings()
    root_cert = ca.pem_to_cert((out / "root.crt.pem").read_text())
    inter = {
        name: (
            ca.pem_to_cert((out / f"{name}.crt.pem").read_text()),
            _load_key(out / f"{name}.key.enc.pem"),
        )
        for name in NAMES
    }
    factory = build_sessionmaker(build_engine(settings))
    with factory() as db:
        store_hierarchy(db, KeyStore(settings.kek()), root_cert, inter)
        db.commit()
    print("Raíz e intermedias cargadas en auth.ca_keys (llaves cifradas con la KEK).")


def acta(out: Path) -> None:
    print(f"ACTA DE CEREMONIA · {dt.datetime.now(dt.UTC):%Y-%m-%d %H:%M} UTC")
    print("Participantes: ____________________   Testigo: ____________________")
    for name in ["root", *NAMES]:
        path = out / f"{name}.crt.pem"
        if path.exists():
            cert = ca.pem_to_cert(path.read_text())
            print(f"- {name:9s} {cert.subject.rfc4514_string()}")
            print(f"  SHA-256 {_fp(cert)}")
            nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
            print(f"  Vigencia {nb:%Y-%m-%d} → {na:%Y-%m-%d}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("step", choices=["ttp-root", "m1-csr", "ttp-sign", "m1-load", "acta"])
    ap.add_argument("--out", default="ceremony-out", type=Path)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    {
        "ttp-root": ttp_root,
        "m1-csr": m1_csr,
        "ttp-sign": ttp_sign,
        "m1-load": m1_load,
        "acta": acta,
    }[args.step](args.out)


if __name__ == "__main__":
    main()
