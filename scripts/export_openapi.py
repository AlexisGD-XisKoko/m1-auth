"""Exporta el contrato OpenAPI de M1 (BT-01) a openapi.yaml sin los endpoints de dev-stub.

Uso: python scripts/export_openapi.py   (no necesita BD ni secretos)
"""

import os
import sys
from pathlib import Path

os.environ["ENABLE_DEV_STUB"] = "false"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

schema = create_app(Settings(enable_dev_stub=False)).openapi()
schema["servers"] = [
    {"url": "http://localhost:8000", "description": "Desarrollo local"},
    {"url": "https://api.boletera.local/auth", "description": "Integración detrás de Traefik"},
]
output = Path(__file__).resolve().parents[1] / "openapi.yaml"
output.write_text(yaml.safe_dump(schema, sort_keys=False, allow_unicode=True), encoding="utf-8")
print(f"OpenAPI exportado en {output}")
