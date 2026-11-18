"""Exporta el contrato OpenAPI de M1 (BT-01) a openapi.yaml sin los endpoints de dev-stub."""

import os

os.environ["ENABLE_DEV_STUB"] = "false"

import yaml  # noqa: E402
from app.main import app  # noqa: E402

schema = app.openapi()
output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "openapi.yaml")

with open(output_path, "w", encoding="utf-8") as f:
    yaml.safe_dump(schema, f, sort_keys=False, allow_unicode=True)

print(f"OpenAPI exportado correctamente en: {output_path}")
