from fastapi import FastAPI
from fastapi.security import HTTPBearer

from app.api import admin, auth, dev_stub, devices, health, pki, wellknown
from app.core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)

app = FastAPI(
    title="Módulo 1 · PKI Interna, Autenticación y Gestión de Identidades",
    description=(
        "Contrato OpenAPI del Módulo 1 (Auth & Crypto Core) para el Sistema de Boletaje Seguro.\n\n"
        "- **Algoritmo JWT:** ES256 (ECDSA P-256)\n"
        "- **Errores:** RFC 7807 (Problem Details)\n"
        "- **Identificadores:** UUIDv4/v7 y tiempos en UTC"
    ),
    version=settings.app_version,
    contact={"name": "Equipo Módulo 1 · Backend APIs (Brandon Trejo)"},
)

app.include_router(auth.router)
app.include_router(wellknown.router)
app.include_router(pki.router)
app.include_router(devices.router)
app.include_router(admin.router)
app.include_router(health.router)

if settings.enable_dev_stub and settings.env != "production":
    app.include_router(dev_stub.router)
