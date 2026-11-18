"""Punto de arranque del servicio M1 (Auth + PKI)."""

from fastapi import FastAPI

from app.core.config import settings

app = FastAPI(
    title="M1 Auth & PKI",
    version=settings.app_version,
    description="Identidades, tokens JWT ES256 y Autoridad Certificadora intermedia.",
)


@app.get("/health", tags=["infra"])
def health() -> dict[str, str]:
    """Usado por el healthcheck de Docker y por el docker-compose de plataforma."""
    return {"status": "ok", "service": "m1-auth", "version": settings.app_version}
