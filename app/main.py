"""Punto de arranque del servicio M1 (Auth & Crypto Core)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import admin, auth, dev_stub, devices, health, pki, wellknown
from app.core.config import Settings, get_settings
from app.core.database import build_engine, build_sessionmaker
from app.core.errors import install_error_handlers
from app.core.logging import CorrelationIdMiddleware, configure_logging
from app.core.ratelimit import build_rate_limiter
from app.crypto.keystore import KeyStore
from app.events.publisher import EventPublisher
from app.services import keys, users

log = logging.getLogger("m1-auth")

ADMIN_UI_DIR = Path(__file__).resolve().parent.parent / "admin-ui"

DESCRIPTION = """Módulo 1 del Sistema de Boletaje Seguro para Auditorio.

- **JWT:** ES256 (ECDSA P-256), claims `sub, role, iss, aud, iat, nbf, exp, jti, idh`, header `kid`.
- **JWKS:** `/.well-known/jwks.json` (llave activa + anterior durante la rotación).
- **PKI:** intermedias de M1 (servicios, dispositivos, eventos) firmadas por la raíz de la TTP.
- **Errores:** RFC 7807 (`application/problem+json`) con `correlation_id`.
"""


def _redis_client(settings: Settings) -> redis.Redis | None:
    if settings.rate_limit_backend != "redis":
        return None
    try:
        client = redis.Redis.from_url(
            settings.redis_url, socket_timeout=1, socket_connect_timeout=1
        )
        client.ping()
        return client
    except redis.RedisError:
        log.warning(
            "Redis no disponible en %s; se usará memoria", settings.redis_url.split("@")[-1]
        )
        return None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(settings)
        app.state.engine = engine
        app.state.sessionmaker = build_sessionmaker(engine)
        app.state.keystore = KeyStore(settings.kek())
        settings.pepper()  # falla al arrancar si no está configurado
        app.state.redis = _redis_client(settings)
        app.state.limiter = build_rate_limiter(settings.rate_limit_backend, app.state.redis)
        app.state.publisher = EventPublisher(
            app.state.redis, settings.events_stream, settings.events_hmac_key()
        )
        with app.state.sessionmaker() as db:
            keys.ensure_signing_key(db, app.state.keystore)
            keys.ensure_dev_pki(db, app.state.keystore, settings)
            users.ensure_bootstrap_admin(db, settings)
        log.info("m1-auth listo (env=%s)", settings.env)
        yield
        engine.dispose()

    app = FastAPI(
        title="Módulo 1 · PKI Interna, Autenticación y Gestión de Identidades",
        description=DESCRIPTION,
        version=settings.app_version,
        contact={"name": "Equipo Módulo 1 (Auth & Crypto Core)"},
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.add_middleware(CorrelationIdMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
        )
    install_error_handlers(app)

    for router in (
        auth.router,
        wellknown.router,
        pki.router,
        devices.router,
        admin.router,
        health.router,
    ):
        app.include_router(router)
    if settings.dev_stub_enabled:
        app.include_router(dev_stub.router)

    if ADMIN_UI_DIR.is_dir():
        app.mount("/ui", StaticFiles(directory=ADMIN_UI_DIR, html=True), name="admin-ui")

        @app.get("/", include_in_schema=False)
        def _root() -> RedirectResponse:
            return RedirectResponse("/ui/")

    return app


app = create_app()  # uvicorn app.main:app
