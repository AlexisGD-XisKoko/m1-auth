"""Configuración leída de variables de entorno (nunca secretos en el código).

Todas las variables tienen un valor por defecto seguro para desarrollo, excepto los
secretos (KEK_BASE64, PEPPER_BASE64), que el servicio exige al arrancar.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- General -------------------------------------------------------------
    app_name: str = "M1 Auth & Crypto Core"
    app_version: str = "1.0.0"
    env: Literal["development", "test", "integration", "production"] = "development"
    log_level: str = "INFO"

    # --- Base de datos (rol m1_app; las migraciones usan m1_owner) -------------
    database_url: str = "postgresql+psycopg://m1_app:change-me@localhost:5432/boletera"
    migrations_database_url: str = ""
    db_pool_size: int = 3  # sección 7.1: pool de 2 a 3 conexiones por servicio

    # --- Redis (rate limiting y eventos) --------------------------------------
    redis_url: str = "redis://localhost:6379/0"
    rate_limit_backend: Literal["redis", "memory"] = "redis"
    events_stream: str = "m1.events"
    events_hmac_key_base64: str = ""

    # --- JWT (RNF-02, RNF-03) ---------------------------------------------------
    jwt_issuer: str = "https://auth.boletera.local"
    jwt_audience: str = "boletera-api"
    access_token_ttl_seconds: int = 900  # 15 min
    refresh_token_ttl_days: int = 7
    jwt_retired_key_grace_hours: int = 24  # la llave anterior sigue en el JWKS

    # --- Secretos (RNF-07) ------------------------------------------------------
    kek_base64: str = ""  # 32 bytes en base64: cifra llaves privadas (AES-256-GCM)
    pepper_base64: str = ""  # 32 bytes en base64: hash de identidad (RF-09)

    # --- Seguridad de login (RNF-05, RNF-08) ------------------------------------
    password_min_length: int = 8
    lockout_threshold: int = 5
    lockout_base_seconds: int = 30
    lockout_max_seconds: int = 900
    rate_limit_login_per_ip: int = 20  # por minuto
    rate_limit_login_per_account: int = 10  # por minuto
    rate_limit_register_per_ip: int = 10  # por minuto

    # --- PKI ----------------------------------------------------------------------
    pki_dev_bootstrap: bool = True  # genera raíz simulada + intermedias si no existen
    enrollment_code_ttl_minutes: int = 15
    crl_next_update_hours: int = 24
    event_cert_default_days: int = 120
    # Política de perfiles para solicitantes autenticados con certificado de servicio:
    # "perfil=cn1,cn2" separados por ';'. '*' = cualquier servicio con certificado válido.
    pki_profile_policy: str = "event-signing=m4-tickets;service=*"
    trust_proxy_client_cert: bool = False  # solo si Traefik reenvía el certificado (mTLS)

    # --- TTP / sellado de tiempo RFC 3161 (deseable) -----------------------------
    tsa_url: str = ""  # p. ej. http://trust-authority:8000/trust/timestamp

    # --- Desarrollo ----------------------------------------------------------------
    enable_dev_stub: bool = True
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    cors_origins: list[str] = Field(default_factory=list)

    # ---------------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def dev_stub_enabled(self) -> bool:
        return self.enable_dev_stub and not self.is_production

    def kek(self) -> bytes:
        return _decode_secret("KEK_BASE64", self.kek_base64)

    def pepper(self) -> bytes:
        return _decode_secret("PEPPER_BASE64", self.pepper_base64)

    def events_hmac_key(self) -> bytes | None:
        if not self.events_hmac_key_base64:
            return None
        return base64.b64decode(self.events_hmac_key_base64)

    def profile_policy(self) -> dict[str, set[str]]:
        policy: dict[str, set[str]] = {}
        for chunk in self.pki_profile_policy.split(";"):
            if "=" not in chunk:
                continue
            profile, names = chunk.split("=", 1)
            policy[profile.strip()] = {n.strip() for n in names.split(",") if n.strip()}
        return policy


class MissingSecretError(RuntimeError):
    pass


def _decode_secret(name: str, value: str) -> bytes:
    if not value:
        raise MissingSecretError(
            f"{name} no está configurada. Genera los secretos con "
            "`python scripts/gen_secrets.py` y cópialos a tu .env"
        )
    raw = base64.b64decode(value)
    if len(raw) != 32:
        raise MissingSecretError(f"{name} debe decodificar a 32 bytes (tiene {len(raw)}).")
    return raw


@lru_cache
def get_settings() -> Settings:
    return Settings()
