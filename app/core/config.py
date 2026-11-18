"""Configuración leída de variables de entorno (nunca secretos en el código)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_version: str = "0.1.0"
    database_url: str = "postgresql+psycopg://m1_app:change-me@localhost:5432/boletera"
    redis_url: str = "redis://localhost:6379/0"
    jwt_issuer: str = "https://auth.boletera.local"
    jwt_audience: str = "boletera"
    kek_base64: str = ""


settings = Settings()
