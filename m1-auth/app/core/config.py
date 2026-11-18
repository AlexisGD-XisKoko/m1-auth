import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_name: str = "M1 Auth & Crypto Core"
    app_version: str = "0.1.0-stub"
    env: str = os.getenv("ENV", "development")
    enable_dev_stub: bool = os.getenv("ENABLE_DEV_STUB", "true").lower() == "true"
    jwt_issuer: str = os.getenv("JWT_ISSUER", "https://auth.boletera.local")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "boletera-api")
    access_token_ttl_seconds: int = int(
        os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900")
    )  # 15 min (RNF-02)
    refresh_token_ttl_days: int = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "7"))  # 7 días (RNF-02)


settings = Settings()
