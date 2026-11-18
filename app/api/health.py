from datetime import UTC, datetime

from fastapi import APIRouter, Request
from sqlalchemy import text

from app.core.security import DB, SettingsDep
from app.schemas.common import HealthResponse

router = APIRouter(tags=["Salud"])


@router.get("/health", response_model=HealthResponse, summary="Estado del servicio")
def health_check(request: Request, db: DB, settings: SettingsDep) -> HealthResponse:
    checks: dict[str, str] = {}
    try:
        db.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception:  # noqa: BLE001 - el healthcheck nunca debe lanzar
        checks["db"] = "error"
    redis_client = request.app.state.redis
    if redis_client is None:
        checks["redis"] = "disabled"
    else:
        try:
            redis_client.ping()
            checks["redis"] = "ok"
        except Exception:  # noqa: BLE001
            checks["redis"] = "error"
    return HealthResponse(
        status="ok" if checks["db"] == "ok" else "degraded",
        service="m1-auth",
        version=settings.app_version,
        timestamp=datetime.now(UTC),
        checks=checks,
    )
