from datetime import UTC, datetime

from fastapi import APIRouter

from app.core.config import settings
from app.schemas.common import HealthResponse

router = APIRouter(tags=["Salud"])


@router.get("/health", response_model=HealthResponse, summary="Estado del servicio")
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="m1-auth",
        version=settings.app_version,
        timestamp=datetime.now(UTC),
    )
