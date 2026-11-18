"""JWKS público (BT-05 · RF-08 · RNF-04)."""

from fastapi import APIRouter, Response

from app.core.security import DB, SettingsDep
from app.schemas.pki import JWKItem, JWKSResponse
from app.services.keys import published_keys

router = APIRouter(tags=["Públicos"])


@router.get(
    "/.well-known/jwks.json",
    response_model=JWKSResponse,
    summary="Llaves públicas de firma JWT por kid (RF-08); activa + anterior en rotación",
)
def get_jwks(response: Response, db: DB, settings: SettingsDep) -> JWKSResponse:
    response.headers["Cache-Control"] = "public, max-age=600"
    return JWKSResponse(keys=[JWKItem(**row.public_jwk) for row in published_keys(db, settings)])
