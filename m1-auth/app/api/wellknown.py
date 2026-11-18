from fastapi import APIRouter, Response

from app.core.stub_keys import STUB_PUBLIC_JWK
from app.schemas.pki import JWKItem, JWKSResponse

router = APIRouter(tags=["Públicos"])


@router.get(
    "/.well-known/jwks.json",
    response_model=JWKSResponse,
    summary="Publicación de llaves públicas de firma JWT (RF-08)",
)
async def get_jwks(response: Response) -> JWKSResponse:
    response.headers["Cache-Control"] = "public, max-age=600"
    return JWKSResponse(keys=[JWKItem(**STUB_PUBLIC_JWK)])
