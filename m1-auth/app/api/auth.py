from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, status

from app.core.stub_keys import compute_stub_idh, sign_stub_jwt
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenPairResponse,
    UserProfileResponse,
)
from app.schemas.common import ProblemDetails, RoleEnum, UserStatusEnum

router = APIRouter(prefix="/auth", tags=["Autenticación"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registro de comprador (RF-01)",
    responses={
        400: {"model": ProblemDetails, "description": "Datos inválidos o contraseña común"},
        409: {"model": ProblemDetails, "description": "Correo ya registrado"},
    },
)
async def register(payload: RegisterRequest) -> RegisterResponse:
    user_id = uuid4()
    return RegisterResponse(
        id=user_id,
        email=payload.email,
        role=RoleEnum.buyer,
        status=UserStatusEnum.ACTIVE,
        idh=compute_stub_idh(str(user_id)),
        created_at=datetime.now(UTC),
    )


@router.post(
    "/login",
    response_model=TokenPairResponse,
    summary="Inicio de sesión con emisión de JWT ES256 y refresh token (RF-02)",
    responses={
        401: {"model": ProblemDetails, "description": "Credenciales inválidas"},
        429: {"model": ProblemDetails, "description": "Límite de intentos excedido"},
    },
)
async def login(payload: LoginRequest) -> TokenPairResponse:
    # Stub de respuesta para contrato; en S2 se conecta a Argon2id (JO-03) y auth.users (OG-04)
    token, _ = sign_stub_jwt(role="buyer")
    return TokenPairResponse(
        access_token=token,
        refresh_token=f"stub-rt-{uuid4()}",
        token_type="Bearer",  # noqa: S106
        expires_in=900,
    )


@router.post(
    "/refresh",
    response_model=TokenPairResponse,
    summary="Renovación con refresh token rotativo y detección de reúso (RF-03)",
    responses={
        401: {
            "model": ProblemDetails,
            "description": "Refresh token inválido, expirado o reutilizado",
        }
    },
)
async def refresh_session(payload: RefreshRequest) -> TokenPairResponse:
    token, _ = sign_stub_jwt(role="buyer")
    return TokenPairResponse(
        access_token=token,
        refresh_token=f"stub-rt-{uuid4()}",
        token_type="Bearer",  # noqa: S106
        expires_in=900,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout y revocación de familia de sesiones (RF-04)",
    responses={401: {"model": ProblemDetails, "description": "No autenticado"}},
)
async def logout(payload: LogoutRequest) -> None:
    return None


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Perfil y rol del usuario autenticado",
    responses={401: {"model": ProblemDetails, "description": "Token JWT inválido o expirado"}},
)
async def get_me() -> UserProfileResponse:
    uid = uuid4()
    return UserProfileResponse(
        id=uid,
        email="stub-user@boletera.local",
        role=RoleEnum.buyer,
        status=UserStatusEnum.ACTIVE,
        idh=compute_stub_idh(str(uid)),
        created_at=datetime.now(UTC),
    )
