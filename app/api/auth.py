"""Endpoints de autenticación (BT-04 · RF-01 a RF-04)."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.core.errors import too_many, unauthorized
from app.core.security import DB, IP, CurrentUser, KeyStoreDep, LimiterDep, SettingsDep
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenPairResponse,
    UserProfileResponse,
)
from app.schemas.common import problem
from app.services import audit, sessions, users

router = APIRouter(prefix="/auth", tags=["Autenticación"])

INVALID_CREDENTIALS = "Correo o contraseña incorrectos."


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registro de comprador (RF-01)",
    responses={
        400: problem("Contraseña débil o común"),
        409: problem("Correo ya registrado"),
        422: problem("Datos inválidos"),
        429: problem("Límite de registros por IP excedido"),
    },
)
def register(
    payload: RegisterRequest, db: DB, settings: SettingsDep, limiter: LimiterDep, ip: IP
) -> RegisterResponse:
    ok, wait = limiter.allow("register-ip", ip, settings.rate_limit_register_per_ip)
    if not ok:
        raise too_many("Demasiados registros desde esta IP; intenta más tarde.", wait)
    user = users.create_user(
        db, settings, email=payload.email, password=payload.password, nombre=payload.nombre
    )
    audit.record(db, actor=str(user.id), action=audit.Actions.REGISTER, target=user.email, ip=ip)
    db.commit()
    return RegisterResponse.model_validate(user)


@router.post(
    "/login",
    response_model=TokenPairResponse,
    summary="Inicio de sesión: JWT ES256 + refresh token (RF-02)",
    responses={
        401: problem("Credenciales inválidas (mismo mensaje si el usuario no existe)"),
        429: problem("Límite de intentos excedido o cuenta bloqueada temporalmente"),
    },
)
def login(
    payload: LoginRequest,
    db: DB,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    limiter: LimiterDep,
    ip: IP,
) -> TokenPairResponse:
    ok_ip, wait_ip = limiter.allow("login-ip", ip, settings.rate_limit_login_per_ip)
    ok_acc, wait_acc = limiter.allow(
        "login-account", payload.email, settings.rate_limit_login_per_account
    )
    if not (ok_ip and ok_acc):
        raise too_many("Demasiados intentos; espera un momento.", max(wait_ip, wait_acc))

    result = users.authenticate(db, settings, payload.email, payload.password)
    if result.user is None:
        audit.record(
            db,
            actor=payload.email.lower(),
            action=audit.Actions.LOCKED if result.locked_for else audit.Actions.LOGIN_FAIL,
            target=payload.email.lower(),
            ip=ip,
        )
        db.commit()
        if result.locked_for:
            raise too_many(
                "Cuenta bloqueada temporalmente por intentos fallidos.", result.locked_for
            )
        raise unauthorized(INVALID_CREDENTIALS, "invalid-credentials")

    pair = sessions.start_session(db, keystore, settings, result.user)
    audit.record(
        db,
        actor=str(result.user.id),
        action=audit.Actions.LOGIN_OK,
        target=result.user.email,
        ip=ip,
    )
    db.commit()
    return TokenPairResponse(
        access_token=pair.access_token, refresh_token=pair.refresh_token, expires_in=pair.expires_in
    )


@router.post(
    "/refresh",
    response_model=TokenPairResponse,
    summary="Renovación con refresh token rotativo y detección de reúso (RF-03)",
    responses={401: problem("Refresh token inválido, expirado o reutilizado")},
)
def refresh_session(
    payload: RefreshRequest, db: DB, settings: SettingsDep, keystore: KeyStoreDep, ip: IP
) -> TokenPairResponse:
    pair = sessions.rotate(db, keystore, settings, payload.refresh_token, ip)
    return TokenPairResponse(
        access_token=pair.access_token, refresh_token=pair.refresh_token, expires_in=pair.expires_in
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Logout: revoca la familia del refresh token (RF-04)",
    responses={401: problem("No autenticado")},
)
def logout(payload: LogoutRequest, principal: CurrentUser, db: DB, ip: IP) -> Response:
    sessions.logout(db, principal.id, payload.refresh_token, ip)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Perfil y rol del usuario autenticado",
    responses={401: problem("Token JWT inválido o expirado")},
)
def get_me(principal: CurrentUser) -> UserProfileResponse:
    return UserProfileResponse.model_validate(principal.user)
