# m1-auth · Módulo 1: Identidades y PKI

Servicio de autenticación (registro, login, JWT ES256, refresh tokens, roles) y Autoridad Certificadora intermedia del sistema de boletera. La raíz de la CA vive en la TTP (`trust/`).

## Stack
Python 3.12 · FastAPI · PostgreSQL (esquema `auth` de la BD general) · Redis · SQLAlchemy + Alembic · cryptography · PyJWT · argon2-cffi

## Estructura
```
app/
  main.py      arranque de FastAPI y routers
  api/         auth, pki, devices, admin, wellknown
  core/        configuración y dependencias de seguridad
  crypto/      contraseñas, tokens, CA, keystore, cliente TSA (solo Johan)
  models/      modelos SQLAlchemy (schema='auth')
  schemas/     modelos Pydantic (contrato)
  services/    lógica de negocio
  events/      publicación en Redis Streams
migrations/    Alembic (solo esquema auth)
scripts/ceremony/  CSR de las intermedias para la ceremonia con la TTP
tests/         unit/, integration/, security/, db_permissions/
```

## Arrancar en local
```bash
cp .env.example .env          # rellena los valores
docker compose up --build
curl http://localhost:8000/health
```

Sin Docker:
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest
```

## Forma de trabajo
- Una rama por tarjeta: `feature/<ID>-<descripcion>` (p. ej. `feature/OG-04-registro`).
- Todo entra por Pull Request a `main`, con CI en verde y al menos una revisión de alguien que no sea el autor.
- Nada de criptografía entra sin revisión de Johan.
- Nunca subir `.env`, llaves ni contraseñas.

## Equipo
| Integrante | Rol |
|---|---|
| Diego Flores Madrigal | Tech Lead & Arquitecto |
| Johan Olguin Hernández | Cripto & Security |
| Osvaldo Gil Valentín | Backend A · Lógica y persistencia |
| Brandon Trejo Hernández | Backend B · APIs y comunicaciones |
| Patricia E. Martinez Ortiz | Frontend / UI |
| Alexis Guzmán Dolores | QA, DevOps & Integración |
