# Módulo 1 · PKI Interna, Autenticación y Gestión de Identidades (`m1-auth`)

Implementación inicial correspondiente a las actividades **BT-01**, **BT-02** y **BT-03** del Roadmap del Módulo 1.

## Entregables incluidos

1. **BT-01 (`openapi.yaml` + esqueleto FastAPI):**
   - Los 15 endpoints del contrato con modelos Pydantic v2 y formato de errores **RFC 7807**.
   - Script `scripts/export_openapi.py` para regenerar `openapi.yaml` sin endpoints de desarrollo (`ENABLE_DEV_STUB=false`).
2. **BT-02 (Stub con JWKS fijo y tokens de prueba - Hito H1):**
   - `GET /.well-known/jwks.json` exponiendo la llave pública de prueba ECDSA P-256 (`kid: m1-stub-key-2026-11`).
   - `POST /dev/token` para emitir JWTs `ES256` válidos para `buyer`, `admin` o `staff` con todos los claims de RNF-03 (`sub`, `role`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `idh`).
   - `Dockerfile` y `docker-compose.yml` listos para levantar el stub.
3. **BT-03 (Middleware de validación JWT):**
   - **Python / FastAPI:** `middleware/python/jwt_auth.py` con `PyJWT`, caché del JWKS de 10 minutos, validación estricta de `ES256`, `iss`, `aud`, `exp` y `nbf`.
   - **TypeScript / Node:** `middleware/typescript/jwtAuth.ts` con `jose` (`createRemoteJWKSet`), caché de 10 minutos y validación estricta de `ES256`.

## Arranque rápido con Docker

```bash
docker compose up --build
```

Probar el stub:
```bash
# 1. Consultar JWKS
curl http://localhost:8000/.well-known/jwks.json

# 2. Emitir token de prueba para role=buyer (o admin / staff)
curl -X POST http://localhost:8000/dev/token \
  -H "Content-Type: application/json" \
  -d '{"role": "buyer"}'
```

## Ejecutar pruebas localmente

```bash
pip install -r requirements.txt
pytest -v
```
