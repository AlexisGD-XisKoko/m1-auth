# m1-auth · Módulo 1: PKI interna, autenticación y gestión de identidades

**Sistema de Boletaje Seguro para Auditorio · Auth & Crypto Core**

Servicio que registra y autentica usuarios (Argon2id), emite tokens de sesión JWT firmados con
ECDSA P-256 (ES256), publica el JWKS y opera las tres CA intermedias de la PKI del sistema
(servicios, dispositivos y eventos), certificadas por la raíz de la Tercera Entidad de Confianza (TTP).
Los otros cinco módulos dependen de él para saber **quién es cada usuario** y **qué llaves son legítimas**.

> Versión 1.0.0 · rama `feature/m1-completo` · revisión del módulo: **martes 8 de diciembre de 2026**.
> Documentos de referencia: *Planeación del Módulo 1 v1.1* y *Roadmap y plan de trabajo del Módulo 1*.

---

## Contenido

1. [Qué incluye](#1-qué-incluye)
2. [Qué desarrolló cada integrante](#2-qué-desarrolló-cada-integrante)
3. [Cómo ejecutarlo](#3-cómo-ejecutarlo)
4. [Cómo probarlo](#4-cómo-probarlo)
5. [Contrato API](#5-contrato-api)
6. [Configuración](#6-configuración)
7. [Ceremonia de llaves con la TTP](#7-ceremonia-de-llaves-con-la-ttp)
8. [Integración con los demás módulos](#8-integración-con-los-demás-módulos)
9. [Estructura del repositorio](#9-estructura-del-repositorio)
10. [Qué pasó con el PR #1 (contrato API)](#10-qué-pasó-con-el-pr-1-contrato-api)
11. [Pendientes antes del 8 de diciembre](#11-pendientes-antes-del-8-de-diciembre)
12. [Forma de trabajo](#12-forma-de-trabajo)

---

## 1. Qué incluye

### Requerimientos cubiertos

| Requerimiento | Qué hace | Dónde |
|---|---|---|
| RF-01 Registro | Email, contraseña y nombre, con validación y política NIST | `POST /auth/register` · `services/users.py` |
| RF-02 Login | Access token JWT ES256 (15 min) + refresh token opaco (7 días) | `POST /auth/login` · `services/sessions.py` |
| RF-03 Refresh rotativo | Cada uso emite uno nuevo; si llega uno ya usado se revoca **toda la familia** | `POST /auth/refresh` |
| RF-04 Logout | Revoca la familia del refresh token | `POST /auth/logout` |
| RF-05 Roles | `buyer`, `admin`, `staff`; el rol se lee de la BD en cada petición | `core/security.py` |
| RF-06 Gestión de usuarios | Alta, búsqueda, cambio de rol, bloqueo/desbloqueo y desactivación (solo admin) | `/admin/users` |
| RF-07 / RNF-01 Argon2id | argon2-cffi por defecto (m = 64 MiB, t = 3, p = 4), formato PHC, rehash automático | `crypto/passwords.py` |
| RF-08 JWKS | `/.well-known/jwks.json` por `kid`, con `Cache-Control` de 10 min | `api/wellknown.py` |
| RF-09 Hash de identidad | `idh = HMAC-SHA256(pepper, user_id)`, claim del JWT y columna de `shared.v_usuarios` | `crypto/tokens.py` |
| RF-10, RF-11 Jerarquía | Raíz de la TTP + intermedias de Servicios, Dispositivos y Eventos | `crypto/ca.py` |
| RF-12, RF-13 Firma de CSR | Por perfil (`service`, `device`, `event-signing`) con BasicConstraints, KeyUsage, EKU, SAN, SKI y AKI | `POST /pki/csr` |
| RF-14 Revocación y CRL | CRL v2 firmada por cada intermedia; evento `certificate.revoked` en Redis Streams | `POST /pki/revoke`, `GET /pki/crl` |
| RF-15 Cadena | Intermedias + raíz de la TTP en PEM para validación offline | `GET /pki/ca-chain` |
| RF-16 Enrolamiento | Código de un solo uso (32 bytes, 15 min, solo se guarda su hash) + CSR del escáner | `/devices/enrollment-codes`, `/devices/enroll` |
| RF-17 Desactivar dispositivo *(deseable)* | Revoca su certificado y lo publica en la CRL | `POST /devices/{id}/revoke` |
| RF-18 Bitácora | Solo inserción (`m1_app` sin UPDATE/DELETE), con actor, IP y correlation ID | `GET /admin/audit` |
| RNF-02/03 JWT | Solo ES256; `iss`, `aud`, `exp`, `nbf`, `kid`; claims `sub, role, iss, aud, iat, nbf, exp, jti, idh` | `crypto/tokens.py` |
| RNF-04 Rotación *(deseable)* | Nueva llave por `kid`; la anterior sigue publicada 24 h | `POST /admin/signing-keys/rotate` |
| RNF-05 Fuerza bruta | Rate limiting por IP y por cuenta (Redis) + bloqueo progresivo (30 s → 15 min) | `core/ratelimit.py` |
| RNF-06 Canales laterales | Verificación ficticia de Argon2id si el usuario no existe; mismo mensaje y tipo de error | `services/users.py` |
| RNF-07 Custodia de llaves | Llaves privadas cifradas con AES-256-GCM bajo la KEK (AAD = id de la llave) | `crypto/keystore.py` |
| RNF-08 Política NIST | Mínimo 8 caracteres, sin reglas de composición, lista de contraseñas comunes | `app/data/common_passwords.txt` |
| RNF-12 Trazabilidad | Logs JSON con `correlation_id`; cabecera `X-Correlation-ID` | `core/logging.py` |
| RNF-13 Aislamiento en BD | Esquema `auth` solo para `m1_owner`/`m1_app`; vista `shared.v_usuarios` (id, role, status, idh) | `db/sql/00_init.sql`, migración 0001 |
| Errores RFC 7807 | `application/problem+json` con `type`, `title`, `status`, `detail`, `instance`, `correlation_id` | `core/errors.py` |
| Sellos RFC 3161 *(deseable)* | Cliente TSA para la CRL y eventos críticos; se activa con `TSA_URL` | `crypto/tsa_client.py` |
| mTLS M1 ↔ M4 *(deseable, parcial)* | `/pki/csr` acepta el certificado de servicio que reenvía Traefik (`X-Forwarded-Tls-Client-Cert`) | `api/pki.py` |

### Además

- **Panel de administración** en `/ui` (login, usuarios, códigos de enrolamiento, certificados, dispositivos, bitácora y rotación de llave). El token vive solo en memoria.
- **Middleware JWT** para los demás equipos en Python/FastAPI y TypeScript/Node (`middleware/`).
- **Vectores de prueba compartidos** para M4, M5 y M6 (`contracts/test-vectors/`).
- **Scripts de ceremonia** con acta de huellas SHA-256 (`scripts/ceremony/ceremony.py`).
- **Datos semilla** idempotentes para la demo (`scripts/seed_demo.py`).
- **Recorrido de demo** automatizado con 19 verificaciones (`scripts/demo_flow.py`).
- **79 pruebas** (21 unitarias, 19 de integración, 29 de seguridad y 10 de permisos de BD), 91 % de cobertura.
- **ADRs** propuestos 0003, 0009, 0010 y 0011 en `docs/adr/` (se suben al repositorio de plataforma).

---

## 2. Qué desarrolló cada integrante

La implementación sigue las tarjetas del roadmap. La tabla indica qué parte del código corresponde a
cada rol, para que cada quien la **revise, explique en la demo y complete** lo pendiente.

### Diego Flores Madrigal · Tech Lead & Arquitecto de Software
- Arquitectura del servicio (Auth + PKI en un solo microservicio) y su estructura (sección 5.9).
- Decisiones registradas como ADR: `docs/adr/0003`, `0009`, `0010` y `0011` (ajustes respecto a la planeación).
- Integración del PR #1 de Brandon a la raíz del repositorio y resolución de sus problemas (sección 10).
- Guion de la demo automatizado: `scripts/demo_flow.py` (DF-11) y este README (DF-10).
- **Tarjetas:** DF-02, DF-03, DF-04, DF-05, DF-07, DF-10, DF-11.

### Johan Olguin Hernández · Cripto & Security Engineer
- `app/crypto/passwords.py` — Argon2id, verificación ficticia y rehash (**JO-03**).
- `app/crypto/tokens.py` — JWT ES256, JWK público, `idh`, tokens opacos, comparación en tiempo constante (**JO-04**).
- `app/crypto/keystore.py` — Key Manager con AES-256-GCM bajo la KEK (**JO-05**).
- `app/crypto/ca.py` — perfiles de certificado con sus extensiones (**JO-02**), firma de CSR y CRL v2 (**JO-07**).
- `scripts/ceremony/ceremony.py` — CSR de las intermedias, firma por la raíz y acta (**JO-06**).
- `app/crypto/tsa_client.py` — solicitud RFC 3161 en DER (**JO-08**, falta verificar la respuesta).
- `scripts/generate_test_vectors.py` + `contracts/test-vectors/` (**JO-01**).
- Revisión de seguridad: `tests/security/test_negative_cases.py` cubre la tabla STRIDE (**JO-09**).

### Osvaldo Gil Valentín · Backend Developer A (lógica y persistencia)
- `db/sql/00_init.sql` + `db/00_init.sh` — esquemas, roles, permisos y `CONNECTION LIMIT` de la BD general (**OG-01**).
- `app/models/__init__.py` — 8 tablas del esquema `auth` y migración `migrations/versions/0001_*` con la vista `shared.v_usuarios` y la bitácora de solo inserción (**OG-03**, **OG-07**).
- `app/services/users.py` — registro, login con bloqueo progresivo, política NIST, gestión de usuarios (**OG-04**, **OG-06**).
- `app/services/sessions.py` — refresh tokens rotativos con detección de reúso y logout (**OG-05**).
- `app/services/audit.py` — Audit Logger (**OG-06**).
- `app/services/devices.py` — códigos de un solo uso con UPDATE condicional (**OG-08**).
- `app/services/pki.py` (persistencia y revocación) y `scripts/seed_demo.py` (**OG-07**, **OG-09**).

### Brandon Trejo Hernández · Backend Developer B (APIs y comunicaciones)
- Esqueleto FastAPI, modelos Pydantic y contrato `openapi.yaml` de su PR #1, ahora conectados a la lógica real (**BT-01**).
- `/dev/token` del stub, que ahora firma con la llave real (**BT-02**).
- `middleware/python/jwt_auth.py` y `middleware/typescript/jwtAuth.ts` (**BT-03**).
- `app/api/*.py` — endpoints de auth, PKI, dispositivos y admin con errores RFC 7807 (**BT-04**, **BT-07**, **BT-08**).
- `app/services/keys.py` — JWKS con rotación por `kid` (**BT-05**).
- `app/core/ratelimit.py` — rate limiting con Redis `INCR`/`EXPIRE` (**BT-06**).
- `app/events/publisher.py` — `certificate.revoked` en Redis Streams firmado con HMAC (**BT-08**).
- Aceptación del certificado de cliente reenviado por el gateway en `/pki/csr` (**BT-09**, parcial).

### Patricia E. Martinez Ortiz · Frontend / UI Developer
- `admin-ui/` — panel de administración servido en `/ui` (**PM-02** a **PM-05**):
  login (token en memoria), tabla de usuarios con búsqueda y cambio de rol, alta de usuarios, generación de
  códigos de enrolamiento que se muestran una sola vez, inventario de certificados con revocación y motivo,
  dispositivos, bitácora con filtros y botón de rotación de llave. Política CSP sin scripts inline.

### Alexis Guzmán Dolores · QA, DevOps & Integration Engineer
- `Dockerfile` (usuario no root, healthcheck) y `docker-compose.yml` con `db`, `redis`, `migrate` y `app` (**AG-01**).
- `.github/workflows/ci.yml` — Ruff, mypy estricto, `00_init.sql`, migraciones, pytest en PostgreSQL y SQLite,
  verificación de que `openapi.yaml` está al día, Bandit, pip-audit y Gitleaks con `.gitleaks.toml` (**AG-02**, **AG-06**).
- `tests/db_permissions/` — otro módulo no puede leer `auth.*`; `m1_app` no altera la bitácora ni hace DDL (**AG-03**).
- `tests/security/` — casos negativos de JWT, refresh, 429, bloqueo, enumeración, CSR y enrolamiento (**AG-04**, **AG-07**).
- `tests/security/test_middleware_jwt.py` + `tests/unit/test_vectors.py` — interoperabilidad con los vectores (**AG-08**, parte M1).
- `tests/conftest.py` — misma suite contra SQLite (sin infraestructura) o PostgreSQL real.

---

## 3. Cómo ejecutarlo

### Requisitos
- **Opción A (recomendada):** Docker Desktop con Docker Compose v2 y Python 3.12+ (solo para generar secretos).
- **Opción B:** Python 3.12+, PostgreSQL 16/17 y Redis 7 instalados localmente.
- En Windows, los comandos funcionan en **Git Bash**. En PowerShell activa el entorno con `.venv\Scripts\Activate.ps1`.

### Opción A · Docker Compose (todo el entorno con un comando)

```bash
git clone https://github.com/AlexisGD-XisKoko/m1-auth.git
cd m1-auth
git checkout feature/m1-completo

cp .env.example .env
python scripts/gen_secrets.py >> .env      # KEK, pepper, contraseñas de roles y del admin inicial

docker compose up --build
```

Esto levanta PostgreSQL 17 (corre `00_init.sql` la primera vez), Redis, aplica la migración como `m1_owner`
y arranca el servicio como `m1_app` en <http://localhost:8000>. En el primer arranque se crean la llave de
firma JWT, una **PKI de desarrollo** (raíz simulada + 3 intermedias) y el administrador inicial.

| URL | Qué es |
|---|---|
| <http://localhost:8000/ui/> | Panel de administración |
| <http://localhost:8000/docs> | Swagger UI (probar cada endpoint) |
| <http://localhost:8000/health> | Estado del servicio, BD y Redis |
| <http://localhost:8000/.well-known/jwks.json> | JWKS público |

**Credenciales del admin inicial:** `admin@example.com` y la contraseña `BOOTSTRAP_ADMIN_PASSWORD` de tu `.env`.

Para cargar datos de demo (un usuario por rol, un certificado de evento y un escáner):

```bash
docker compose exec app python scripts/seed_demo.py
```

Para empezar de cero (borra la BD local): `docker compose down -v`.

### Opción B · Sin Docker

```bash
python -m venv .venv && source .venv/bin/activate     # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
cp .env.example .env && python scripts/gen_secrets.py >> .env
```

Edita en `.env` las contraseñas `CAMBIAR` de `DATABASE_URL` y `MIGRATIONS_DATABASE_URL` con
`M1_APP_PASSWORD` y `M1_OWNER_PASSWORD`. Luego, como superusuario de PostgreSQL:

```bash
createdb boletera
psql -d boletera -v m1_owner_pw="<M1_OWNER_PASSWORD>" -v m1_app_pw="<M1_APP_PASSWORD>" \
     -v other_pw="<OTHER_MODULES_PASSWORD>" -f db/sql/00_init.sql
alembic upgrade head                      # usa MIGRATIONS_DATABASE_URL (m1_owner)
uvicorn app.main:app --reload             # usa DATABASE_URL (m1_app)
```

Si Redis no está disponible el servicio arranca igual y usa un contador en memoria (con una advertencia).
Para no depender de Redis pon `RATE_LIMIT_BACKEND=memory`.

### Contra la BD de integración en Neon
Usa en `DATABASE_URL` la cadena de `m1_app` que entregue el administrador (OG-02) con `?sslmode=require`
(o `verify-full` con el certificado de Neon). Las migraciones en Neon solo las aplica el CI desde `main` (AG-06).

---

## 4. Cómo probarlo

### 4.1 Pruebas automáticas

```bash
pytest                       # 79 pruebas con SQLite temporal; no necesita Docker
pytest --cov=app             # con cobertura (91 %)
ruff check . && ruff format --check . && mypy app
```

Contra PostgreSQL real, incluidas las pruebas de permisos (lo mismo que corre el CI):

```bash
export TEST_DATABASE_URL=postgresql+psycopg://m1_app:<pw>@localhost:5432/boletera
export TEST_OTHER_MODULE_URL=postgresql+psycopg://m2_app:<pw>@localhost:5432/boletera
# Si la BD ya tiene llaves creadas por el servicio, usa la MISMA KEK y pepper que tu .env:
export TEST_KEK_BASE64=<KEK_BASE64> TEST_PEPPER_BASE64=<PEPPER_BASE64>
pytest
```

| Carpeta | Qué valida |
|---|---|
| `tests/unit` | Argon2id, AES-GCM con AAD, JWT ES256, perfiles X.509, CRL, solicitud RFC 3161, vectores |
| `tests/integration` | Registro → login → `/me` → refresh → logout; admin; rotación de llave; CSR de M4; enrolamiento; revocación; mTLS |
| `tests/security` | `alg: none`, HS256 con la llave pública, expirado, `aud`/`iss`/`kid`/`nbf` inválidos, claim faltante, payload alterado, refresh reutilizado, 429, bloqueo progresivo, enumeración, CSR inválido/RSA/P-384/perfil no autorizado, CRL, códigos usados o expirados, middleware de otros equipos |
| `tests/db_permissions` | `m2_app` recibe *permission denied* en `auth.users`, `refresh_tokens`, `signing_keys`; solo ve `shared.v_usuarios`; `m1_app` no puede UPDATE/DELETE/TRUNCATE en `audit_log` ni crear tablas |

### 4.2 Recorrido de la demo (servicio en marcha)

```bash
python scripts/demo_flow.py --admin-email admin@example.com --admin-password "<BOOTSTRAP_ADMIN_PASSWORD>"
```

Ejecuta 19 pasos y marca cada uno OK/FALLO: registro, contraseña común rechazada, login, JWT con `kid` e
`idh`, refresh rotativo, **refresh reutilizado que revoca la familia**, **token `alg: none` rechazado**, CSR
`event-signing` de M4, enrolamiento de un escáner, código que no sirve dos veces, revocación que aparece en la
CRL y consulta de la bitácora.

### 4.3 Verificar la cadena de confianza con OpenSSL

```bash
curl -s localhost:8000/pki/ca-chain > chain.pem
csplit -sz -f cert chain.pem '/-----BEGIN CERTIFICATE-----/' '{*}'   # cert00..cert02 = intermedias, cert03 = raíz
for c in cert00 cert01 cert02; do openssl verify -CAfile cert03 $c; done
openssl x509 -in cert03 -noout -subject -ext basicConstraints,keyUsage
curl -s localhost:8000/pki/crl | openssl crl -noout -text | head -20
```

### 4.4 A mano con curl

```bash
curl -s -X POST localhost:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"ana@example.com","password":"boletos-seguros-2026","nombre":"Ana"}'
curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"ana@example.com","password":"boletos-seguros-2026"}'
curl -s localhost:8000/auth/me -H "Authorization: Bearer <access_token>"
curl -s -X POST localhost:8000/dev/token -H 'Content-Type: application/json' -d '{"role":"staff"}'   # solo dev
```

Para Postman, Bruno o Insomnia: importa `openapi.yaml` (genera la colección completa).

---

## 5. Contrato API

`openapi.yaml` se genera desde el código con `python scripts/export_openapi.py`; el CI falla si no está al día.

| Método | Ruta | Acceso | RF |
|---|---|---|---|
| POST | `/auth/register` | Público | RF-01 |
| POST | `/auth/login` | Público | RF-02 |
| POST | `/auth/refresh` | Refresh token | RF-03 |
| POST | `/auth/logout` | Autenticado + refresh token | RF-04 |
| GET | `/auth/me` | Autenticado | — |
| GET | `/.well-known/jwks.json` | Público | RF-08 |
| GET | `/pki/ca-chain` | Público | RF-15 |
| GET | `/pki/crl` | Público (cabecera `X-TSA-Token` si hay TTP) | RF-14 |
| POST | `/pki/csr` | admin o certificado de servicio (mTLS) | RF-12, RF-13 |
| POST | `/pki/revoke` | admin | RF-14 |
| GET | `/pki/certificates` | admin · *nuevo* | — |
| POST | `/devices/enrollment-codes` | admin | RF-16 |
| POST | `/devices/enroll` | Código de un solo uso | RF-16 |
| GET | `/devices` | admin · *nuevo* | — |
| POST | `/devices/{id}/revoke` | admin · *nuevo* | RF-17 |
| GET / POST / PATCH | `/admin/users` | admin | RF-06 |
| GET | `/admin/audit` | admin | RF-18 |
| POST | `/admin/signing-keys/rotate` | admin · *nuevo* | RNF-04 |
| GET | `/health` | Interno | — |
| POST | `/dev/token` | Solo `ENV≠production` y `ENABLE_DEV_STUB=true` | BT-02 |

Las rutas *nuevas* son cambios compatibles (solo se agregan); se avisan en el Scrum of Scrums.

---

## 6. Configuración

Todas las variables se leen del entorno o de `.env` (`app/core/config.py`).

| Variable | Por defecto | Descripción |
|---|---|---|
| `DATABASE_URL` | — | Conexión como **m1_app** |
| `MIGRATIONS_DATABASE_URL` | — | Conexión como **m1_owner** (solo Alembic) |
| `REDIS_URL` / `RATE_LIMIT_BACKEND` | `redis://localhost:6379/0` / `redis` | Rate limiting y eventos (`memory` para no usar Redis) |
| `KEK_BASE64` | **obligatoria** | 32 bytes: cifra las llaves privadas (AES-256-GCM) |
| `PEPPER_BASE64` | **obligatoria** | 32 bytes: `idh`. Cambiarla invalida todos los `idh` |
| `EVENTS_HMAC_KEY_BASE64` | vacía | Firma HMAC de los eventos de Redis Streams |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `https://auth.boletera.local` / `boletera-api` | Deben coincidir con el middleware de M2–M6 |
| `ACCESS_TOKEN_TTL_SECONDS` / `REFRESH_TOKEN_TTL_DAYS` | 900 / 7 | RNF-02 |
| `LOCKOUT_THRESHOLD` / `LOCKOUT_BASE_SECONDS` / `LOCKOUT_MAX_SECONDS` | 5 / 30 / 900 | Bloqueo progresivo |
| `RATE_LIMIT_LOGIN_PER_IP` / `_PER_ACCOUNT` / `RATE_LIMIT_REGISTER_PER_IP` | 20 / 10 / 10 | Por minuto |
| `PKI_DEV_BOOTSTRAP` | `true` | Simula la ceremonia si no hay jerarquía (**false** en integración) |
| `PKI_PROFILE_POLICY` | `event-signing=m4-tickets;service=*` | Qué servicio (CN) puede pedir qué perfil por mTLS |
| `TRUST_PROXY_CLIENT_CERT` | `false` | Aceptar el certificado de cliente que reenvía Traefik |
| `TSA_URL` | vacía | Endpoint RFC 3161 de la TTP |
| `BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | vacías | Primer admin si no existe ninguno |
| `ENABLE_DEV_STUB` | `true` | Habilita `/dev/token` (nunca en producción) |

---

## 7. Ceremonia de llaves con la TTP

En desarrollo la PKI se simula sola. Para la ceremonia real del **viernes 27 de noviembre** (DF-07):

```bash
export CEREMONY_PASSPHRASE='frase-larga-de-los-custodios'
python scripts/ceremony/ceremony.py ttp-root --out ceremony-out   # [TTP] raíz P-256, 10 años
python scripts/ceremony/ceremony.py m1-csr   --out ceremony-out   # [M1]  3 llaves + CSR
python scripts/ceremony/ceremony.py ttp-sign --out ceremony-out   # [TTP] firma las intermedias (3 años)
PKI_DEV_BOOTSTRAP=false \
python scripts/ceremony/ceremony.py m1-load  --out ceremony-out   # [M1]  carga en auth.ca_keys cifradas con la KEK
python scripts/ceremony/ceremony.py acta     --out ceremony-out   # huellas SHA-256 para el acta
```

`ceremony-out/` está en `.gitignore`. La llave raíz cifrada se entrega a los custodios de la TTP y se borra
de la máquina de la ceremonia. Si la TTP ya tiene su propio script, solo se usan `m1-csr`, `m1-load` y `acta`.

---

## 8. Integración con los demás módulos

| Módulo | Qué usa de M1 | Cómo |
|---|---|---|
| Todos | Validar JWT | `middleware/python/jwt_auth.py` (FastAPI) o `middleware/typescript/jwtAuth.ts` (`jose`). `M1_JWKS_URL`, `JWT_ISSUER`, `JWT_AUDIENCE=boletera-api` |
| Todos | Datos de usuario sin tocar `auth` | Vista `shared.v_usuarios (id, role, status, idh)` o `GET /auth/me` |
| M4 | Certificado `event-signing` | Genera su par P-256, envía CSR a `POST /pki/csr` (admin o mTLS con CN `m4-tickets`) |
| M4 | Hash de identidad del comprador | Claim `idh` del JWT |
| M5, M6 | Validación offline | `GET /pki/ca-chain` (ancla: raíz de la TTP) y `GET /pki/crl` |
| M6 | Enrolar escáneres | Admin genera código → la app envía CSR + código a `POST /devices/enroll` |
| M5, M6 | Revocaciones | Stream `m1.events`, evento `certificate.revoked` (`sig` = HMAC-SHA256 de `ts.payload`) |
| M4, M5 | Interoperabilidad de formatos | `contracts/test-vectors/` (JWT, DER vs R‖S, idh, payload canónico, tokens negativos) |

---

## 9. Estructura del repositorio

```
app/
  main.py            create_app(): lifespan (llaves, PKI, admin), routers, /ui
  api/               auth, wellknown, pki, devices, admin, health, dev_stub
  core/              config, database, security (JWT y roles), errors (RFC 7807), logging, ratelimit
  crypto/            passwords, tokens, keystore, ca, tsa_client  ← revisión obligatoria de Johan
  models/            8 tablas del esquema auth (SQLAlchemy 2)
  schemas/           modelos Pydantic = contrato
  services/          users, sessions, keys, pki, devices, audit
  events/            publisher (Redis Streams)
  data/              common_passwords.txt
admin-ui/            panel de administración (HTML/JS/CSS sin build)
middleware/          validación JWT para otros equipos (Python y TypeScript)
contracts/test-vectors/  vectores compartidos (JO-01)
db/                  00_init.sh + sql/00_init.sql (BD general)
migrations/          Alembic, solo esquema auth
scripts/             gen_secrets, seed_demo, demo_flow, export_openapi, generate_test_vectors, ceremony/
tests/               unit/, integration/, security/, db_permissions/, vectors/
docs/adr/            ADR 0003, 0009, 0010, 0011
openapi.yaml         contrato exportado
```

---

## 10. Qué pasó con el PR #1 (contrato API)

El PR de Brandon (`feature/actualizacion`, BT-01/02/03) **no tenía conflictos de texto con `main`**: Git lo fusiona
sin marcas. Los problemas eran de estructura, y por eso «chocaba» con el proyecto:

1. **Creaba un segundo proyecto dentro de `m1-auth/m1-auth/`**, con su propio `Dockerfile`, `docker-compose.yml`,
   `README.md`, `requirements.txt` y un `app/core/config.py` incompatible (dataclass) con el de `main` (pydantic-settings).
2. **El CI no probaba su código:** `pytest` solo busca en `tests/` y `mypy` solo en `app/` de la raíz, así que el CI
   salía verde ejecutando una sola prueba. Al probarlo aparte, `mypy --strict` marcaba 5 errores.
3. **Llave privada en el código** (`stub_keys.py`): Gitleaks la detecta como secreto y bloquea el CI.
4. **Audiencia distinta:** el PR usaba `boletera-api` y el `.env.example` de `main` decía `boletera`.
5. Los endpoints devolvían datos fijos y `ProblemDetails` se declaraba pero no había manejador RFC 7807.

**Solución en esta rama:** se hizo merge del PR (se conserva la autoría de Brandon en el historial), se movió su
código a la raíz (schemas, routers, middleware, `openapi.yaml`, prueba del middleware), se eliminó la carpeta
anidada, se conectó todo a la lógica real, se movió la llave de prueba a `tests/vectors/` con excepción en
`.gitleaks.toml`, se unificó `JWT_AUDIENCE=boletera-api` y `openapi.yaml` ahora se genera desde el código.
**Recomendación:** cerrar el PR #1 sin fusionarlo y abrir uno nuevo desde `feature/m1-completo`.

---

## 11. Pendientes antes del 8 de diciembre

El detalle, con responsable y fecha, está en el *Reporte técnico y ejecutivo del Módulo 1*. Resumen:

- **Diego:** confirmar con la profesora el alcance de la TTP (DF-02) y el valor de `JWT_AUDIENCE` con M2–M6; aprobar los ADR.
- **Johan:** verificar la respuesta RFC 3161 contra el certificado `tsa` (JO-08); revisar `app/crypto/`; ampliar la lista de contraseñas comunes.
- **Osvaldo:** llevar `00_init.sql` a `platform/db/` y crear la BD en Neon (OG-02); pasar la ceremonia real con `m1-load`.
- **Brandon:** configurar Traefik con mTLS real hacia M1 (BT-09) y cerrar el PR #1.
- **Patricia:** validar el panel con el equipo y preparar la presentación (PM-06).
- **Alexis:** verificar el CI en GitHub (primera corrida), publicar la imagen en GHCR (AG-09), pruebas con M4/M5 (AG-08) y reporte final (AG-10).

---

## 12. Forma de trabajo

- Una rama por tarjeta: `feature/<ID>-<descripcion>` (p. ej. `feature/OG-04-registro`).
- Todo entra por Pull Request a `main`, con CI en verde y al menos una revisión de alguien que no sea el autor.
- Nada de `app/crypto/` entra sin revisión de Johan.
- Nunca subir `.env`, llaves ni contraseñas; `ceremony-out/` tampoco.

| Integrante | Rol |
|---|---|
| Diego Flores Madrigal | Tech Lead & Arquitecto de Software |
| Johan Olguin Hernández | Cripto & Security Engineer |
| Osvaldo Gil Valentín | Backend Developer A · Lógica y persistencia |
| Brandon Trejo Hernández | Backend Developer B · APIs y comunicaciones |
| Patricia E. Martinez Ortiz | Frontend / UI Developer |
| Alexis Guzmán Dolores | QA, DevOps & Integration Engineer |
