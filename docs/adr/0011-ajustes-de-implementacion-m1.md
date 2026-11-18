# ADR-0011: Ajustes de implementación de M1 respecto a la planeación v1.1
Estado: Propuesto (2026-11-18) · Para revisión del equipo M1 (no afecta contratos de otros módulos salvo lo indicado)

| # | Planeación v1.1 | Implementación | Motivo |
|---|---|---|---|
| 1 | 7 tablas en `auth` | 8 tablas: se agrega `auth.ca_keys` | La 5.5 pide intermedias cifradas en el esquema `auth`, pero la 2.6 no tenía tabla. La raíz se guarda sin llave privada. |
| 2 | `auth.users` sin nombre | Columna `nombre` | RF-01 pide nombre en el registro. |
| 3 | `aud` sin valor definido | `JWT_AUDIENCE=boletera-api` | Valor que ya usaba el middleware del PR #1; el `.env.example` de `main` decía `boletera`. Debe acordarse con M2–M6. |
| 4 | 15 endpoints | 19 (+ `GET /pki/certificates`, `GET /devices`, `POST /devices/{id}/revoke`, `POST /admin/signing-keys/rotate`) | Panel de administración, RF-17 y RNF-04. Cambios compatibles (solo se agregan rutas). |
| 5 | Panel en React + Vite | Panel estático HTML/JS servido en `/ui` | Cero build para la demo; misma funcionalidad PM-02 a PM-05. Migrar a React es opcional. |
| 6 | `/auth/logout` «Autenticado» | Requiere Bearer **y** el refresh token en el cuerpo | Se revoca la familia exacta y solo si pertenece al usuario. |
| 7 | Cuenta bloqueada | Responde 429 con `Retry-After` | Coherente con «exceso de intentos responde 429» del guion de demo. |
| 8 | Stub con llave fija en el código (PR #1) | `/dev/token` firma con la llave real activa; la llave fija pasa a `tests/vectors/` | Gitleaks bloquea llaves privadas en el código; los vectores JO-01 sí necesitan una llave pública de prueba. |
