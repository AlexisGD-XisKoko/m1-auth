# ADR-0003: Un microservicio por módulo y una BD PostgreSQL general con esquema y rol por módulo
Estado: Propuesto (2026-11-18) · Reemplaza a la versión «una base por servicio» si ya se había aceptado
Autor: Diego Flores Madrigal (Tech Lead M1)

## Contexto
El grupo decidió usar una sola instancia PostgreSQL (`boletera`) para poder alojarla gratis en la nube.
Con una sola base, un módulo podría leer o alterar datos de otro (p. ej. `auth.users.password_hash`).

## Decisión
- Un esquema por módulo (`auth`, `catalog`, `payments`, `tickets`, `access`, `trust`) y `shared` solo para vistas.
- Dos roles por módulo: `mN_owner` (dueño, migra) y `mN_app` (el servicio; solo DML, `CONNECTION LIMIT`).
- Sin llaves foráneas ni JOINs entre esquemas; referencias por UUID; datos ajenos por API, eventos o vistas de `shared`.
- `platform/db/00_init.sql` crea esquemas, roles y permisos; cada equipo versiona sus tablas (Alembic `version_table_schema`, Flyway `schemas`).
- Prueba automática de permisos en CI (rol de otro módulo → `permission denied` en `auth.*`).

## Consecuencias
+ Una sola cosa que administrar y respaldar; cabe en Neon Free.
+ El aislamiento es verificable en CI (`tests/db_permissions`).
- El aislamiento depende de configurar bien los permisos: el script de roles se revisa por PR.
- Un módulo puede agotar conexiones: se mitiga con `CONNECTION LIMIT` y pool de 2–3 por servicio.
