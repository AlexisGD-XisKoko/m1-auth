# ADR-0010: Hospedaje de la BD general (local para desarrollo, Neon para integración)
Estado: Aceptado (2026-11-19)
Autor: Diego Flores Madrigal (Tech Lead M1)

## Decisión
- Desarrollo: PostgreSQL 17 en `docker compose` con el mismo `00_init.sql`.
- Integración: proyecto Neon `boletera`, rama `main` (PostgreSQL 17); una rama por equipo para probar migraciones.
- Migraciones solo desde GitHub Actions al hacer merge a `main`, con `mN_owner` en GitHub Secrets.
- Demo: `docker compose` local como plan B (Neon se duerme tras 5 min y tarda en despertar).
- Alternativa si Neon no convence: Aiven (siempre encendido, máx. 20 conexiones).

## Administración y resguardo de secretos
- Administrador designado de la BD en Neon: **Oswaldo Gil Valentín** (con respaldo de **Brandon Trejo Hernández** para la credencial administrativa `neondb_owner`).
- Las credenciales maestras y las cadenas de conexión individuales (`mN_owner`, `mN_app`, `trust_owner`, `trust_app` e `integration_ro`) se resguardan en gestor de contraseñas y en los GitHub Secrets de cada repositorio, sin archivos planos en equipos locales ni en control de versiones.

## Consecuencias
+ Costo $0, integración entre laptops distintas y aislamiento por esquemas/roles verificado.
- Arranque en frío de Neon; límite de 1 GB (sobra con datos ficticios) y tope de 5 conexiones por rol de aplicación.
