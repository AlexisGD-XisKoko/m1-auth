# ADR-0010: Hospedaje de la BD general (local para desarrollo, Neon para integración)
Estado: Propuesto (2026-11-18)
Autor: Diego Flores Madrigal (Tech Lead M1)

## Decisión
- Desarrollo: PostgreSQL 17 en `docker compose` con el mismo `00_init.sql`.
- Integración: proyecto Neon `boletera`, rama `main`; una rama por equipo para probar migraciones.
- Migraciones solo desde GitHub Actions al hacer merge a `main`, con `mN_owner` en GitHub Secrets.
- Demo: `docker compose` local como plan B (Neon se duerme tras 5 min y tarda en despertar).
- Alternativa si Neon no convence: Aiven (siempre encendido, máx. 20 conexiones).

## Consecuencias
+ Costo $0, integración entre laptops distintas.
- Arranque en frío de Neon; límite de 1 GB (sobra con datos ficticios).
