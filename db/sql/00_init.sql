-- =====================================================================================
-- platform/db/00_init.sql  (OG-01 · sección 7.1 de la planeación v1.1)
-- BD general «boletera»: un esquema y dos roles por módulo (mN_owner migra, mN_app opera).
-- Las contraseñas llegan como variables de psql desde los secretos; NUNCA se escriben aquí:
--   psql -v m1_owner_pw=... -v m1_app_pw=... -v other_pw=... -f 00_init.sql
-- Este archivo es la copia local de M1; la versión oficial vive en platform/db/.
-- Ejecutar como superusuario/administrador de la BD. Es idempotente.
-- =====================================================================================
\set ON_ERROR_STOP on

-- ---------- Roles ----------------------------------------------------------------------
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', r.name, r.pw)
FROM (VALUES
  ('m1_owner', :'m1_owner_pw'), ('m1_app', :'m1_app_pw'),
  ('m2_owner', :'other_pw'), ('m2_app', :'other_pw'),
  ('m3_owner', :'other_pw'), ('m3_app', :'other_pw'),
  ('m4_owner', :'other_pw'), ('m4_app', :'other_pw'),
  ('m6_owner', :'other_pw'), ('m6_app', :'other_pw'),
  ('trust_owner', :'other_pw'), ('trust_app', :'other_pw'),
  ('integration_ro', :'other_pw')
) AS r(name, pw)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.name)
\gexec

-- Límite de conexiones por rol de aplicación (STRIDE: DoS por agotamiento de conexiones).
ALTER ROLE m1_app CONNECTION LIMIT 5;
ALTER ROLE m2_app CONNECTION LIMIT 5;
ALTER ROLE m3_app CONNECTION LIMIT 5;
ALTER ROLE m4_app CONNECTION LIMIT 5;
ALTER ROLE m6_app CONNECTION LIMIT 5;
ALTER ROLE trust_app CONNECTION LIMIT 3;
ALTER ROLE integration_ro CONNECTION LIMIT 3;

-- Nadie crea objetos en public.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ---------- Esquemas ---------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS auth     AUTHORIZATION m1_owner;
CREATE SCHEMA IF NOT EXISTS catalog  AUTHORIZATION m2_owner;
CREATE SCHEMA IF NOT EXISTS payments AUTHORIZATION m3_owner;
CREATE SCHEMA IF NOT EXISTS tickets  AUTHORIZATION m4_owner;
CREATE SCHEMA IF NOT EXISTS access   AUTHORIZATION m6_owner;
CREATE SCHEMA IF NOT EXISTS trust    AUTHORIZATION trust_owner;
CREATE SCHEMA IF NOT EXISTS shared;  -- dueño: administrador (grupo de integración)

-- ---------- Permisos del esquema auth (M1) -------------------------------------------------
REVOKE ALL ON SCHEMA auth FROM PUBLIC;
GRANT USAGE ON SCHEMA auth TO m1_app;
ALTER DEFAULT PRIVILEGES FOR ROLE m1_owner IN SCHEMA auth
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO m1_app;
ALTER DEFAULT PRIVILEGES FOR ROLE m1_owner IN SCHEMA auth
  GRANT USAGE, SELECT ON SEQUENCES TO m1_app;

-- Patrón equivalente para los demás módulos (cada dueño ajusta en su migración).
DO $$
DECLARE s text; o text; a text;
BEGIN
  FOR s, o, a IN SELECT * FROM (VALUES
      ('catalog','m2_owner','m2_app'), ('payments','m3_owner','m3_app'),
      ('tickets','m4_owner','m4_app'), ('access','m6_owner','m6_app'),
      ('trust','trust_owner','trust_app')) AS t(s,o,a)
  LOOP
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', s);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s, a);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
                   'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', o, s, a);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
                   'GRANT USAGE, SELECT ON SEQUENCES TO %I', o, s, a);
  END LOOP;
END $$;

-- ---------- Esquema shared: solo vistas publicadas por cada dueño -------------------------
REVOKE ALL ON SCHEMA shared FROM PUBLIC;
GRANT USAGE ON SCHEMA shared TO m1_app, m2_app, m3_app, m4_app, m6_app, trust_app, integration_ro;
GRANT USAGE, CREATE ON SCHEMA shared TO m1_owner, m2_owner, m4_owner, m6_owner;

-- integration_ro: depuración de solo lectura de lo publicado (nunca del esquema auth).
GRANT SELECT ON ALL TABLES IN SCHEMA shared TO integration_ro;
