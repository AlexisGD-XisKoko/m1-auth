#!/bin/sh
# Lo ejecuta la imagen oficial de PostgreSQL la PRIMERA vez que arranca el contenedor
# (docker-entrypoint-initdb.d). Pasa las contraseñas como variables de psql.
set -eu
OTHER_PW="${OTHER_MODULES_PASSWORD:-$(head -c 18 /dev/urandom | base64)}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v m1_owner_pw="$M1_OWNER_PASSWORD" \
  -v m1_app_pw="$M1_APP_PASSWORD" \
  -v other_pw="$OTHER_PW" \
  -f /docker-entrypoint-initdb.d/sql/00_init.sql
