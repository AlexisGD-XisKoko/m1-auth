"""Permisos de la BD general (AG-03 · RNF-13 · casos negativos de la sección 4.5).

Requieren PostgreSQL con 00_init.sql y la migración aplicados. Variables:
  TEST_DATABASE_URL     conexión como m1_app
  TEST_OTHER_MODULE_URL conexión como el rol de OTRO módulo (p. ej. m2_app)
Se omiten si no están definidas (p. ej. al correr con SQLite).
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

M1_URL = os.getenv("TEST_DATABASE_URL", "")
OTHER_URL = os.getenv("TEST_OTHER_MODULE_URL", "")

pytestmark = pytest.mark.skipif(
    not (M1_URL.startswith("postgresql") and OTHER_URL.startswith("postgresql")),
    reason="Requiere PostgreSQL con roles reales (TEST_DATABASE_URL y TEST_OTHER_MODULE_URL)",
)


def _run(url: str, sql: str) -> object:
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            return conn.execute(text(sql)).fetchall()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM auth.users",
        "SELECT password_hash FROM auth.users",
        "SELECT * FROM auth.refresh_tokens",
        "SELECT * FROM auth.signing_keys",
        "UPDATE auth.users SET role = 'admin'",
    ],
)
def test_otro_modulo_no_puede_tocar_el_esquema_auth(sql: str) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        _run(OTHER_URL, sql)


def test_otro_modulo_lee_solo_la_vista_compartida() -> None:
    cols = _run(
        OTHER_URL,
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'shared' AND table_name = 'v_usuarios' ORDER BY ordinal_position",
    )
    assert [c[0] for c in cols] == ["id", "role", "status", "idh"]  # type: ignore[attr-defined]
    _run(OTHER_URL, "SELECT id, role, status, idh FROM shared.v_usuarios LIMIT 1")


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE auth.audit_log SET actor = 'x'",
        "DELETE FROM auth.audit_log",
        "TRUNCATE auth.audit_log",
    ],
)
def test_m1_app_no_altera_la_bitacora(sql: str) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        _run(M1_URL, sql)


def test_m1_app_no_puede_hacer_ddl() -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        _run(M1_URL, "CREATE TABLE auth.intruso (id int)")
