"""Entorno de Alembic: versiona solo el esquema auth (version_table_schema='auth')."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool, text

from app.models import SCHEMA, Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    url = os.getenv("MIGRATIONS_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("Define MIGRATIONS_DATABASE_URL (rol m1_owner) para migrar.")
    return url


def _include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    # Nunca tocar objetos de otros esquemas (shared, catalog, tickets, ...).
    if type_ == "table":
        return getattr(obj, "schema", None) == SCHEMA
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        version_table_schema=SCHEMA,
        include_schemas=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name = :s"),
            {"s": SCHEMA},
        ).scalar()
        if not exists:  # en la BD general lo crea 00_init.sql; esto es solo para BD efímeras
            connection.execute(text(f"CREATE SCHEMA {SCHEMA}"))
        connection.commit()  # cerrar la transacción implícita antes de migrar
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=SCHEMA,
            include_schemas=True,
            include_object=_include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
