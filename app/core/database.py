"""Conexión a la BD general (esquema auth) con el rol de aplicación m1_app."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from typing import Any

from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


def build_engine(settings: Settings) -> Engine:
    url = settings.database_url
    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        # Pruebas sin PostgreSQL: SQLite no tiene esquemas, así que «auth» se traduce a nada.
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url.endswith("sqlite://"):
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs).execution_options(schema_translate_map={"auth": None})

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn: Any, _: Any) -> None:
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

        return engine
    kwargs.update(pool_size=settings.db_pool_size, max_overflow=1)
    return create_engine(url, **kwargs)


def build_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def get_db(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.sessionmaker
    with factory() as session:
        yield session


def as_utc(value: dt.datetime | None) -> dt.datetime | None:
    """SQLite devuelve fechas sin zona; PostgreSQL (timestamptz) con zona."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
