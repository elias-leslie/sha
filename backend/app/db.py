from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any, Literal, cast
from pathlib import Path

from fastapi import Request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.migrations import require_current_database, run_sqlite_migrations, upgrade_database

_POSTGRES_DDL_LOCK_ID = 918502781


class DatabaseStore:
    def __init__(
        self,
        database_url: str,
        *,
        migration_mode: Literal["upgrade", "check"] = "upgrade",
    ) -> None:
        self.database_url = database_url
        self.migration_mode = migration_mode
        url = make_url(database_url)
        connect_args = {"check_same_thread": False} if url.drivername.startswith("sqlite") else {}
        self.engine = create_engine(
            database_url,
            future=True,
            poolclass=NullPool,
            connect_args=connect_args,
        )
        if url.drivername.startswith("sqlite"):
            event.listen(self.engine, "connect", _enable_sqlite_foreign_keys)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )

    def prepare(self) -> None:
        self._ensure_sqlite_parent_directory()
        run_sqlite_migrations(self.database_url)
        is_postgres = make_url(self.database_url).drivername.startswith("postgresql")
        with self.engine.begin() as connection:
            if is_postgres:
                connection.exec_driver_sql(f"SELECT pg_advisory_lock({_POSTGRES_DDL_LOCK_ID})")
            try:
                if self.migration_mode == "upgrade":
                    upgrade_database(connection, self.database_url)
                else:
                    require_current_database(connection, self.database_url)
            finally:
                if is_postgres:
                    connection.exec_driver_sql(f"SELECT pg_advisory_unlock({_POSTGRES_DDL_LOCK_ID})")

    def dispose(self) -> None:
        self.engine.dispose()

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()

    def _ensure_sqlite_parent_directory(self) -> None:
        url = make_url(self.database_url)
        if not url.drivername.startswith("sqlite"):
            return
        database = url.database
        if not database or database == ":memory:":
            return
        Path(database).expanduser().parent.mkdir(parents=True, exist_ok=True)


def _enable_sqlite_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
    cursor = cast(Any, dbapi_connection).cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()

def get_store(request: Request) -> DatabaseStore:
    store = request.app.state.store
    if not isinstance(store, DatabaseStore):
        raise RuntimeError("database store is not initialized")
    return store
