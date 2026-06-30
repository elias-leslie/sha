from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any, cast
from pathlib import Path
import sqlite3

from fastapi import Request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.models import Base


class DatabaseStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            future=True,
            poolclass=NullPool,
            connect_args={"check_same_thread": False},
        )
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
        Base.metadata.create_all(self.engine)
        self._upgrade_sqlite_platform_constraints()

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

    def _upgrade_sqlite_platform_constraints(self) -> None:
        url = make_url(self.database_url)
        if not url.drivername.startswith("sqlite"):
            return
        database = url.database
        if not database or database == ":memory:":
            return

        db_path = Path(database).expanduser()
        if not db_path.exists():
            return

        with sqlite3.connect(db_path) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            try:
                for table_name in ("endpoints", "installer_profiles"):
                    _upgrade_platform_constraint(connection, table_name)
                problems = connection.execute("PRAGMA foreign_key_check").fetchall()
                if problems:
                    raise RuntimeError(f"sqlite foreign key check failed after platform upgrade: {problems}")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.execute("PRAGMA foreign_keys=ON")


def _enable_sqlite_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
    cursor = cast(Any, dbapi_connection).cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def _upgrade_platform_constraint(connection: sqlite3.Connection, table_name: str) -> None:
    old_expression = "platform IN ('windows', 'linux')"
    new_expression = "platform IN ('windows', 'linux', 'macos')"
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    if row is None:
        return
    table_sql = str(row[0])
    if new_expression in table_sql or old_expression not in table_sql:
        return

    temp_table = f"{table_name}_sha_platform_upgrade"
    new_table_sql = table_sql.replace(f"CREATE TABLE {table_name}", f"CREATE TABLE {temp_table}", 1).replace(
        old_expression,
        new_expression,
    )
    columns = [str(column[1]) for column in connection.execute(f'PRAGMA table_info("{table_name}")').fetchall()]
    quoted_columns = ", ".join(f'"{column}"' for column in columns)

    connection.execute(f'DROP TABLE IF EXISTS "{temp_table}"')
    connection.execute(new_table_sql)
    connection.execute(
        f'INSERT INTO "{temp_table}" ({quoted_columns}) SELECT {quoted_columns} FROM "{table_name}"'
    )
    connection.execute(f'DROP TABLE "{table_name}"')
    connection.execute(f'ALTER TABLE "{temp_table}" RENAME TO "{table_name}"')


def get_store(request: Request) -> DatabaseStore:
    store = request.app.state.store
    if not isinstance(store, DatabaseStore):
        raise RuntimeError("database store is not initialized")
    return store
