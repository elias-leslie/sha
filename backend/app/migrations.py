from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
import sqlite3

from sqlalchemy.engine import make_url

Migration = tuple[str, Callable[[sqlite3.Connection], None]]

CURRENT_SCHEMA_VERSION = "20260630_0001_macos_platform_constraints"


def run_sqlite_migrations(database_url: str) -> list[str]:
    db_path = _sqlite_database_path(database_url)
    if db_path is None or not db_path.exists():
        return []

    applied_now: list[str] = []
    with sqlite3.connect(db_path) as connection:
        _ensure_schema_migrations(connection)
        applied = {
            str(row[0])
            for row in connection.execute("SELECT version FROM schema_migrations").fetchall()
        }
        for version, migrate in _MIGRATIONS:
            if version in applied:
                continue
            connection.execute("PRAGMA foreign_keys=OFF")
            try:
                migrate(connection)
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, _utc_now_z()),
                )
                problems = connection.execute("PRAGMA foreign_key_check").fetchall()
                if problems:
                    raise RuntimeError(f"sqlite foreign key check failed after migration {version}: {problems}")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.execute("PRAGMA foreign_keys=ON")
            applied_now.append(version)
    return applied_now


def sqlite_migration_versions(database_url: str) -> list[str]:
    db_path = _sqlite_database_path(database_url)
    if db_path is None or not db_path.exists():
        return []
    with sqlite3.connect(db_path) as connection:
        _ensure_schema_migrations(connection)
        return [
            str(row[0])
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version ASC").fetchall()
        ]


def _sqlite_database_path(database_url: str) -> Path | None:
    url = make_url(database_url)
    if not url.drivername.startswith("sqlite"):
        return None
    database = url.database
    if not database or database == ":memory:":
        return None
    return Path(database).expanduser()


def _ensure_schema_migrations(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )
    connection.commit()


def _upgrade_sqlite_platform_constraints(connection: sqlite3.Connection) -> None:
    for table_name in ("endpoints", "installer_profiles"):
        _upgrade_platform_constraint(connection, table_name)


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
    connection.execute(f'INSERT INTO "{temp_table}" ({quoted_columns}) SELECT {quoted_columns} FROM "{table_name}"')
    connection.execute(f'DROP TABLE "{table_name}"')
    connection.execute(f'ALTER TABLE "{temp_table}" RENAME TO "{table_name}"')


def _utc_now_z() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


_MIGRATIONS: tuple[Migration, ...] = (
    (CURRENT_SCHEMA_VERSION, _upgrade_sqlite_platform_constraints),
)
