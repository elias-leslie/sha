from __future__ import annotations

from app.config import get_settings
from app.db import DatabaseStore
from app.migrations import sqlite_migration_versions


def main() -> None:
    settings = get_settings()
    store = DatabaseStore(settings.database_url)
    try:
        store.prepare()
        versions = sqlite_migration_versions(settings.database_url)
    finally:
        store.dispose()
    print(f"applied {len(versions)} migration(s): {', '.join(versions) if versions else 'none'}")


if __name__ == "__main__":
    main()
