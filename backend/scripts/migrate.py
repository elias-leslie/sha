from __future__ import annotations

from app.config import get_settings
from app.db import DatabaseStore
from app.migrations import database_revisions


def main() -> None:
    settings = get_settings()
    database_url = settings.resolved_database_url()
    store = DatabaseStore(database_url, migration_mode="upgrade")
    try:
        store.prepare()
        with store.engine.connect() as connection:
            current, head = database_revisions(connection, database_url)
    finally:
        store.dispose()
    print(f"database revision: {current or 'none'} (head: {head})")


if __name__ == "__main__":
    main()
