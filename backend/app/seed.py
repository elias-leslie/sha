from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import DatabaseStore
from app.models import Client, Endpoint, Location, PostureSnapshot
from app.utils import to_utc_z, utc_now


def seed_database(session: Session) -> None:
    now = to_utc_z(utc_now())

    # Safely clear tables without foreign key issues
    tables_to_clear = [
        "posture_snapshots",
        "installers",
        "approval_decisions",
        "endpoints",
        "locations",
        "clients",
    ]

    session.execute(text("PRAGMA foreign_keys = OFF;"))
    for tbl in tables_to_clear:
        try:
            session.execute(text(f"DELETE FROM {tbl};"))
        except Exception:
            pass
    session.execute(text("PRAGMA foreign_keys = ON;"))
    session.flush()

    # Seed Default Home / Primary Tenant & Site for real computer agent enrollment
    primary_tenant = Client(
        client_id="tenant_home_primary",
        key="home-lab",
        name="SummitFlow Home Lab",
        name_normalized="summitflow home lab",
        state="active",
        is_system=True,
        created_at=now,
        updated_at=now,
    )
    session.add(primary_tenant)
    session.flush()

    primary_site = Location(
        location_id="site_home_primary",
        client_id="tenant_home_primary",
        key="main-residence",
        name="Main Residence",
        name_normalized="main residence",
        state="active",
        is_system=True,
        created_at=now,
        updated_at=now,
    )
    session.add(primary_site)
    session.flush()

    session.commit()
    print("Purged all fake seed data and initialized clean Home Lab Tenant & Site.")


if __name__ == "__main__":
    settings = get_settings()
    store = DatabaseStore(settings.resolved_database_url())
    with store.session() as sess:
        seed_database(sess)
