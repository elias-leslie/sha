from __future__ import annotations

import os
import platform
import socket
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import DatabaseStore
from app.models import Client, Endpoint, Location
from app.utils import to_utc_z, utc_now


def get_real_os_pretty_name() -> str:
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=")[1].strip().strip('"')
    except Exception:
        pass
    return f"{platform.system()} {platform.release()}"


def seed_database(session: Session) -> None:
    now = to_utc_z(utc_now())

    # Safely clear old tables
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

    # 1. Seed Real Home Lab / Personal Workspace Tenant & Site
    primary_tenant = Client(
        client_id="tenant_home_primary",
        key="home-lab",
        name="SummitFlow Home Lab & Workspace",
        name_normalized="summitflow home lab & workspace",
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

    # 2. Ingest REAL Live Telemetry from the local host running SHA
    real_hostname = socket.gethostname()
    real_os = get_real_os_pretty_name()
    real_arch = platform.machine() or "x86_64"

    real_endpoint_id = f"ep_{real_hostname.replace('.', '_')}"
    real_fp = f"fp_real_{real_hostname}"

    real_endpoint = Endpoint(
        endpoint_id=real_endpoint_id,
        agent_fingerprint=real_fp,
        hostname=real_hostname,
        platform=platform.system().lower(),
        platform_version=real_os,
        platform_profile="server" if "server" in real_os.lower() else "workstation",
        agent_version="2.4.0-live",
        protocol_version="v2",
        architecture=real_arch,
        client_id="tenant_home_primary",
        location_id="site_home_primary",
        tenant_id="home-lab",
        site_id="main-residence",
        status="active",
        connectivity_status="online",
        last_seen_at=now,
        last_heartbeat_at=now,
        created_at=now,
        updated_at=now,
    )
    session.add(real_endpoint)
    session.flush()

    session.commit()
    print(f"Purged all fake data. Registered REAL local host system [{real_hostname}] ({real_os}) under Home Lab Tenant.")


if __name__ == "__main__":
    settings = get_settings()
    store = DatabaseStore(settings.resolved_database_url())
    with store.session() as sess:
        seed_database(sess)
