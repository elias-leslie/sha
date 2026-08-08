from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import DatabaseStore
from app.models import Client, Endpoint, Location, PostureSnapshot
from app.utils import to_utc_z, utc_now


def seed_database(session: Session) -> None:
    now = to_utc_z(utc_now())

    # Update test artifact client names if present
    old_test_clients = session.scalars(select(Client).where(Client.name.like("reporter-action%"))).all()
    msp_names = ["SummitFlow Solutions", "Acme Financial Group", "Apex Logistics Corp", "Vanguard Health Alliance"]
    for idx, old_c in enumerate(old_test_clients):
        new_name = msp_names[idx % len(msp_names)]
        old_c.name = new_name
        old_c.name_normalized = new_name.lower()
    session.flush()

    # Seed MSP Client Companies
    clients_data = [
        ("cl_summitflow", "summit-corp", "SummitFlow Solutions"),
        ("cl_acme", "acme-financial", "Acme Financial Group"),
        ("cl_apex", "apex-logistics", "Apex Logistics Corp"),
        ("cl_vanguard", "vanguard-health", "Vanguard Health Alliance"),
    ]

    client_map: dict[str, Client] = {}
    for cid, key, name in clients_data:
        client = session.scalar(select(Client).where(Client.client_id == cid))
        if not client:
            client = Client(
                client_id=cid,
                key=key,
                name=name,
                name_normalized=name.lower(),
                state="active",
                is_system=False,
                created_at=now,
                updated_at=now,
            )
            session.add(client)
        else:
            client.name = name
            client.name_normalized = name.lower()
            client.key = key
        client_map[cid] = client

    session.flush()

    # Seed Branch / Site Locations
    locations_data = [
        ("loc_sf_ny", "cl_summitflow", "sf-ny-hq", "New York Headquarters"),
        ("loc_sf_lon", "cl_summitflow", "sf-lon-dc", "London Datacenter"),
        ("loc_acme_ny", "cl_acme", "acme-ny-wallst", "Wall St Trading Floor"),
        ("loc_acme_chi", "cl_acme", "acme-chi-ops", "Chicago Operations Hub"),
        ("loc_apex_dal", "cl_apex", "apex-dal-hub", "Dallas Fleet Terminal"),
        ("loc_apex_atl", "cl_apex", "apex-atl-dist", "Atlanta Distribution Center"),
        ("loc_van_bos", "cl_vanguard", "van-bos-med", "Boston Medical Center"),
        ("loc_van_sea", "cl_vanguard", "van-sea-lab", "Seattle Clinical Lab"),
    ]

    location_map: dict[str, Location] = {}
    for lid, cid, key, name in locations_data:
        location = session.scalar(select(Location).where(Location.location_id == lid))
        if not location:
            location = Location(
                location_id=lid,
                client_id=cid,
                key=key,
                name=name,
                name_normalized=name.lower(),
                state="active",
                is_system=False,
                created_at=now,
                updated_at=now,
            )
            session.add(location)
        else:
            location.name = name
            location.key = key
        location_map[lid] = location

    session.flush()

    # Seed Host Computers & Servers
    endpoints_data = [
        ("ep_sf_ny_dc01", "cl_summitflow", "loc_sf_ny", "sf-ny-dc01.summitflow.dev", "windows", "Windows Server 2025"),
        ("ep_sf_lon_gw01", "cl_summitflow", "loc_sf_lon", "sf-lon-sec-gw01", "linux", "RHEL 9.4 Enterprise"),
        ("ep_acme_wks14", "cl_acme", "loc_acme_ny", "acme-trading-wks14", "windows", "Windows 11 Pro"),
        ("ep_acme_db01", "cl_acme", "loc_acme_chi", "acme-chi-db01.internal", "linux", "Ubuntu Server 24.04 LTS"),
        ("ep_apex_dal_dispatch", "cl_apex", "loc_apex_dal", "apex-dal-dispatch", "windows", "Windows 11 Enterprise"),
        ("ep_van_bos_sec", "cl_vanguard", "loc_van_bos", "van-bos-sec-node", "linux", "Fedora 40 Workstation"),
        ("ep_van_sea_mac02", "cl_vanguard", "loc_van_sea", "van-sea-imaging-mac", "macos", "macOS Sequoia 15.1"),
    ]

    for eid, cid, lid, hostname, platform, platform_ver in endpoints_data:
        ep = session.scalar(select(Endpoint).where(Endpoint.endpoint_id == eid))
        if not ep:
            ep = Endpoint(
                endpoint_id=eid,
                agent_fingerprint=f"fp_{eid}",
                hostname=hostname,
                platform=platform,
                platform_version=platform_ver,
                agent_version="1.4.2",
                client_id=cid,
                location_id=lid,
                tenant_id=cid,
                site_id=lid,
                status="active",
                connectivity_status="online",
                last_seen_at=now,
                last_heartbeat_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(ep)
        else:
            ep.hostname = hostname
            ep.client_id = cid
            ep.location_id = lid

    session.commit()


if __name__ == "__main__":
    from app.config import get_settings

    settings = get_settings()
    store = DatabaseStore(settings.resolved_database_url())
    store.prepare()
    with store.session() as session:
        seed_database(session)
    print("Database seeded with MSP Clients, Locations, and Endpoints.")
