from __future__ import annotations

import socket
from typing import Literal

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.auth import Principal
from app.authorization import record_audit_event, require_permission
from app.db import DatabaseStore, get_store
from app.models import Endpoint, Location
from app.utils import to_utc_z, utc_now

router = APIRouter(prefix="/api/network", tags=["network"])

DeviceType = Literal[
    "server",
    "workstation",
    "router",
    "switch",
    "nas",
    "san",
    "camera",
    "printer",
    "mobile",
    "ups",
    "other",
]


def classify_device(open_ports: list[int], hostname: str) -> tuple[DeviceType, str]:
    h = hostname.lower()
    if "router" in h or "gateway" in h or "firewall" in h:
        return "router", "Router / Gateway"
    if "switch" in h or "ubiquiti" in h or "unifi" in h:
        return "switch", "Managed Switch"
    if "nas" in h or "synology" in h or "qnap" in h or "truenas" in h or 548 in open_ports:
        return "nas", "Network Attached Storage"
    if "cam" in h or "camera" in h or 554 in open_ports:
        return "camera", "IP Security Camera"
    if "print" in h or 9100 in open_ports or 631 in open_ports:
        return "printer", "Network Printer"
    if 3389 in open_ports:
        return "workstation", "Windows Workstation"
    if 22 in open_ports and (80 in open_ports or 443 in open_ports):
        return "server", "Server Node"
    if 22 in open_ports:
        return "server", "Linux Host / Server"
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        return "router", "Network Appliance"
    return "other", "Network Device"


def get_local_subnet_base() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    except Exception:
        return "192.168.1"


@router.post("/scan")
async def trigger_network_scan(
    payload: dict[str, str] | None = None,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("endpoint.read")),
) -> dict[str, object]:
    subnet_base = get_local_subnet_base()
    target_cidr = (payload or {}).get("cidr") or f"{subnet_base}.0/24"
    discovered_nodes = []

    # Fast probe local subnet IPs (probe .1, .2, .254, gateway, and local interface)
    probe_ips = [
        f"{subnet_base}.1",
        f"{subnet_base}.2",
        f"{subnet_base}.10",
        f"{subnet_base}.50",
        f"{subnet_base}.100",
        f"{subnet_base}.254",
    ]

    for ip in probe_ips:
        open_ports = []
        for port in [22, 80, 443, 554, 3389, 8080, 9100]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.15)
                res = sock.connect_ex((ip, port))
                if res == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass

        if open_ports:
            try:
                resolved_hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                resolved_hostname = f"device-{ip.replace('.', '-')}.home"

            device_type, label = classify_device(open_ports, resolved_hostname)

            discovered_nodes.append({
                "ip": ip,
                "hostname": resolved_hostname,
                "device_type": device_type,
                "label": label,
                "open_ports": open_ports,
                "status": "online",
            })

    now_str = to_utc_z(utc_now())

    # Auto-register discovered network devices into Primary Home Tenant
    with store.session() as session:
        site = session.scalar(select(Location).where(Location.location_id == "site_home_primary"))
        location_id = site.location_id if site else "site_home_primary"
        client_id = site.client_id if site else "tenant_home_primary"

        registered_count = 0
        for node in discovered_nodes:
            ep_id = f"dev_{node['ip'].replace('.', '_')}"
            existing = session.scalar(select(Endpoint).where(Endpoint.endpoint_id == ep_id))
            if not existing:
                ep = Endpoint(
                    endpoint_id=ep_id,
                    agent_fingerprint=f"fp_net_{node['ip']}",
                    hostname=node["hostname"],
                    platform=node["device_type"],
                    platform_version=f"IP: {node['ip']} • {node['label']}",
                    platform_profile=node["device_type"],
                    agent_version="network-agentless",
                    protocol_version="v2",
                    client_id=client_id,
                    location_id=location_id,
                    tenant_id="home-lab",
                    site_id="main-residence",
                    status="active",
                    connectivity_status="online",
                    last_seen_at=now_str,
                    last_heartbeat_at=now_str,
                    created_at=now_str,
                    updated_at=now_str,
                )
                session.add(ep)
                registered_count += 1

        record_audit_event(
            session,
            event_type="network.scan_complete",
            actor=principal.user_id,
            metadata={"target_cidr": target_cidr, "discovered_count": len(discovered_nodes), "registered_count": registered_count},
        )
        session.commit()

    return {
        "cidr": target_cidr,
        "scanned_at": now_str,
        "discovered_count": len(discovered_nodes),
        "registered_count": registered_count,
        "discovered_nodes": discovered_nodes,
    }
