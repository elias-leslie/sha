from __future__ import annotations

from app.control_registry import control_registry
from app.source_packs.catalog import load_source_packs

ACTIONABLE_CONTROL_IDS = {
    "control.windows.defender-real-time-protection",
    "control.windows.firewall-all-profiles",
    "control.windows.firewall-endpoint-isolated",
    "linux.network.endpoint-isolated",
    "linux.ssh.password-authentication-disabled",
}


def test_control_registry_api_exposes_every_catalog_control_in_deterministic_order(
    db_path,
    make_client,
) -> None:
    client = make_client(db_path)

    first = client.get("/api/control-registry")
    second = client.get("/api/control-registry")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()

    items = first.json()["items"]
    control_ids = [item["control_id"] for item in items]
    catalog_ids = {
        control.control_id
        for source_pack in load_source_packs()
        for control in source_pack.controls
    }

    assert catalog_ids < set(control_ids)
    assert control_ids == sorted(control_registry())
    assert all(
        set(item) == {
            "control_id",
            "title",
            "platform",
            "kind",
            "observation_aliases",
            "supported_actions",
        }
        for item in items
    )
    assert all(item["observation_aliases"] == sorted(item["observation_aliases"]) for item in items)


def test_control_registry_api_declares_only_actionable_controls_and_canonical_actions(
    db_path,
    make_client,
) -> None:
    client = make_client(db_path)

    response = client.get("/api/control-registry")

    assert response.status_code == 200
    items_by_id = {item["control_id"]: item for item in response.json()["items"]}
    assert {
        control_id
        for control_id, item in items_by_id.items()
        if item["supported_actions"]
    } == ACTIONABLE_CONTROL_IDS
    for control_id in ACTIONABLE_CONTROL_IDS:
        assert items_by_id[control_id]["supported_actions"] == [
            "apply_control",
            "rollback_control",
        ]

    assert items_by_id["control.windows.defender-real-time-protection"] == {
        "control_id": "control.windows.defender-real-time-protection",
        "title": "Windows Defender real-time protection",
        "platform": "windows",
        "kind": "benchmark_control",
        "observation_aliases": [
            "windows.defender.real-time-protection",
            "windows.defender.real_time_protection",
        ],
        "supported_actions": ["apply_control", "rollback_control"],
    }
    assert items_by_id["macos.disk.filevault-enabled"]["supported_actions"] == []
    assert items_by_id["macos.disk.filevault-enabled"]["kind"] == "benchmark_control"
    assert items_by_id["windows.telemetry.process-inventory"] == {
        "control_id": "windows.telemetry.process-inventory",
        "title": "Windows process inventory",
        "platform": "windows",
        "kind": "operational_observation",
        "observation_aliases": [],
        "supported_actions": [],
    }
