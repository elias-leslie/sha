from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

from app.api.endpoints import approvals as approvals_module

UTC = timezone.utc


def set_approval_now(monkeypatch, value: str) -> None:
    current = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    monkeypatch.setattr(approvals_module, "utc_now", lambda: current)


def enroll_endpoint(client, **overrides):
    payload = {
        "agent_fingerprint": "  AA:BB:CC:DD  ",
        "hostname": "  workstation-01  ",
        "platform": "windows",
        "platform_version": "11 23H2",
        "agent_version": "1.0.0",
        "tenant_id": "tenant-a",
        "site_id": "site-a",
    }
    payload.update(overrides)
    return client.post("/api/endpoints/enroll", json=payload)


def test_enrollment_is_idempotent_and_normalizes_fingerprint(db_path, make_client):
    client = make_client(db_path)

    first = enroll_endpoint(client)
    second = enroll_endpoint(
        client,
        agent_fingerprint="aa:bb:cc:dd",
        hostname="  workstation-01-renamed  ",
    )

    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["endpoint_id"] == second.json()["endpoint_id"]
    assert first.json()["status"] == "active"
    assert second.json()["status"] == "active"
    assert second.json()["agent_fingerprint"] == "aa:bb:cc:dd"
    assert second.json()["hostname"] == "workstation-01-renamed"
    assert second.json()["tenant_id"] == "tenant-a"
    assert second.json()["site_id"] == "site-a"
    assert second.json()["platform_version"] == "11 23H2"


def test_reenroll_can_clear_optional_fields_with_explicit_null(db_path, make_client):
    client = make_client(db_path)

    first = enroll_endpoint(client)
    second = enroll_endpoint(client, platform_version=None, tenant_id=None, site_id=None)

    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["platform_version"] is None
    assert second.json()["tenant_id"] is None
    assert second.json()["site_id"] is None


def test_reenroll_rejects_cross_platform_fingerprint_reuse(db_path, make_client):
    client = make_client(db_path)
    enroll_endpoint(client)

    response = enroll_endpoint(client, platform="linux")

    assert response.status_code == 409
    assert response.json() == {
        "detail": "agent fingerprint already enrolled for a different platform"
    }


def test_posture_snapshot_persists_results_and_ack_count(db_path, make_client):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]

    response = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-04-18T14:00:00+02:00",
            "platform_profile": "windows-workstation",
            "results": [
                {
                    "control_key": " SSH-ROOT ",
                    "status": "fail",
                    "current_value": "enabled",
                    "recommended_value": "disabled",
                    "severity": "high",
                    "evidence_summary": "Root login is enabled",
                    "reboot_required": False,
                },
                {
                    "control_key": "Firewall-All-Profiles",
                    "status": "pass",
                    "current_value": "enabled",
                    "recommended_value": "enabled",
                    "severity": None,
                    "evidence_summary": "Firewall already enabled",
                    "reboot_required": False,
                },
            ],
        },
    )

    body = response.json()

    assert response.status_code == 202
    assert body["endpoint_id"] == endpoint_id
    assert body["snapshot_id"].startswith("snap_")
    assert body["accepted_result_count"] == 2
    assert body["observed_at"] == "2026-04-18T12:00:00Z"
    assert body["created_at"].endswith("Z")

    with sqlite3.connect(db_path) as connection:
        snapshot_count = connection.execute(
            "SELECT COUNT(*) FROM posture_snapshots"
        ).fetchone()[0]
        result_rows = connection.execute(
            "SELECT control_key, current_value, recommended_value, severity, evidence_summary, reboot_required FROM posture_results ORDER BY control_key ASC"
        ).fetchall()

    assert snapshot_count == 1
    assert result_rows == [
        (
            "Firewall-All-Profiles",
            "enabled",
            "enabled",
            None,
            "Firewall already enabled",
            0,
        ),
        (
            "SSH-ROOT",
            "enabled",
            "disabled",
            "high",
            "Root login is enabled",
            0,
        ),
    ]


def test_collection_routes_use_persisted_rows_across_fresh_clients(db_path, make_client, monkeypatch):
    set_approval_now(monkeypatch, "2026-04-18T20:00:00Z")
    first_client = make_client(db_path)
    endpoint_id = enroll_endpoint(first_client).json()["endpoint_id"]

    created_installer = first_client.post(
        "/api/installer-profiles",
        json={
            "name": "  Windows Stable  ",
            "platform": "windows",
            "channel": "stable",
            "control_plane_url": "https://sha.example.test/control",
            "policy_mode": "safe_auto",
            "tenant_id": None,
            "site_id": "site-a",
        },
    ).json()
    created_grant_response = first_client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [f" {endpoint_id} "],
            "allowed_actions": ["apply_control"],
            "control_ids": [" control.rdp-network-level-authentication "],
            "troubleshooting_scopes": [],
            "requested_by": "  shana  ",
            "approved_by": "  secops  ",
            "reason": "  Investigate control drift  ",
            "expires_at": "2026-04-19T16:00:00+02:00",
        },
    )

    assert created_grant_response.status_code == 201
    created_grant = created_grant_response.json()

    set_approval_now(monkeypatch, "2026-04-18T20:10:00Z")
    second_client = make_client(db_path)
    installers = second_client.get("/api/installer-profiles")
    approvals = second_client.get("/api/approval-grants")

    assert installers.status_code == 200
    assert approvals.status_code == 200
    assert installers.json() == {"items": [created_installer]}
    assert approvals.json() == {"items": [created_grant]}
    assert created_installer["name"] == "Windows Stable"
    assert created_grant["approval_request_id"] is None
    assert created_grant["endpoint_ids"] == [endpoint_id]
    assert created_grant["allowed_actions"] == ["apply_control"]
    assert created_grant["control_ids"] == ["control.rdp-network-level-authentication"]
    assert created_grant["troubleshooting_scopes"] == []
    assert created_grant["requested_by"] == "shana"
    assert created_grant["approved_by"] == "secops"
    assert created_grant["reason"] == "Investigate control drift"
    assert created_grant["status"] == "approved"
    assert created_grant["expires_at"] == "2026-04-19T14:00:00Z"


def test_collection_routes_return_empty_items_envelopes(db_path, make_client):
    client = make_client(db_path)

    installers = client.get("/api/installer-profiles")
    approvals = client.get("/api/approval-grants")

    assert installers.json() == {"items": []}
    assert approvals.json() == {"items": []}
