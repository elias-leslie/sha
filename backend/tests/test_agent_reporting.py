from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

from app.api.endpoints import endpoints as endpoints_module

UTC = timezone.utc


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


def set_now(monkeypatch, value: str) -> None:
    current = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    monkeypatch.setattr(endpoints_module, "utc_now", lambda: current)


def test_endpoint_heartbeat_persists_capabilities_and_execution_hooks(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T22:00:00Z")

    response = client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        json={
            "agent_version": " 1.2.0 ",
            "platform_version": " 11 24H2 ",
            "platform_profile": " windows-workstation ",
            "connectivity_status": "online",
            "declared_capabilities": [
                "heartbeat",
                "collect_posture_snapshot",
                "inspect_control",
                "apply_control",
                "rollback_control",
            ],
            "execution_hooks": {
                "captures_rollback_artifacts": True,
                "reports_execution_results": True,
                "supports_dry_run": True,
            },
        },
    )

    assert response.status_code == 202
    assert response.json() == {
        "endpoint_id": endpoint_id,
        "status": "active",
        "connectivity_status": "online",
        "last_seen_at": "2026-04-18T22:00:00Z",
        "last_heartbeat_at": "2026-04-18T22:00:00Z",
        "accepted_capability_count": 5,
        "pending_action_count": 0,
        "created_at": response.json()["created_at"],
        "updated_at": "2026-04-18T22:00:00Z",
    }

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT agent_version, platform_version, platform_profile, connectivity_status, declared_capabilities_json, execution_hooks_json, last_seen_at, last_heartbeat_at FROM endpoints WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()

    assert row == (
        "1.2.0",
        "11 24H2",
        "windows-workstation",
        "online",
        '["apply_control","collect_posture_snapshot","heartbeat","inspect_control","rollback_control"]',
        '{"captures_rollback_artifacts":true,"reports_execution_results":true,"supports_dry_run":true}',
        "2026-04-18T22:00:00Z",
        "2026-04-18T22:00:00Z",
    )


def test_endpoint_collection_and_detail_include_latest_posture_summary_and_results(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client, platform="linux", platform_version="Ubuntu 24.04").json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T22:05:00Z")
    heartbeat = client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        json={
            "agent_version": "1.0.1",
            "platform_version": "Ubuntu 24.04.1 LTS",
            "platform_profile": "linux-server",
            "connectivity_status": "degraded",
            "declared_capabilities": [
                "heartbeat",
                "collect_posture_snapshot",
                "inspect_control",
                "collect_security_context",
                "request_elevated_troubleshooting",
            ],
            "execution_hooks": {
                "captures_rollback_artifacts": False,
                "reports_execution_results": True,
                "supports_dry_run": True,
            },
        },
    )
    assert heartbeat.status_code == 202

    posture = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-04-18T22:03:00+00:00",
            "platform_profile": "linux-server",
            "results": [
                {
                    "control_key": "ssh.disable-password-authentication",
                    "status": "fail",
                    "current_value": "yes",
                    "recommended_value": "no",
                    "severity": "high",
                    "evidence_summary": "PasswordAuthentication is enabled.",
                    "reboot_required": False,
                },
                {
                    "control_key": "journald.storage-persistent",
                    "status": "warn",
                    "current_value": "volatile",
                    "recommended_value": "persistent",
                    "severity": "medium",
                    "evidence_summary": "journald still stores logs in /run.",
                    "reboot_required": False,
                },
                {
                    "control_key": "ufw.enabled",
                    "status": "pass",
                    "current_value": "enabled",
                    "recommended_value": "enabled",
                    "severity": None,
                    "evidence_summary": "UFW is already enabled.",
                    "reboot_required": False,
                },
            ],
        },
    )
    assert posture.status_code == 202
    snapshot_id = posture.json()["snapshot_id"]

    collection = client.get("/api/endpoints")
    detail = client.get(f"/api/endpoints/{endpoint_id}")

    assert collection.status_code == 200
    assert detail.status_code == 200
    assert collection.json() == {
        "items": [
            {
                "endpoint_id": endpoint_id,
                "hostname": "workstation-01",
                "platform": "linux",
                "platform_version": "Ubuntu 24.04.1 LTS",
                "agent_version": "1.0.1",
                "tenant_id": "tenant-a",
                "site_id": "site-a",
                "status": "active",
                "connectivity_status": "degraded",
                "last_seen_at": "2026-04-18T22:05:00Z",
                "last_heartbeat_at": "2026-04-18T22:05:00Z",
                "created_at": collection.json()["items"][0]["created_at"],
                "updated_at": "2026-04-18T22:05:00Z",
                "last_platform_profile": "linux-server",
                "declared_capabilities": [
                    "collect_posture_snapshot",
                    "collect_security_context",
                    "heartbeat",
                    "inspect_control",
                    "request_elevated_troubleshooting",
                ],
                "execution_hooks": {
                    "captures_rollback_artifacts": False,
                    "reports_execution_results": True,
                    "supports_dry_run": True,
                },
                "latest_posture_summary": {
                    "snapshot_id": snapshot_id,
                    "observed_at": "2026-04-18T22:03:00Z",
                    "platform_profile": "linux-server",
                    "pass_count": 1,
                    "fail_count": 1,
                    "warn_count": 1,
                    "error_count": 0,
                    "not_applicable_count": 0,
                    "reboot_required_count": 0,
                },
            }
        ]
    }
    assert detail.json() == {
        **collection.json()["items"][0],
        "latest_results": [
            {
                "control_key": "journald.storage-persistent",
                "status": "warn",
                "current_value": "volatile",
                "recommended_value": "persistent",
                "severity": "medium",
                "evidence_summary": "journald still stores logs in /run.",
                "reboot_required": False,
            },
            {
                "control_key": "ssh.disable-password-authentication",
                "status": "fail",
                "current_value": "yes",
                "recommended_value": "no",
                "severity": "high",
                "evidence_summary": "PasswordAuthentication is enabled.",
                "reboot_required": False,
            },
            {
                "control_key": "ufw.enabled",
                "status": "pass",
                "current_value": "enabled",
                "recommended_value": "enabled",
                "severity": None,
                "evidence_summary": "UFW is already enabled.",
                "reboot_required": False,
            },
        ],
    }


def test_heartbeat_rejects_duplicate_capabilities_and_unknown_endpoints(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T22:10:00Z")

    duplicate_capabilities = client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        json={
            "agent_version": "1.0.0",
            "platform_profile": "windows-workstation",
            "connectivity_status": "online",
            "declared_capabilities": ["heartbeat", " heartbeat "],
            "execution_hooks": {
                "captures_rollback_artifacts": True,
                "reports_execution_results": True,
                "supports_dry_run": False,
            },
        },
    )
    missing_endpoint = client.post(
        "/api/endpoints/ep_missing/heartbeat",
        json={
            "agent_version": "1.0.0",
            "platform_profile": "windows-workstation",
            "connectivity_status": "online",
            "declared_capabilities": ["heartbeat"],
            "execution_hooks": {
                "captures_rollback_artifacts": True,
                "reports_execution_results": True,
                "supports_dry_run": False,
            },
        },
    )

    assert duplicate_capabilities.status_code == 422
    assert duplicate_capabilities.json() == {"detail": "duplicate declared_capabilities are not allowed"}
    assert missing_endpoint.status_code == 404
    assert missing_endpoint.json() == {"detail": "endpoint not found"}
