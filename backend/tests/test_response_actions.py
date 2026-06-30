from __future__ import annotations

from datetime import datetime, timezone

from app.api.endpoints import approvals as approvals_module
from app.api.endpoints import endpoints as endpoints_module
from app.api.endpoints import response_actions as response_actions_module

UTC = timezone.utc


def set_now(monkeypatch, value: str) -> None:
    current = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    monkeypatch.setattr(approvals_module, "utc_now", lambda: current)
    monkeypatch.setattr(endpoints_module, "utc_now", lambda: current)
    monkeypatch.setattr(response_actions_module, "utc_now", lambda: current)


def enroll_endpoint(client) -> str:
    response = client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": "linux-action-agent",
            "hostname": "linux-ir-01",
            "platform": "linux",
            "platform_version": "Ubuntu 24.04",
            "agent_version": "agent-test",
        },
    )
    assert response.status_code == 201
    return response.json()["endpoint_id"]


def heartbeat(client, endpoint_id: str) -> dict[str, object]:
    response = client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        json={
            "agent_version": "agent-test",
            "platform_version": "Ubuntu 24.04",
            "platform_profile": "linux-test",
            "connectivity_status": "online",
            "declared_capabilities": ["heartbeat", "apply_control", "rollback_control"],
            "execution_hooks": {
                "captures_rollback_artifacts": True,
                "reports_execution_results": True,
                "supports_dry_run": True,
            },
        },
    )
    assert response.status_code == 202
    return response.json()


def create_grant(client, endpoint_id: str) -> str:
    response = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["apply_control"],
            "control_ids": ["control.linux.firewall-default-deny"],
            "troubleshooting_scopes": [],
            "requested_by": "SHAna",
            "approved_by": "secops",
            "reason": "Contain risky inbound exposure",
            "expires_at": "2026-04-18T20:45:00Z",
        },
    )
    assert response.status_code == 201
    return response.json()["approval_grant_id"]


def test_response_action_queue_requires_active_grant_and_drives_heartbeat_count(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    assert heartbeat(client, endpoint_id)["pending_action_count"] == 0
    approval_grant_id = create_grant(client, endpoint_id)

    queued = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": approval_grant_id,
            "action": "apply_control",
            "control_id": "control.linux.firewall-default-deny",
            "requested_by": "SHAna",
            "reason": "Run approved containment playbook step",
        },
    )

    assert queued.status_code == 201
    action = queued.json()
    assert action["response_action_id"].startswith("act_")
    assert action["endpoint_id"] == endpoint_id
    assert action["approval_grant_id"] == approval_grant_id
    assert action["action"] == "apply_control"
    assert action["control_id"] == "control.linux.firewall-default-deny"
    assert action["status"] == "queued"
    assert heartbeat(client, endpoint_id)["pending_action_count"] == 1

    pending = client.get(f"/api/endpoints/{endpoint_id}/response-actions")
    assert pending.status_code == 200
    assert [item["response_action_id"] for item in pending.json()["items"]] == [action["response_action_id"]]

    completed = client.post(
        f"/api/response-actions/{action['response_action_id']}/result",
        json={"status": "succeeded", "result_summary": "Firewall default deny applied and verified."},
    )

    assert completed.status_code == 200
    assert completed.json()["status"] == "succeeded"
    assert completed.json()["completed_at"] == "2026-04-18T20:00:00Z"
    assert heartbeat(client, endpoint_id)["pending_action_count"] == 0
    assert client.get(f"/api/endpoints/{endpoint_id}/response-actions").json() == {"items": []}


def test_response_action_rejects_missing_endpoint_capability(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    approval_grant_id = create_grant(client, endpoint_id)

    response = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": approval_grant_id,
            "action": "apply_control",
            "control_id": "control.linux.firewall-default-deny",
            "requested_by": "SHAna",
            "reason": "Run approved containment playbook step",
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "endpoint has not declared action capability"}
