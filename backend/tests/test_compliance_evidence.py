from __future__ import annotations

from datetime import datetime, timezone

from app.api.endpoints import approvals as approvals_module
from app.api.endpoints import endpoints as endpoints_module
from app.api.endpoints import evidence as evidence_module
from app.api.endpoints import posture as posture_module
from app.api.endpoints import response_actions as response_actions_module

UTC = timezone.utc


def set_now(monkeypatch, value: str) -> None:
    current = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    for module in (approvals_module, endpoints_module, evidence_module, posture_module, response_actions_module):
        monkeypatch.setattr(module, "utc_now", lambda: current)


def test_compliance_evidence_export_links_posture_approvals_and_actions(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")

    endpoint = client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": "linux-evidence-agent",
            "hostname": "linux-evidence-01",
            "platform": "linux",
            "platform_version": "Ubuntu 24.04",
            "agent_version": "agent-test",
        },
    ).json()
    endpoint_id = endpoint["endpoint_id"]

    assert client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        json={
            "agent_version": "agent-test",
            "platform_version": "Ubuntu 24.04",
            "platform_profile": "linux-server",
            "connectivity_status": "online",
            "declared_capabilities": ["heartbeat", "apply_control"],
            "execution_hooks": {
                "captures_rollback_artifacts": True,
                "reports_execution_results": True,
                "supports_dry_run": True,
            },
        },
    ).status_code == 202

    assert client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-04-18T19:59:00Z",
            "platform_profile": "linux-server",
            "results": [
                {
                    "control_key": "linux.ssh.password-authentication-disabled",
                    "status": "fail",
                    "current_value": "yes",
                    "recommended_value": "no",
                    "severity": "high",
                    "evidence_summary": "PasswordAuthentication is enabled.",
                    "reboot_required": False,
                }
            ],
        },
    ).status_code == 202

    request = client.post(
        "/api/approval-requests",
        json={
            "endpoint_ids": [endpoint_id],
            "request_kind": "hardening_change",
            "requested_actions": ["apply_control"],
            "control_ids": ["linux.ssh.password-authentication-disabled"],
            "troubleshooting_scopes": [],
            "requested_ttl_minutes": 60,
            "requested_by": "SHAna",
            "reason": "Disable SSH password authentication",
            "risk": "high",
        },
    ).json()
    set_now(monkeypatch, "2026-04-18T20:05:00Z")
    approved = client.post(
        f"/api/approval-requests/{request['approval_request_id']}/decisions",
        json={
            "decision": "approve",
            "decided_by": "secops",
            "decision_comment": "Approved for maintenance window",
            "expires_at": "2026-04-18T20:45:00Z",
        },
    ).json()

    action = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": approved["approval_grant_id"],
            "action": "apply_control",
            "control_id": "linux.ssh.password-authentication-disabled",
            "requested_by": "SHAna",
            "reason": "Run approved SSH hardening",
        },
    ).json()
    assert client.post(
        f"/api/response-actions/{action['response_action_id']}/result",
        json={"status": "succeeded", "result_summary": "SSH password authentication disabled."},
    ).status_code == 200

    export = client.get("/api/compliance/evidence")

    assert export.status_code == 200
    payload = export.json()
    assert payload["exported_at"] == "2026-04-18T20:05:00Z"
    assert payload["source_catalog"]["pack_count"] == 4
    assert payload["source_catalog"]["control_count"] == 17
    assert payload["endpoints"][0]["endpoint_id"] == endpoint_id
    assert payload["posture_snapshots"][0]["results"][0]["control_key"] == "linux.ssh.password-authentication-disabled"
    assert payload["posture_snapshots"][0]["results"][0]["evidence_summary"] == "PasswordAuthentication is enabled."
    assert payload["approval_requests"][0]["audit_events"][1]["event_type"] == "approved"
    assert payload["approval_grants"][0]["approval_grant_id"] == approved["approval_grant_id"]
    assert payload["response_actions"][0]["result_summary"] == "SSH password authentication disabled."
