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


def heartbeat(client, endpoint_id: str, capabilities: list[str] | None = None) -> dict[str, object]:
    response = client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        json={
            "agent_version": "agent-test",
            "platform_version": "Ubuntu 24.04",
            "platform_profile": "linux-test",
            "connectivity_status": "online",
            "declared_capabilities": capabilities or ["heartbeat", "apply_control", "rollback_control"],
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
            "control_ids": ["linux.ssh.password-authentication-disabled"],
            "troubleshooting_scopes": [],
            "requested_by": "SHAna",
            "approved_by": "secops",
            "reason": "Contain risky inbound exposure",
            "expires_at": "2026-04-18T20:45:00Z",
        },
    )
    assert response.status_code == 201
    return response.json()["approval_grant_id"]


def claim_action(client, endpoint_id: str) -> dict[str, object]:
    response = client.post(f"/api/endpoints/{endpoint_id}/response-actions/claim", json={})
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    return items[0]


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
            "control_id": "linux.ssh.password-authentication-disabled",
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
    assert action["control_id"] == "linux.ssh.password-authentication-disabled"
    assert action["status"] == "queued"
    assert heartbeat(client, endpoint_id)["pending_action_count"] == 1

    pending = client.get(f"/api/endpoints/{endpoint_id}/response-actions")
    assert pending.status_code == 200
    assert [item["response_action_id"] for item in pending.json()["items"]] == [action["response_action_id"]]

    claimed = claim_action(client, endpoint_id)
    assert claimed["response_action_id"] == action["response_action_id"]
    assert claimed["status"] == "leased"
    assert claimed["attempt_count"] == 1
    assert isinstance(claimed["lease_token"], str)

    completed = client.post(
        f"/api/response-actions/{action['response_action_id']}/result",
        json={
            "status": "succeeded",
            "result_summary": "Firewall default deny applied and verified.",
            "lease_token": claimed["lease_token"],
        },
    )

    assert completed.status_code == 200
    assert completed.json()["status"] == "succeeded"
    assert completed.json()["completed_at"] == "2026-04-18T20:00:00Z"
    assert heartbeat(client, endpoint_id)["pending_action_count"] == 0
    assert client.get(f"/api/endpoints/{endpoint_id}/response-actions").json() == {"items": []}
    history = client.get(f"/api/endpoints/{endpoint_id}/response-actions?include_terminal=true")
    assert [item["response_action_id"] for item in history.json()["items"]] == [action["response_action_id"]]
    assert history.json()["items"][0]["status"] == "succeeded"


def test_response_action_accepts_only_matching_per_control_capability(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    approval_grant_id = create_grant(client, endpoint_id)
    heartbeat(
        client,
        endpoint_id,
        capabilities=["heartbeat", "apply_control:linux.ssh.password-authentication-disabled"],
    )

    queued = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": approval_grant_id,
            "action": "apply_control",
            "control_id": "linux.ssh.password-authentication-disabled",
            "requested_by": "SHAna",
            "reason": "Run approved containment playbook step",
        },
    )
    assert queued.status_code == 201

    other_grant = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["apply_control"],
            "control_ids": ["linux.network.endpoint-isolated"],
            "troubleshooting_scopes": [],
            "requested_by": "SHAna",
            "approved_by": "secops",
            "reason": "Test control scoping",
            "expires_at": "2026-04-18T20:45:00Z",
        },
    )
    assert other_grant.status_code == 201
    refused = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": other_grant.json()["approval_grant_id"],
            "action": "apply_control",
            "control_id": "linux.network.endpoint-isolated",
            "requested_by": "SHAna",
            "reason": "Must not pass a different scoped capability",
        },
    )
    assert refused.status_code == 422
    assert refused.json() == {"detail": "endpoint has not declared action capability"}


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
            "control_id": "linux.ssh.password-authentication-disabled",
            "requested_by": "SHAna",
            "reason": "Run approved containment playbook step",
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "endpoint has not declared action capability"}


def test_collect_remediation_evidence_action_does_not_require_scope(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    heartbeat(client, endpoint_id, capabilities=["heartbeat", "collect_remediation_evidence"])
    grant = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["request_elevated_troubleshooting", "collect_remediation_evidence"],
            "control_ids": [],
            "troubleshooting_scopes": ["process_inventory"],
            "requested_by": "SHAna",
            "approved_by": "secops",
            "reason": "Collect bounded remediation evidence",
            "expires_at": "2026-04-18T20:45:00Z",
        },
    )
    assert grant.status_code == 201

    queued = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": grant.json()["approval_grant_id"],
            "action": "collect_remediation_evidence",
            "requested_by": "SHAna",
            "reason": "Collect post-change evidence",
        },
    )

    assert queued.status_code == 201
    assert queued.json()["action"] == "collect_remediation_evidence"
    assert queued.json()["troubleshooting_scope"] is None
    assert queued.json()["control_id"] is None


def test_response_action_claim_is_exclusive_and_completion_replay_is_idempotent(
    db_path, make_client, monkeypatch
):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    heartbeat(client, endpoint_id)
    approval_grant_id = create_grant(client, endpoint_id)
    queued = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": approval_grant_id,
            "action": "apply_control",
            "control_id": "linux.ssh.password-authentication-disabled",
            "reason": "Apply once despite polling overlap",
        },
    )
    assert queued.status_code == 201

    claimed = claim_action(client, endpoint_id)
    second_claim = client.post(f"/api/endpoints/{endpoint_id}/response-actions/claim", json={})
    assert second_claim.status_code == 200
    assert second_claim.json() == {"items": []}

    result_payload = {
        "status": "succeeded",
        "result_summary": "Applied and verified once.",
        "lease_token": claimed["lease_token"],
    }
    completed = client.post(
        f"/api/response-actions/{queued.json()['response_action_id']}/result",
        json=result_payload,
    )
    replayed = client.post(
        f"/api/response-actions/{queued.json()['response_action_id']}/result",
        json=result_payload,
    )
    assert completed.status_code == 200
    assert replayed.status_code == 200
    assert replayed.json() == completed.json()

    conflicting_replay = client.post(
        f"/api/response-actions/{queued.json()['response_action_id']}/result",
        json={**result_payload, "result_summary": "Different result."},
    )
    assert conflicting_replay.status_code == 409
    assert conflicting_replay.json() == {"detail": "response action is already terminal"}


def test_expired_response_action_lease_is_reclaimed_and_stale_result_is_rejected(
    db_path, make_client, monkeypatch
):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    heartbeat(client, endpoint_id)
    approval_grant_id = create_grant(client, endpoint_id)
    queued = client.post(
        "/api/response-actions",
        json={
            "endpoint_id": endpoint_id,
            "approval_grant_id": approval_grant_id,
            "action": "apply_control",
            "control_id": "linux.ssh.password-authentication-disabled",
            "reason": "Exercise lease recovery",
        },
    )
    assert queued.status_code == 201
    first_claim = claim_action(client, endpoint_id)

    set_now(monkeypatch, "2026-04-18T20:02:01Z")
    assert heartbeat(client, endpoint_id)["pending_action_count"] == 1
    second_claim = claim_action(client, endpoint_id)
    assert second_claim["response_action_id"] == first_claim["response_action_id"]
    assert second_claim["attempt_count"] == 2
    assert second_claim["lease_token"] != first_claim["lease_token"]

    stale = client.post(
        f"/api/response-actions/{queued.json()['response_action_id']}/result",
        json={
            "status": "succeeded",
            "result_summary": "Stale worker result.",
            "lease_token": first_claim["lease_token"],
        },
    )
    assert stale.status_code == 409
    assert stale.json() == {"detail": "response action lease does not match"}

    completed = client.post(
        f"/api/response-actions/{queued.json()['response_action_id']}/result",
        json={
            "status": "succeeded",
            "result_summary": "Current worker result.",
            "lease_token": second_claim["lease_token"],
        },
    )
    assert completed.status_code == 200
    assert completed.json()["attempt_count"] == 2


def test_response_action_enqueue_idempotency_key_replays_only_identical_request(
    db_path, make_client, monkeypatch
):
    client = make_client(db_path)
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    endpoint_id = enroll_endpoint(client)
    heartbeat(client, endpoint_id)
    approval_grant_id = create_grant(client, endpoint_id)
    payload = {
        "endpoint_id": endpoint_id,
        "approval_grant_id": approval_grant_id,
        "action": "apply_control",
        "control_id": "linux.ssh.password-authentication-disabled",
        "idempotency_key": "incident-42-ssh-hardening",
        "reason": "Apply approved SSH hardening",
    }

    first = client.post("/api/response-actions", json=payload)
    replay = client.post("/api/response-actions", json=payload)
    conflict = client.post(
        "/api/response-actions",
        json={**payload, "reason": "A different operation must not reuse the key"},
    )

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json() == first.json()
    assert first.json()["idempotency_key"] == "incident-42-ssh-hardening"
    assert conflict.status_code == 409
    assert conflict.json() == {
        "detail": "idempotency_key is already bound to a different response action"
    }
