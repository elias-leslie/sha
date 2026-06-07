from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

from app.api.endpoints import approvals as approvals_module

UTC = timezone.utc


def enroll_endpoint(client, **overrides):
    payload = {
        "agent_fingerprint": "  AA:BB:CC:DD  ",
        "hostname": "  workstation-01  ",
        "platform": "windows",
        "platform_version": "11 23H2",
        "agent_version": "1.0.0",
        "tenant_id": None,
        "site_id": None,
    }
    payload.update(overrides)
    return client.post("/api/endpoints/enroll", json=payload)


def set_now(monkeypatch, value: str) -> None:
    current = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    monkeypatch.setattr(approvals_module, "utc_now", lambda: current)


def create_request(client, endpoint_id: str, **overrides):
    payload = {
        "endpoint_ids": [endpoint_id],
        "request_kind": "hardening_change",
        "requested_actions": ["apply_control"],
        "control_ids": [" control.rdp-network-level-authentication "],
        "troubleshooting_scopes": [],
        "requested_ttl_minutes": 60,
        "requested_by": "  SHAna  ",
        "reason": "  Tighten RDP posture  ",
        "risk": "high",
    }
    payload.update(overrides)
    return client.post("/api/approval-requests", json=payload)


def approve_request(client, approval_request_id: str, **overrides):
    payload = {
        "decision": "approve",
        "decided_by": "  secops  ",
        "decision_comment": "  Approved for rollout  ",
        "expires_at": "2026-04-18T20:45:00+00:00",
    }
    payload.update(overrides)
    return client.post(f"/api/approval-requests/{approval_request_id}/decisions", json=payload)


def test_create_hardening_request_persists_pending_request_and_requested_audit_event(
    db_path, make_client, monkeypatch
):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")

    response = create_request(client, endpoint_id)

    assert response.status_code == 201
    body = response.json()
    assert body["approval_request_id"].startswith("apr_")
    assert body["endpoint_ids"] == [endpoint_id]
    assert body["request_kind"] == "hardening_change"
    assert body["requested_actions"] == ["apply_control"]
    assert body["control_ids"] == ["control.rdp-network-level-authentication"]
    assert body["troubleshooting_scopes"] == []
    assert body["requested_ttl_minutes"] == 60
    assert body["requested_by"] == "SHAna"
    assert body["reason"] == "Tighten RDP posture"
    assert body["risk"] == "high"
    assert body["status"] == "pending"
    assert body["decision_by"] is None
    assert body["decision_comment"] is None
    assert body["decision_at"] is None
    assert body["approval_grant_id"] is None
    assert body["created_at"] == "2026-04-18T20:00:00Z"
    assert body["updated_at"] == "2026-04-18T20:00:00Z"
    assert body["audit_events"] == [
        {
            "approval_event_id": body["audit_events"][0]["approval_event_id"],
            "event_type": "requested",
            "actor": "SHAna",
            "comment": "Tighten RDP posture",
            "created_at": "2026-04-18T20:00:00Z",
        }
    ]


def test_create_request_uses_endpoint_table_for_unknown_id_validation_before_duplicates(
    db_path, make_client, monkeypatch
):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")

    response = create_request(
        client,
        endpoint_id,
        endpoint_ids=[f" {endpoint_id} ", f" {endpoint_id} ", " ep_missing "],
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "one or more endpoint_ids were not found"}


def test_elevated_troubleshooting_request_requires_bounded_action_scope(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")

    response = create_request(
        client,
        endpoint_id,
        request_kind="elevated_troubleshooting",
        requested_actions=["inspect_control"],
        control_ids=[],
        troubleshooting_scopes=["security_logs"],
    )

    assert response.status_code == 422


def test_approve_request_creates_linked_grant_and_normalizes_expiry(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    created = create_request(client, endpoint_id)
    approval_request_id = created.json()["approval_request_id"]

    set_now(monkeypatch, "2026-04-18T20:05:00Z")
    approved = approve_request(
        client,
        approval_request_id,
        expires_at="2026-04-18T21:45:00+01:00",
    )

    assert approved.status_code == 200
    body = approved.json()
    assert body["status"] == "approved"
    assert body["decision_by"] == "secops"
    assert body["decision_comment"] == "Approved for rollout"
    assert body["decision_at"] == "2026-04-18T20:05:00Z"
    assert body["approval_grant_id"].startswith("grant_")
    assert [event["event_type"] for event in body["audit_events"]] == ["requested", "approved"]

    grants = client.get("/api/approval-grants")
    assert grants.status_code == 200
    assert grants.json() == {
        "items": [
            {
                "approval_grant_id": body["approval_grant_id"],
                "approval_request_id": approval_request_id,
                "endpoint_ids": [endpoint_id],
                "allowed_actions": ["apply_control"],
                "control_ids": ["control.rdp-network-level-authentication"],
                "troubleshooting_scopes": [],
                "requested_by": "SHAna",
                "approved_by": "secops",
                "reason": "Tighten RDP posture",
                "expires_at": "2026-04-18T20:45:00Z",
                "status": "approved",
                "created_at": "2026-04-18T20:05:00Z",
                "updated_at": "2026-04-18T20:05:00Z",
            }
        ]
    }


def test_approve_request_rejects_expiry_outside_requested_ttl_window(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    created = create_request(client, endpoint_id, requested_ttl_minutes=30)
    approval_request_id = created.json()["approval_request_id"]

    set_now(monkeypatch, "2026-04-18T20:05:00Z")
    response = approve_request(
        client,
        approval_request_id,
        expires_at="2026-04-18T20:40:01Z",
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "expires_at must be within requested_ttl_minutes of decision time"
    }


def test_decision_route_rejects_replay_after_request_is_terminal(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    approval_request_id = create_request(client, endpoint_id).json()["approval_request_id"]

    set_now(monkeypatch, "2026-04-18T20:05:00Z")
    assert approve_request(client, approval_request_id).status_code == 200

    set_now(monkeypatch, "2026-04-18T20:06:00Z")
    replay = approve_request(client, approval_request_id)

    assert replay.status_code == 409
    assert replay.json() == {
        "detail": "approval request is not in a state that allows this decision"
    }


def test_decision_route_returns_conflict_when_a_linked_grant_was_created_by_a_racing_writer(
    db_path, make_client, monkeypatch
):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    created = create_request(client, endpoint_id)
    approval_request_id = created.json()["approval_request_id"]

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO approval_grants (
                approval_grant_id,
                approval_request_id,
                endpoint_ids,
                allowed_actions,
                control_ids,
                troubleshooting_scopes,
                requested_by,
                approved_by,
                reason,
                expires_at,
                status,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "grant_racewinner",
                approval_request_id,
                '["%s"]' % endpoint_id,
                '["apply_control"]',
                '["control.rdp-network-level-authentication"]',
                '[]',
                'SHAna',
                'secops',
                'Tighten RDP posture',
                '2026-04-18T20:45:00Z',
                'approved',
                '2026-04-18T20:05:00Z',
                '2026-04-18T20:05:00Z',
            ),
        )
        connection.commit()

    set_now(monkeypatch, "2026-04-18T20:05:00Z")
    response = approve_request(client, approval_request_id)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "approval request is not in a state that allows this decision"
    }


def test_list_routes_lazily_expire_request_backed_and_manual_grants_once(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")
    approval_request_id = create_request(client, endpoint_id).json()["approval_request_id"]

    set_now(monkeypatch, "2026-04-18T20:05:00Z")
    approved = approve_request(client, approval_request_id, expires_at="2026-04-18T20:10:00Z")
    approval_grant_id = approved.json()["approval_grant_id"]

    manual = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["request_elevated_troubleshooting", "inspect_control"],
            "control_ids": [],
            "troubleshooting_scopes": ["security_logs"],
            "requested_by": "ops",
            "approved_by": "secops",
            "reason": "Collect emergency logs",
            "expires_at": "2026-04-18T20:10:00Z",
        },
    )
    assert manual.status_code == 201
    manual_grant_id = manual.json()["approval_grant_id"]

    set_now(monkeypatch, "2026-04-18T20:11:00Z")
    expired_requests = client.get("/api/approval-requests")
    expired_grants = client.get("/api/approval-grants")
    repeated_requests = client.get("/api/approval-requests")

    assert expired_requests.status_code == 200
    assert expired_grants.status_code == 200
    request_items = expired_requests.json()["items"]
    assert request_items[0]["status"] == "expired"
    assert [event["event_type"] for event in request_items[0]["audit_events"]] == [
        "requested",
        "approved",
        "expired",
    ]
    assert request_items[0]["audit_events"][-1]["comment"] == "Grant expired automatically."

    repeated_items = repeated_requests.json()["items"]
    assert [event["event_type"] for event in repeated_items[0]["audit_events"]] == [
        "requested",
        "approved",
        "expired",
    ]

    grant_items = expired_grants.json()["items"]
    expected_grants = [
        {
            "approval_grant_id": approval_grant_id,
            "approval_request_id": approval_request_id,
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["apply_control"],
            "control_ids": ["control.rdp-network-level-authentication"],
            "troubleshooting_scopes": [],
            "requested_by": "SHAna",
            "approved_by": "secops",
            "reason": "Tighten RDP posture",
            "expires_at": "2026-04-18T20:10:00Z",
            "status": "expired",
            "created_at": "2026-04-18T20:05:00Z",
            "updated_at": "2026-04-18T20:11:00Z",
        },
        {
            "approval_grant_id": manual_grant_id,
            "approval_request_id": None,
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["request_elevated_troubleshooting", "inspect_control"],
            "control_ids": [],
            "troubleshooting_scopes": ["security_logs"],
            "requested_by": "ops",
            "approved_by": "secops",
            "reason": "Collect emergency logs",
            "expires_at": "2026-04-18T20:10:00Z",
            "status": "expired",
            "created_at": "2026-04-18T20:05:00Z",
            "updated_at": "2026-04-18T20:11:00Z",
        },
    ]
    assert grant_items == sorted(
        expected_grants,
        key=lambda item: (item["created_at"], item["approval_grant_id"]),
    )


def test_manual_grants_reject_mixed_hardening_and_troubleshooting_signals(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")

    response = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["request_elevated_troubleshooting", "apply_control"],
            "control_ids": ["control.rdp-network-level-authentication"],
            "troubleshooting_scopes": ["security_logs"],
            "requested_by": "ops",
            "approved_by": "secops",
            "reason": "Do both",
            "expires_at": "2026-04-18T20:20:00Z",
        },
    )

    assert response.status_code == 422


def test_manual_grants_reject_expired_expires_at(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = enroll_endpoint(client).json()["endpoint_id"]
    set_now(monkeypatch, "2026-04-18T20:00:00Z")

    response = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["apply_control"],
            "control_ids": ["control.windows.rdp-network-level-authentication"],
            "troubleshooting_scopes": [],
            "requested_by": "ops",
            "approved_by": "secops",
            "reason": "Late emergency change",
            "expires_at": "2026-04-18T19:59:59Z",
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "expires_at must be in the future"}
