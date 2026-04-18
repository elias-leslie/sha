from __future__ import annotations


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


def test_posture_snapshot_rejects_duplicate_control_keys_case_insensitively(db_path, make_client):
    client = make_client(db_path)
    enroll_response = enroll_endpoint(client)
    endpoint_id = enroll_response.json()["endpoint_id"]

    response = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-04-18T14:00:00+02:00",
            "platform_profile": "windows-workstation",
            "results": [
                {
                    "control_key": "SSH-ROOT",
                    "status": "fail",
                    "evidence_summary": "Root login still enabled",
                    "reboot_required": False,
                },
                {
                    "control_key": " ssh-root ",
                    "status": "fail",
                    "evidence_summary": "Duplicate logical key",
                    "reboot_required": False,
                },
            ],
        },
    )

    assert response.status_code == 422


def test_posture_snapshot_rejects_empty_results(db_path, make_client):
    client = make_client(db_path)
    enroll_response = enroll_endpoint(client)
    endpoint_id = enroll_response.json()["endpoint_id"]

    response = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-04-18T14:00:00Z",
            "platform_profile": "windows-workstation",
            "results": [],
        },
    )

    assert response.status_code == 422


def test_installer_profile_rejects_whitespace_only_name(db_path, make_client):
    client = make_client(db_path)

    response = client.post(
        "/api/installer-profiles",
        json={
            "name": "   ",
            "platform": "windows",
            "channel": "stable",
            "control_plane_url": "https://sha.example.test",
            "policy_mode": "safe_auto",
            "tenant_id": None,
            "site_id": None,
        },
    )

    assert response.status_code == 422


def test_approval_grant_rejects_whitespace_only_required_strings(db_path, make_client):
    client = make_client(db_path)
    enroll_response = enroll_endpoint(client)
    endpoint_id = enroll_response.json()["endpoint_id"]

    response = client.post(
        "/api/approval-grants",
        json={
            "endpoint_ids": [endpoint_id],
            "allowed_actions": ["inspect_control"],
            "requested_by": "   ",
            "approved_by": "secops",
            "reason": "Validate posture",
            "expires_at": "2026-04-18T16:00:00Z",
        },
    )

    assert response.status_code == 422
