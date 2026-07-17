from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import sqlite3
from secrets import token_urlsafe
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import config as config_module
from app.api.endpoints import device_identity as device_identity_endpoints
from app.config import Settings
from app.main import create_app

HMAC_KEY = b"sha-device-identity-test-key-32-bytes-minimum"
OPERATOR_HEADERS = {"Authorization": "Bearer operator-token"}
LEGACY_AGENT_HEADERS = {"Authorization": "Bearer legacy-agent-token"}


def create_scope(client: TestClient, suffix: str) -> tuple[str, str]:
    created_client = client.post(
        "/api/clients",
        headers=OPERATOR_HEADERS,
        json={"key": f"tenant-{suffix}", "name": f"Tenant {suffix}"},
    )
    assert created_client.status_code == 201
    client_id = created_client.json()["client_id"]
    created_location = client.post(
        f"/api/clients/{client_id}/locations",
        headers=OPERATOR_HEADERS,
        json={"key": f"site-{suffix}", "name": f"Site {suffix}"},
    )
    assert created_location.status_code == 201
    return client_id, created_location.json()["location_id"]


def create_enrollment_token(
    client: TestClient,
    client_id: str,
    location_id: str,
    **overrides: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "client_id": client_id,
        "location_id": location_id,
        "platform": "linux",
        "approval_policy": "approved",
        "expires_in_minutes": 60,
        "max_uses": 1,
    }
    payload.update(overrides)
    response = client.post(
        "/api/enrollment-tokens",
        headers=OPERATOR_HEADERS,
        json=payload,
    )
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "private, no-store"
    return response.json()


def exchange_payload(suffix: str, *, platform: str = "linux") -> tuple[dict[str, object], str]:
    secret = token_urlsafe(32)
    return (
        {
            "installation_id": f"install-{suffix}-00000001",
            "credential_id": f"dc_{suffix.replace('-', '_')}_0123456789abcdef",
            "credential_secret": secret,
            "agent_fingerprint": f"fingerprint-{suffix}",
            "hostname": f"host-{suffix}",
            "platform": platform,
            "platform_version": "Ubuntu 24.04" if platform == "linux" else "Windows 11",
            "agent_version": "device-test-1",
            "protocol_version": "sha-agent-v1",
            "architecture": "amd64",
        },
        secret,
    )


def exchange(
    client: TestClient,
    enrollment_token: str,
    payload: dict[str, object],
):
    return client.post(
        "/api/agent/bootstrap",
        headers={"Authorization": f"Bearer {enrollment_token}"},
        json=payload,
    )


def device_headers(payload: dict[str, object], secret: str) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer sha_device.{payload['credential_id']}.{secret}"
        )
    }


def capability_manifest(capabilities: list[str]) -> dict[str, object]:
    descriptors: list[dict[str, object]] = []
    for capability in capabilities:
        kind = "core"
        if capability == "collect_posture_snapshot":
            kind = "collector"
        elif capability.startswith(("apply_control:", "rollback_control:")):
            kind = "action"
        descriptors.append(
            {"id": capability, "kind": kind, "versions": ["1"]}
        )
    return {
        "schema_version": "sha-agent-capabilities-v1",
        "capabilities": descriptors,
        "runtime": {
            "privilege": "elevated",
            "service_context": "system_service",
        },
        "features": {"evidence_upload": False, "terminal": False},
        "resource_limits": {
            "max_concurrent_jobs": 1,
            "max_output_bytes": 65536,
            "max_upload_bytes": 0,
            "command_timeout_seconds": 30,
        },
        "health": {"state": "healthy", "reasons": []},
    }


def heartbeat(client: TestClient, endpoint_id: str, headers: dict[str, str]):
    capabilities = ["heartbeat", "apply_control"]
    return client.post(
        f"/api/endpoints/{endpoint_id}/heartbeat",
        headers=headers,
        json={
            "agent_version": "device-test-2",
            "protocol_version": "sha-agent-v1",
            "architecture": "amd64",
            "platform_version": "Ubuntu 24.04",
            "platform_profile": "linux-test",
            "connectivity_status": "online",
            "declared_capabilities": capabilities,
            "capability_manifest": capability_manifest(capabilities),
            "execution_hooks": {
                "captures_rollback_artifacts": True,
                "reports_execution_results": True,
                "supports_dry_run": True,
            },
        },
    )


@pytest.fixture
def protected_client(db_path: Path):
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            api_token="operator-token",
            agent_api_token="legacy-agent-token",
            credential_hmac_key=HMAC_KEY,
        )
    ) as client:
        yield client


def test_enrollment_token_is_returned_once_hashed_at_rest_and_exactly_replayable(
    db_path: Path,
    protected_client: TestClient,
) -> None:
    client_id, location_id = create_scope(protected_client, "replay")
    token_metadata = create_enrollment_token(
        protected_client,
        client_id,
        location_id,
    )
    enrollment_token = str(token_metadata["token"])
    token_secret = enrollment_token.rsplit(".", 1)[1]

    listed = protected_client.get(
        "/api/enrollment-tokens",
        headers=OPERATOR_HEADERS,
    )
    assert listed.status_code == 200
    assert "token" not in listed.json()["items"][0]
    assert enrollment_token not in listed.text
    assert token_secret not in listed.text

    with sqlite3.connect(db_path) as connection:
        stored_hash, use_count = connection.execute(
            "SELECT secret_hash, use_count FROM enrollment_tokens WHERE token_id = ?",
            (token_metadata["token_id"],),
        ).fetchone()
    assert stored_hash != token_secret
    assert len(stored_hash) == 64
    assert use_count == 0

    payload, credential_secret = exchange_payload("replay")
    first = exchange(protected_client, enrollment_token, payload)
    assert first.status_code == 201, first.text
    endpoint = first.json()["endpoint"]
    assert endpoint["client_id"] == client_id
    assert endpoint["location_id"] == location_id
    assert endpoint["installation_id"] == payload["installation_id"]
    assert endpoint["credential_mode"] == "device"
    assert endpoint["enrollment_token_id"] == token_metadata["token_id"]
    assert first.json()["replayed"] is False

    replay = exchange(protected_client, enrollment_token, payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["endpoint"]["endpoint_id"] == endpoint["endpoint_id"]

    conflicting_payload = {**payload, "hostname": "different-host"}
    conflict = exchange(protected_client, enrollment_token, conflicting_payload)
    assert conflict.status_code == 409
    assert token_secret not in conflict.text
    assert credential_secret not in conflict.text

    second_payload, _second_secret = exchange_payload("max-use")
    exhausted = exchange(protected_client, enrollment_token, second_payload)
    assert exhausted.status_code == 401
    assert exhausted.json() == {"detail": "authentication required"}

    bearer = device_headers(payload, credential_secret)
    me = protected_client.get("/api/agent/me", headers=bearer)
    assert me.status_code == 200
    assert me.json()["endpoint"]["endpoint_id"] == endpoint["endpoint_id"]
    assert credential_secret not in me.text
    operator_detail = protected_client.get(
        f"/api/endpoints/{endpoint['endpoint_id']}",
        headers=OPERATOR_HEADERS,
    )
    assert operator_detail.status_code == 200
    active_credential = operator_detail.json()["active_credential"]
    assert active_credential["credential_id"] == payload["credential_id"]
    assert active_credential["status"] == "active"
    assert active_credential["endpoint_id"] == endpoint["endpoint_id"]
    assert active_credential["created_at"]
    assert "secret" not in operator_detail.text

    with sqlite3.connect(db_path) as connection:
        credential_hash, final_use_count, request_hash = connection.execute(
            """
            SELECT dc.secret_hash, et.use_count, er.request_hash
            FROM device_credentials AS dc
            JOIN enrollment_redemptions AS er ON er.credential_id = dc.credential_id
            JOIN enrollment_tokens AS et ON et.token_id = er.enrollment_token_id
            WHERE dc.credential_id = ?
            """,
            (payload["credential_id"],),
        ).fetchone()
    assert credential_hash != credential_secret
    assert len(credential_hash) == 64
    assert len(request_hash) == 64
    assert final_use_count == 1


def test_device_credentials_are_endpoint_bound_and_legacy_token_cannot_bypass_them(
    protected_client: TestClient,
) -> None:
    client_id, location_id = create_scope(protected_client, "binding")
    token = create_enrollment_token(
        protected_client,
        client_id,
        location_id,
        max_uses=2,
    )
    first_payload, first_secret = exchange_payload("binding-one")
    second_payload, second_secret = exchange_payload("binding-two")
    first = exchange(protected_client, str(token["token"]), first_payload)
    second = exchange(protected_client, str(token["token"]), second_payload)
    assert first.status_code == 201
    assert second.status_code == 201
    first_endpoint_id = first.json()["endpoint"]["endpoint_id"]
    second_endpoint_id = second.json()["endpoint"]["endpoint_id"]
    first_headers = device_headers(first_payload, first_secret)
    second_headers = device_headers(second_payload, second_secret)

    assert heartbeat(protected_client, first_endpoint_id, first_headers).status_code == 202
    cross_device = heartbeat(protected_client, second_endpoint_id, first_headers)
    assert cross_device.status_code == 403
    legacy_bypass = heartbeat(protected_client, first_endpoint_id, LEGACY_AGENT_HEADERS)
    assert legacy_bypass.status_code == 403
    legacy_reenroll = protected_client.post(
        "/api/endpoints/enroll",
        headers=LEGACY_AGENT_HEADERS,
        json={
            "agent_fingerprint": first_payload["agent_fingerprint"],
            "hostname": "legacy-takeover-attempt",
            "platform": "linux",
            "agent_version": "legacy-agent",
        },
    )
    assert legacy_reenroll.status_code == 403

    grant = protected_client.post(
        "/api/approval-grants",
        headers=OPERATOR_HEADERS,
        json={
            "endpoint_ids": [first_endpoint_id],
            "allowed_actions": ["apply_control"],
            "control_ids": ["linux.ssh.password-authentication-disabled"],
            "troubleshooting_scopes": [],
            "reason": "Verify device-bound action completion",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=60)).isoformat(),
        },
    )
    assert grant.status_code == 201, grant.text
    action = protected_client.post(
        "/api/response-actions",
        headers=OPERATOR_HEADERS,
        json={
            "endpoint_id": first_endpoint_id,
            "approval_grant_id": grant.json()["approval_grant_id"],
            "action": "apply_control",
            "control_id": "linux.ssh.password-authentication-disabled",
            "reason": "Verify result binding",
        },
    )
    assert action.status_code == 201, action.text
    claimed = protected_client.post(
        f"/api/endpoints/{first_endpoint_id}/response-actions/claim",
        headers=first_headers,
    )
    assert claimed.status_code == 200
    lease = claimed.json()["items"][0]

    cross_result = protected_client.post(
        f"/api/response-actions/{action.json()['response_action_id']}/result",
        headers=second_headers,
        json={
            "status": "succeeded",
            "result_summary": "Must not be accepted",
            "lease_token": lease["lease_token"],
        },
    )
    assert cross_result.status_code == 403


def test_concurrent_http_bootstrap_allows_only_one_use_limit_winner(
    db_path: Path,
    protected_client: TestClient,
) -> None:
    client_id, location_id = create_scope(protected_client, "http-race")
    token = create_enrollment_token(
        protected_client,
        client_id,
        location_id,
        max_uses=1,
    )
    first_payload, _first_secret = exchange_payload("http-race-one")
    second_payload, _second_secret = exchange_payload("http-race-two")
    barrier = Barrier(2)

    def redeem(payload: dict[str, object]):
        barrier.wait(timeout=5)
        return exchange(protected_client, str(token["token"]), payload)

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(redeem, (first_payload, second_payload)))

    assert sorted(response.status_code for response in responses) == [201, 401]
    assert sum(response.status_code == 201 for response in responses) == 1
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT use_count FROM enrollment_tokens WHERE token_id = ?",
            (token["token_id"],),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM endpoints WHERE enrollment_token_id = ?",
            (token["token_id"],),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM enrollment_redemptions WHERE enrollment_token_id = ?",
            (token["token_id"],),
        ).fetchone() == (1,)


def test_pending_enrollment_allows_heartbeat_only_until_operator_approval(
    protected_client: TestClient,
) -> None:
    client_id, location_id = create_scope(protected_client, "pending")
    token = create_enrollment_token(
        protected_client,
        client_id,
        location_id,
        approval_policy="pending",
    )
    payload, secret = exchange_payload("pending")
    enrolled = exchange(protected_client, str(token["token"]), payload)
    assert enrolled.status_code == 201
    endpoint_id = enrolled.json()["endpoint"]["endpoint_id"]
    headers = device_headers(payload, secret)

    pending_heartbeat = heartbeat(protected_client, endpoint_id, headers)
    assert pending_heartbeat.status_code == 202
    assert pending_heartbeat.json()["status"] == "pending"
    assert pending_heartbeat.json()["pending_action_count"] == 0

    posture_payload = {
        "endpoint_id": endpoint_id,
        "observed_at": "2026-07-17T12:00:00Z",
        "platform_profile": "linux-test",
        "results": [
            {
                "control_key": "linux.firewall.service-active",
                "status": "pass",
                "current_value": "active",
                "recommended_value": "active",
                "severity": "low",
                "evidence_summary": "Firewall is active.",
                "reboot_required": False,
            }
        ],
    }
    posture = protected_client.post(
        "/api/posture-snapshots",
        headers=headers,
        json=posture_payload,
    )
    assert posture.status_code == 403
    claim = protected_client.post(
        f"/api/endpoints/{endpoint_id}/response-actions/claim",
        headers=headers,
    )
    assert claim.status_code == 403

    approved = protected_client.post(
        f"/api/endpoints/{endpoint_id}/approve-enrollment",
        headers=OPERATOR_HEADERS,
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "active"
    assert protected_client.post(
        "/api/posture-snapshots",
        headers=headers,
        json=posture_payload,
    ).status_code == 202


def test_rotation_and_operator_revocation_take_effect_immediately(
    protected_client: TestClient,
) -> None:
    client_id, location_id = create_scope(protected_client, "rotation")
    token = create_enrollment_token(protected_client, client_id, location_id)
    payload, old_secret = exchange_payload("rotation")
    enrolled = exchange(protected_client, str(token["token"]), payload)
    assert enrolled.status_code == 201
    old_headers = device_headers(payload, old_secret)

    new_secret = token_urlsafe(32)
    new_credential_id = "dc_rotation_new_0123456789abcdef"
    rotated = protected_client.post(
        "/api/agent/credentials/rotate",
        headers=old_headers,
        json={
            "credential_id": new_credential_id,
            "credential_secret": new_secret,
        },
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["status"] == "active"
    assert protected_client.get("/api/agent/me", headers=old_headers).status_code == 401

    new_headers = {
        "Authorization": f"Bearer sha_device.{new_credential_id}.{new_secret}"
    }
    assert protected_client.get("/api/agent/me", headers=new_headers).status_code == 200
    endpoint_id = enrolled.json()["endpoint"]["endpoint_id"]
    after_rotation = protected_client.get(
        f"/api/endpoints/{endpoint_id}",
        headers=OPERATOR_HEADERS,
    )
    assert after_rotation.status_code == 200
    assert after_rotation.json()["active_credential"]["credential_id"] == new_credential_id
    revoked = protected_client.post(
        f"/api/device-credentials/{new_credential_id}/revoke",
        headers=OPERATOR_HEADERS,
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert protected_client.get("/api/agent/me", headers=new_headers).status_code == 401
    after_revocation = protected_client.get(
        f"/api/endpoints/{endpoint_id}",
        headers=OPERATOR_HEADERS,
    )
    assert after_revocation.status_code == 200
    assert after_revocation.json()["active_credential"] is None


def test_revoked_token_and_malformed_credentials_return_generic_auth_errors(
    db_path: Path,
    protected_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_id, location_id = create_scope(protected_client, "invalid")
    token = create_enrollment_token(protected_client, client_id, location_id, max_uses=2)
    payload, _secret = exchange_payload("invalid")

    invalid_secret = "!" * 43
    invalid_payload = {**payload, "credential_secret": invalid_secret}
    invalid_body = exchange(protected_client, str(token["token"]), invalid_payload)
    assert invalid_body.status_code == 422
    assert invalid_secret not in invalid_body.text
    assert "[REDACTED]" in invalid_body.text

    revoked = protected_client.post(
        f"/api/enrollment-tokens/{token['token_id']}/revoke",
        headers=OPERATOR_HEADERS,
    )
    assert revoked.status_code == 200
    rejected = exchange(protected_client, str(token["token"]), payload)
    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "authentication required"}

    malformed = protected_client.get(
        "/api/agent/me",
        headers={"Authorization": "Bearer sha_device.dc_bad.not-a-secret"},
    )
    assert malformed.status_code == 401
    assert malformed.json() == {"detail": "authentication required"}

    expiry_boundary = datetime(2026, 7, 17, 15, 30, tzinfo=UTC)
    monkeypatch.setattr(device_identity_endpoints, "utc_now", lambda: expiry_boundary)
    expired = create_enrollment_token(protected_client, client_id, location_id)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE enrollment_tokens SET expires_at = ? WHERE token_id = ?",
            ("2026-07-17T15:30:00Z", expired["token_id"]),
        )
        connection.commit()
    expired_payload, _expired_secret = exchange_payload("expired")
    expired_response = exchange(
        protected_client,
        str(expired["token"]),
        expired_payload,
    )
    assert expired_response.status_code == 401
    assert expired_response.json() == {"detail": "authentication required"}

    wrong_secret = token_urlsafe(32)
    unknown = protected_client.get(
        "/api/agent/me",
        headers={
            "Authorization": (
                f"Bearer sha_device.{payload['credential_id']}.{wrong_secret}"
            )
        },
    )
    assert unknown.status_code == 401
    assert wrong_secret not in unknown.text


def test_installer_profile_scope_and_platform_are_fixed_by_enrollment_token(
    protected_client: TestClient,
) -> None:
    first_client_id, first_location_id = create_scope(protected_client, "profile-one")
    second_client_id, second_location_id = create_scope(protected_client, "profile-two")
    profile = protected_client.post(
        "/api/installer-profiles",
        headers=OPERATOR_HEADERS,
        json={
            "name": "Scoped Linux",
            "platform": "linux",
            "channel": "stable",
            "control_plane_url": "https://sha.example.test",
            "policy_mode": "observe",
            "client_id": first_client_id,
            "location_id": first_location_id,
        },
    )
    assert profile.status_code == 201

    wrong_scope = protected_client.post(
        "/api/enrollment-tokens",
        headers=OPERATOR_HEADERS,
        json={
            "client_id": second_client_id,
            "location_id": second_location_id,
            "installer_profile_id": profile.json()["id"],
        },
    )
    assert wrong_scope.status_code == 422

    wrong_profile_platform = protected_client.post(
        "/api/enrollment-tokens",
        headers=OPERATOR_HEADERS,
        json={
            "client_id": first_client_id,
            "location_id": first_location_id,
            "installer_profile_id": profile.json()["id"],
            "platform": "windows",
        },
    )
    assert wrong_profile_platform.status_code == 422

    token = create_enrollment_token(
        protected_client,
        first_client_id,
        first_location_id,
        installer_profile_id=profile.json()["id"],
        platform=None,
    )
    assert token["platform"] == "linux"
    windows_payload, _secret = exchange_payload("wrong-platform", platform="windows")
    platform_mismatch = exchange(
        protected_client,
        str(token["token"]),
        windows_payload,
    )
    assert platform_mismatch.status_code == 422
    assert platform_mismatch.json() == {
        "detail": "endpoint platform does not match enrollment token"
    }

    linux_payload, _linux_secret = exchange_payload("right-platform")
    accepted = exchange(protected_client, str(token["token"]), linux_payload)
    assert accepted.status_code == 201
    assert accepted.json()["endpoint"]["client_id"] == first_client_id
    assert accepted.json()["endpoint"]["location_id"] == first_location_id


def test_credential_hmac_key_file_requires_secure_absolute_regular_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "credential-key"
    key_file.write_bytes(HMAC_KEY)
    key_file.chmod(0o600)
    assert Settings(credential_hmac_key_file=str(key_file)).resolved_credential_hmac_key() == HMAC_KEY

    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="absolute"):
        Settings(credential_hmac_key_file="credential-key").resolved_credential_hmac_key()

    symlink = tmp_path / "credential-key-link"
    symlink.symlink_to(key_file)
    with pytest.raises(ValueError, match="symlink components"):
        Settings(credential_hmac_key_file=str(symlink)).resolved_credential_hmac_key()

    real_parent = tmp_path / "real-secret-parent"
    real_parent.mkdir()
    nested_key = real_parent / "credential-key"
    nested_key.write_bytes(HMAC_KEY)
    nested_key.chmod(0o600)
    linked_parent = tmp_path / "linked-secret-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink components"):
        Settings(
            credential_hmac_key_file=str(linked_parent / "credential-key")
        ).resolved_credential_hmac_key()

    if os.name == "posix":
        for insecure_mode in (0o640, 0o604, 0o622):
            key_file.chmod(insecure_mode)
            with pytest.raises(ValueError, match="group or world permissions"):
                Settings(
                    credential_hmac_key_file=str(key_file)
                ).resolved_credential_hmac_key()

        key_file.chmod(0o600)
        actual_stat = os.stat(key_file)
        untrusted_stat = SimpleNamespace(
            st_mode=actual_stat.st_mode,
            st_uid=os.geteuid() + 1,
        )
        monkeypatch.setattr(config_module.os, "fstat", lambda _descriptor: untrusted_stat)
        monkeypatch.setattr(
            config_module.os,
            "statvfs",
            lambda _path: SimpleNamespace(f_flag=0),
        )
        with pytest.raises(ValueError, match="unless mounted read-only"):
            Settings(credential_hmac_key_file=str(key_file)).resolved_credential_hmac_key()

        monkeypatch.setattr(
            config_module.os,
            "statvfs",
            lambda _path: SimpleNamespace(f_flag=os.ST_RDONLY),
        )
        assert (
            Settings(credential_hmac_key_file=str(key_file)).resolved_credential_hmac_key()
            == HMAC_KEY
        )
