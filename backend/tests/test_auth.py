from __future__ import annotations

from secrets import token_urlsafe

from fastapi.testclient import TestClient

from app.agent_packages import AgentPackageProvider, PublishedAgentPackage
from app.config import get_settings
from app.main import create_app


def test_api_token_auth_protects_api_routes_but_not_health(db_path):
    with TestClient(create_app(database_url=f"sqlite:///{db_path}", api_token="secret-token")) as client:
        assert client.get("/health").status_code == 200
        missing = client.get("/api/endpoints")
        assert missing.status_code == 401
        assert missing.json() == {"detail": "authentication required"}

        bearer = client.get("/api/endpoints", headers={"Authorization": "Bearer secret-token"})
        assert bearer.status_code == 200

        header = client.get("/api/endpoints", headers={"X-SHA-API-Token": "secret-token"})
        assert header.status_code == 200


def test_agent_api_token_is_limited_to_reporter_routes(db_path):
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            api_token="operator-token",
            agent_api_token="agent-token",
            legacy_reporter_mode="migration",
            legacy_reporter_compatibility_until="2099-01-01T00:00:00Z",
        )
    ) as client:
        agent_headers = {"Authorization": "Bearer agent-token"}
        operator_headers = {"Authorization": "Bearer operator-token"}

        assert client.get("/api/endpoints", headers=operator_headers).status_code == 200
        operator_agent_route = client.post(
            "/api/endpoints/enroll",
            headers=operator_headers,
            json={
                "agent_fingerprint": "operator-must-not-enroll",
                "hostname": "operator-host",
                "platform": "linux",
                "agent_version": "agent-test",
            },
        )
        assert operator_agent_route.status_code == 403
        assert operator_agent_route.json() == {"detail": "forbidden for operator principal"}
        forbidden = client.get("/api/endpoints", headers=agent_headers)
        assert forbidden.status_code == 403
        assert forbidden.json() == {"detail": "forbidden for agent token"}

        enrolled = client.post(
            "/api/endpoints/enroll",
            headers=agent_headers,
            json={
                "agent_fingerprint": "agent-token-fingerprint",
                "hostname": "agent-token-host",
                "platform": "linux",
                "platform_version": "Ubuntu 24.04",
                "agent_version": "agent-test",
            },
        )
        assert enrolled.status_code == 201
        endpoint_id = enrolled.json()["endpoint_id"]

        assert client.post(
            f"/api/endpoints/{endpoint_id}/heartbeat",
            headers=agent_headers,
            json={
                "agent_version": "agent-test",
                "platform_version": "Ubuntu 24.04",
                "platform_profile": "linux-server",
                "connectivity_status": "online",
                "declared_capabilities": ["heartbeat"],
                "execution_hooks": {
                    "captures_rollback_artifacts": False,
                    "reports_execution_results": True,
                    "supports_dry_run": True,
                },
            },
        ).status_code == 202

        operator_claim = client.post(
            f"/api/endpoints/{endpoint_id}/response-actions/claim",
            headers=operator_headers,
            json={},
        )
        assert operator_claim.status_code == 403
        assert operator_claim.json() == {"detail": "forbidden for operator principal"}
        agent_claim = client.post(
            f"/api/endpoints/{endpoint_id}/response-actions/claim",
            headers=agent_headers,
            json={},
        )
        assert agent_claim.status_code == 200
        assert agent_claim.json() == {"items": []}

        operator_result = client.post(
            "/api/response-actions/act_missing/result",
            headers=operator_headers,
            json={
                "status": "failed",
                "result_summary": "Must not reach route",
                "lease_token": "x" * 32,
            },
        )
        assert operator_result.status_code == 403
        assert operator_result.json() == {"detail": "forbidden for operator principal"}
        agent_result = client.post(
            "/api/response-actions/act_missing/result",
            headers=agent_headers,
            json={
                "status": "failed",
                "result_summary": "Route authorization passed",
                "lease_token": "x" * 32,
            },
        )
        assert agent_result.status_code == 404


def test_readonly_api_token_can_read_but_not_mutate_or_download_agent_artifacts(db_path):
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            api_token="operator-token",
            readonly_api_token="readonly-token",
        )
    ) as client:
        readonly_headers = {"Authorization": "Bearer readonly-token"}
        operator_headers = {"Authorization": "Bearer operator-token"}

        assert client.get("/api/endpoints", headers=readonly_headers).status_code == 200
        forbidden_write = client.post(
            "/api/endpoints/enroll",
            headers=readonly_headers,
            json={
                "agent_fingerprint": "readonly-fingerprint",
                "hostname": "readonly-host",
                "platform": "linux",
                "agent_version": "agent-test",
            },
        )
        assert forbidden_write.status_code == 403
        assert forbidden_write.json() == {"detail": "forbidden for read-only principal"}

        created = client.post(
            "/api/installer-profiles",
            headers=operator_headers,
            json={
                "name": "Linux Readonly Guard",
                "platform": "linux",
                "channel": "stable",
                "control_plane_url": "https://sha.example.test/control",
                "policy_mode": "observe",
            },
        )
        assert created.status_code == 201
        artifact = client.get(
            f"/api/installer-profiles/{created.json()['id']}/artifact",
            headers=readonly_headers,
        )
        assert artifact.status_code == 403


def test_external_auth_proxy_operator_and_readonly_roles(db_path):
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            external_auth_trusted_token="proxy-secret",
        )
    ) as client:
        operator_headers = {
            "X-SHA-External-Auth": "proxy-secret",
            "X-SHA-External-Role": "operator",
            "X-SHA-External-User": "alice@example.test",
        }
        readonly_headers = {
            "X-SHA-External-Auth": "proxy-secret",
            "X-SHA-External-Role": "readonly",
            "X-SHA-External-User": "auditor@example.test",
        }

        created = client.post(
            "/api/installer-profiles",
            headers=operator_headers,
            json={
                "name": "Linux External Auth",
                "platform": "linux",
                "channel": "stable",
                "control_plane_url": "https://sha.example.test/control",
                "policy_mode": "observe",
            },
        )
        assert created.status_code == 201
        assert client.get("/api/source-packs", headers=readonly_headers).status_code == 200

        forbidden_write = client.post(
            "/api/endpoints/enroll",
            headers=readonly_headers,
            json={
                "agent_fingerprint": "external-readonly-fingerprint",
                "hostname": "external-readonly-host",
                "platform": "linux",
                "agent_version": "agent-test",
            },
        )
        assert forbidden_write.status_code == 403
        assert forbidden_write.json() == {"detail": "forbidden for read-only principal"}

        artifact = client.get(
            f"/api/installer-profiles/{created.json()['id']}/artifact",
            headers=readonly_headers,
        )
        assert artifact.status_code == 403

        unavailable = client.get(
            f"/api/installer-profiles/{created.json()['id']}/artifact",
            headers=operator_headers,
        )
        assert unavailable.status_code == 503
        assert unavailable.json() == {
            "detail": "signed agent package service is not configured"
        }


def test_protected_installer_artifact_requires_signed_package_provider(db_path):
    headers = {"Authorization": "Bearer secret-token"}
    with TestClient(create_app(database_url=f"sqlite:///{db_path}", api_token="secret-token")) as client:
        created = client.post(
            "/api/installer-profiles",
            headers=headers,
            json={
                "name": "Linux Protected",
                "platform": "linux",
                "channel": "stable",
                "control_plane_url": "https://sha.example.test/control",
                "policy_mode": "observe",
            },
        )
        assert created.status_code == 201

        artifact = client.get(f"/api/installer-profiles/{created.json()['id']}/artifact", headers=headers)

        assert artifact.status_code == 503
        assert artifact.json() == {
            "detail": "signed agent package service is not configured"
        }
        assert "secret-token" not in artifact.text


def test_protected_installer_artifact_serves_verified_generic_package(
    db_path,
    tmp_path,
    monkeypatch,
):
    headers = {"Authorization": "Bearer operator-token"}
    package_bytes = b"signed generic SHA agent package"
    package = PublishedAgentPackage(
        platform="linux",
        architecture="amd64",
        filename="sha-agent-1.0.0-linux-amd64.tar.gz",
        sha256="a" * 64,
        size=len(package_bytes),
        version="1.0.0",
        signing_identity="SHA release signing",
        signing_key_id="release-2026-01",
    )
    provider = AgentPackageProvider(
        release_root=tmp_path,
        trust_policy_file=tmp_path / "trust-policy.json",
        profile_signing_key_file=tmp_path / "profile-signing-key.pem",
        profile_signing_identity="SHA profile signing",
        profile_signing_key_id="profile-2026-01",
        spool_root=tmp_path,
        profile_package_tool=tmp_path / "create-profile-package",
    )
    monkeypatch.setattr(
        AgentPackageProvider,
        "package",
        lambda self, platform, architecture: package,
    )
    monkeypatch.setattr(
        AgentPackageProvider,
        "read_generic",
        lambda self, published: package_bytes,
    )
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            api_token="operator-token",
            agent_package_provider=provider,
        )
    ) as client:
        created = client.post(
            "/api/installer-profiles",
            headers=headers,
            json={
                "name": "Linux Agent Token",
                "platform": "linux",
                "channel": "stable",
                "control_plane_url": "https://sha.example.test/control",
                "policy_mode": "observe",
            },
        )
        assert created.status_code == 201

        artifact = client.get(f"/api/installer-profiles/{created.json()['id']}/artifact", headers=headers)

        assert artifact.status_code == 200
        assert artifact.content == package_bytes
        assert "operator-token" not in artifact.text
        assert "agent-token" not in artifact.text
        assert artifact.headers["cache-control"] == "private, no-store"
        assert artifact.headers["pragma"] == "no-cache"
        assert artifact.headers["referrer-policy"] == "no-referrer"
        assert artifact.headers["x-content-type-options"] == "nosniff"
        assert artifact.headers["x-sha-artifact-sha256"] == package.sha256
        assert artifact.headers["x-sha-signing-identity"] == package.signing_identity
        assert artifact.headers["x-sha-signing-key-id"] == package.signing_key_id


def test_api_tokens_can_be_loaded_from_secret_files(db_path, tmp_path, monkeypatch):
    api_token_file = tmp_path / "api-token"
    api_token_file.write_text("file-operator-token\n", encoding="utf-8")
    api_token_file.chmod(0o600)
    readonly_token_file = tmp_path / "readonly-token"
    readonly_token_file.write_text("file-readonly-token\n", encoding="utf-8")
    readonly_token_file.chmod(0o600)
    monkeypatch.setenv("SHA_API_TOKEN_FILE", str(api_token_file))
    monkeypatch.setenv("SHA_READONLY_API_TOKEN_FILE", str(readonly_token_file))
    get_settings.cache_clear()
    try:
        with TestClient(create_app(database_url=f"sqlite:///{db_path}")) as client:
            assert client.get("/api/endpoints").status_code == 401
            assert client.get(
                "/api/endpoints",
                headers={"Authorization": "Bearer file-readonly-token"},
            ).status_code == 200
            assert client.post(
                "/api/installer-profiles",
                headers={"Authorization": "Bearer file-operator-token"},
                json={
                    "name": "Linux Secret File",
                    "platform": "linux",
                    "channel": "stable",
                    "control_plane_url": "https://sha.example.test/control",
                    "policy_mode": "observe",
                },
            ).status_code == 201
    finally:
        get_settings.cache_clear()


def test_protected_mode_fails_closed_when_authentication_is_not_configured(db_path):
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            auth_mode="protected",
        )
    ) as client:
        assert client.get("/health").status_code == 200
        unavailable = client.get("/api/endpoints")
        assert unavailable.status_code == 503
        assert unavailable.json() == {"detail": "authentication is not configured"}


def test_mutation_actor_comes_from_trusted_external_principal(db_path):
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            external_auth_trusted_token="proxy-secret",
            credential_hmac_key=b"auth-test-device-credential-key-32-bytes",
        )
    ) as client:
        operator_headers = {
            "X-SHA-External-Auth": "proxy-secret",
            "X-SHA-External-Role": "operator",
            "X-SHA-External-User": "Alice@Example.Test",
        }
        scope = client.post(
            "/api/clients",
            headers=operator_headers,
            json={"key": "actor-attribution", "name": "Actor attribution"},
        )
        assert scope.status_code == 201
        location = client.post(
            f"/api/clients/{scope.json()['client_id']}/locations",
            headers=operator_headers,
            json={"key": "primary", "name": "Primary"},
        )
        assert location.status_code == 201
        enrollment = client.post(
            "/api/enrollment-tokens",
            headers=operator_headers,
            json={
                "client_id": scope.json()["client_id"],
                "location_id": location.json()["location_id"],
                "platform": "linux",
                "approval_policy": "approved",
                "expires_in_minutes": 60,
                "max_uses": 1,
            },
        )
        assert enrollment.status_code == 201
        credential_secret = token_urlsafe(32)
        endpoint = client.post(
            "/api/agent/bootstrap",
            headers={"Authorization": f"Bearer {enrollment.json()['token']}"},
            json={
                "installation_id": "install-principal-attribution-0001",
                "credential_id": "dc_principal_actor_0123456789abcdef",
                "credential_secret": credential_secret,
                "agent_fingerprint": "principal-attribution-endpoint",
                "hostname": "principal-host",
                "platform": "linux",
                "platform_version": "Ubuntu 24.04",
                "agent_version": "agent-test",
                "protocol_version": "sha-agent-v1",
                "architecture": "amd64",
            },
        )
        assert endpoint.status_code == 201
        endpoint_id = endpoint.json()["endpoint"]["endpoint_id"]

        created = client.post(
            "/api/approval-requests",
            headers=operator_headers,
            json={
                "endpoint_ids": [endpoint_id],
                "request_kind": "hardening_change",
                "requested_actions": ["apply_control"],
                "control_ids": ["linux.ssh.password-authentication-disabled"],
                "troubleshooting_scopes": [],
                "requested_ttl_minutes": 60,
                "requested_by": "mallory",
                "reason": "Verify principal-derived audit attribution",
                "risk": "high",
            },
        )
        assert created.status_code == 201
        assert created.json()["requested_by"] == "external:alice@example.test"
        assert created.json()["audit_events"][0]["actor"] == "external:alice@example.test"

        denied = client.post(
            f"/api/approval-requests/{created.json()['approval_request_id']}/decisions",
            headers=operator_headers,
            json={
                "decision": "deny",
                "decided_by": "mallory",
                "decision_comment": "Verify decision attribution",
            },
        )
        assert denied.status_code == 200
        assert denied.json()["decision_by"] == "external:alice@example.test"
        assert denied.json()["audit_events"][-1]["actor"] == "external:alice@example.test"
