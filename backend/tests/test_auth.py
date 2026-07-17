from __future__ import annotations

from fastapi.testclient import TestClient

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
        create_app(database_url=f"sqlite:///{db_path}", api_token="operator-token", agent_api_token="agent-token")
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
            "detail": "agent API token is required to generate installer artifacts when operator authentication is configured"
        }


def test_protected_installer_artifact_requires_agent_api_token(db_path):
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
            "detail": "agent API token is required to generate installer artifacts when operator authentication is configured"
        }
        assert "secret-token" not in artifact.text


def test_protected_installer_artifact_prefers_agent_api_token(db_path):
    headers = {"Authorization": "Bearer operator-token"}
    with TestClient(
        create_app(database_url=f"sqlite:///{db_path}", api_token="operator-token", agent_api_token="agent-token")
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
        assert '"api_token": "agent-token"' in artifact.text
        assert '"api_token": "operator-token"' not in artifact.text
        assert artifact.headers["cache-control"] == "private, no-store"
        assert artifact.headers["pragma"] == "no-cache"
        assert artifact.headers["referrer-policy"] == "no-referrer"
        assert artifact.headers["x-content-type-options"] == "nosniff"


def test_api_tokens_can_be_loaded_from_secret_files(db_path, tmp_path, monkeypatch):
    api_token_file = tmp_path / "api-token"
    api_token_file.write_text("file-operator-token\n", encoding="utf-8")
    readonly_token_file = tmp_path / "readonly-token"
    readonly_token_file.write_text("file-readonly-token\n", encoding="utf-8")
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
            agent_api_token="agent-token",
            external_auth_trusted_token="proxy-secret",
        )
    ) as client:
        agent_headers = {"Authorization": "Bearer agent-token"}
        operator_headers = {
            "X-SHA-External-Auth": "proxy-secret",
            "X-SHA-External-Role": "operator",
            "X-SHA-External-User": "Alice@Example.Test",
        }
        endpoint = client.post(
            "/api/endpoints/enroll",
            headers=agent_headers,
            json={
                "agent_fingerprint": "principal-attribution-endpoint",
                "hostname": "principal-host",
                "platform": "linux",
                "agent_version": "agent-test",
            },
        )
        assert endpoint.status_code == 201

        created = client.post(
            "/api/approval-requests",
            headers=operator_headers,
            json={
                "endpoint_ids": [endpoint.json()["endpoint_id"]],
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
