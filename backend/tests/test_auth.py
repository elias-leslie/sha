from __future__ import annotations

from fastapi.testclient import TestClient

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
        assert forbidden_write.json() == {"detail": "forbidden for read-only token"}

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
        assert forbidden_write.json() == {"detail": "forbidden for external read-only role"}

        artifact = client.get(
            f"/api/installer-profiles/{created.json()['id']}/artifact",
            headers=readonly_headers,
        )
        assert artifact.status_code == 403


def test_protected_installer_artifact_embeds_active_api_token(db_path):
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

        assert artifact.status_code == 200
        assert '"api_token": "secret-token"' in artifact.text
        assert "Authorization" in artifact.text


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
