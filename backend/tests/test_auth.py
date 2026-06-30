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
