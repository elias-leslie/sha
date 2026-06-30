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
