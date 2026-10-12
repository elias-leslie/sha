"""The API exposes no shell, remote-desktop, or backend-host network scan routes.

Endpoint work goes through typed, approval-gated response actions. These tests
guard against reintroducing a free-form command path or features that run on the
backend host instead of the managed endpoint.
"""

from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import create_app

FORBIDDEN_PATH_FRAGMENTS = ("terminal", "remote-desktop", "/api/network", "shell", "/exec")


def _enroll_endpoint(client) -> str:
    response = client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": "linux-route-guard-agent",
            "hostname": "linux-route-guard-01",
            "platform": "linux",
            "platform_version": "Ubuntu 24.04",
            "agent_version": "agent-test",
        },
    )
    assert response.status_code == 201
    return response.json()["endpoint_id"]


def test_no_registered_route_offers_command_desktop_or_network_scan(tmp_path):
    app = create_app(database_url=f"sqlite:///{tmp_path / 'sha.sqlite3'}")

    offending = [
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
        and any(fragment in route.path for fragment in FORBIDDEN_PATH_FRAGMENTS)
    ]

    assert offending == []


def test_removed_routes_are_not_served(db_path, make_client):
    client = make_client(db_path)
    endpoint_id = _enroll_endpoint(client)

    requests = [
        (f"/api/endpoints/{endpoint_id}/terminal/execute", {"command": "uname -a"}),
        (f"/api/endpoints/{endpoint_id}/terminal/execute", {"command": "rm -rf /"}),
        (f"/api/endpoints/{endpoint_id}/remote-desktop/session", None),
        ("/api/network/scan", {"cidr": "10.0.0.0/24"}),
    ]

    for path, body in requests:
        response = client.post(path, json=body)
        assert response.status_code in {404, 405}, (path, response.status_code)
        assert "stdout" not in response.text
        assert "tunnel" not in response.text
