from __future__ import annotations

from fastapi.testclient import TestClient

from app.hierarchy import QUARANTINE_CLIENT_ID, QUARANTINE_LOCATION_ID
from app.main import create_app


def create_scope(client, *, client_key: str, location_key: str) -> tuple[dict[str, object], dict[str, object]]:
    client_response = client.post(
        "/api/clients",
        json={"key": client_key, "name": f"Client {client_key}"},
    )
    assert client_response.status_code == 201
    client_body = client_response.json()
    location_response = client.post(
        f"/api/clients/{client_body['client_id']}/locations",
        json={"key": location_key, "name": f"Location {location_key}"},
    )
    assert location_response.status_code == 201
    return client_body, location_response.json()


def enroll(client, *, fingerprint: str, tenant_id: str | None, site_id: str | None):
    return client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": fingerprint,
            "hostname": f"host-{fingerprint}",
            "platform": "linux",
            "agent_version": "hierarchy-test",
            "tenant_id": tenant_id,
            "site_id": site_id,
        },
    )


def test_hierarchy_starts_with_quarantine_and_supports_exact_case_keys(db_path, make_client):
    client = make_client(db_path)

    initial = client.get("/api/clients")
    assert initial.status_code == 200
    assert initial.json()["items"] == [
        {
            "client_id": QUARANTINE_CLIENT_ID,
            "key": None,
            "name": "Legacy scope quarantine",
            "state": "migration_quarantine",
            "is_system": True,
            "created_at": "2026-07-17T00:00:00Z",
            "updated_at": "2026-07-17T00:00:00Z",
        }
    ]
    quarantine_locations = client.get(
        f"/api/clients/{QUARANTINE_CLIENT_ID}/locations"
    )
    assert quarantine_locations.status_code == 200
    assert quarantine_locations.json()["items"][0]["location_id"] == QUARANTINE_LOCATION_ID

    upper, upper_location = create_scope(
        client,
        client_key="Tenant-A",
        location_key="Shared-Site",
    )
    lower, lower_location = create_scope(
        client,
        client_key="tenant-a",
        location_key="Shared-Site",
    )

    assert upper["client_id"] != lower["client_id"]
    assert upper_location["location_id"] != lower_location["location_id"]


def test_known_legacy_scope_resolves_and_list_filters_validate_hierarchy(db_path, make_client):
    client = make_client(db_path)
    client_a, location_a = create_scope(client, client_key="tenant-a", location_key="site-a")
    client_b, location_b = create_scope(client, client_key="tenant-b", location_key="site-a")

    endpoint_a = enroll(
        client,
        fingerprint="scope-a",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    endpoint_b = enroll(
        client,
        fingerprint="scope-b",
        tenant_id="tenant-b",
        site_id="site-a",
    )
    assert endpoint_a.status_code == 201
    assert endpoint_b.status_code == 201
    assert endpoint_a.json()["client_id"] == client_a["client_id"]
    assert endpoint_a.json()["location_id"] == location_a["location_id"]
    assert endpoint_b.json()["client_id"] == client_b["client_id"]
    assert endpoint_b.json()["location_id"] == location_b["location_id"]

    client_filtered = client.get(
        "/api/endpoints",
        params={"client_id": client_a["client_id"]},
    )
    assert [item["endpoint_id"] for item in client_filtered.json()["items"]] == [
        endpoint_a.json()["endpoint_id"]
    ]
    location_filtered = client.get(
        "/api/endpoints",
        params={
            "client_id": client_b["client_id"],
            "location_id": location_b["location_id"],
        },
    )
    assert [item["endpoint_id"] for item in location_filtered.json()["items"]] == [
        endpoint_b.json()["endpoint_id"]
    ]
    missing_parent = client.get(
        "/api/endpoints",
        params={"location_id": location_a["location_id"]},
    )
    assert missing_parent.status_code == 422
    mismatched_parent = client.get(
        "/api/endpoints",
        params={
            "client_id": client_a["client_id"],
            "location_id": location_b["location_id"],
        },
    )
    assert mismatched_parent.status_code == 422


def test_unknown_agent_aliases_are_quarantined_without_creating_hierarchy_rows(db_path):
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

        forbidden = client.post(
            "/api/clients",
            headers=agent_headers,
            json={"key": "agent-created", "name": "Agent created"},
        )
        assert forbidden.status_code == 403

        endpoint = client.post(
            "/api/endpoints/enroll",
            headers=agent_headers,
            json={
                "agent_fingerprint": "unknown-scope-agent",
                "hostname": "unknown-scope-agent",
                "platform": "linux",
                "agent_version": "hierarchy-test",
                "client_id": "cl_caller_controlled",
                "location_id": "loc_caller_controlled",
                "tenant_id": "unknown-tenant",
                "site_id": "unknown-site",
            },
        )
        assert endpoint.status_code == 201
        assert endpoint.json()["client_id"] == QUARANTINE_CLIENT_ID
        assert endpoint.json()["location_id"] == QUARANTINE_LOCATION_ID
        assert endpoint.json()["tenant_id"] == "unknown-tenant"
        assert endpoint.json()["site_id"] == "unknown-site"

        clients = client.get("/api/clients", headers=operator_headers)
        assert [item["client_id"] for item in clients.json()["items"]] == [
            QUARANTINE_CLIENT_ID
        ]


def test_reenrollment_cannot_move_between_known_legacy_scopes(db_path, make_client):
    client = make_client(db_path)
    create_scope(client, client_key="tenant-a", location_key="site-a")
    create_scope(client, client_key="tenant-b", location_key="site-b")
    first = enroll(
        client,
        fingerprint="immutable-scope",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    assert first.status_code == 201

    repeated = enroll(
        client,
        fingerprint="immutable-scope",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    assert repeated.status_code == 200
    moved = enroll(
        client,
        fingerprint="immutable-scope",
        tenant_id="tenant-b",
        site_id="site-b",
    )
    assert moved.status_code == 409
    assert moved.json() == {
        "detail": "re-enrollment cannot change endpoint client or location"
    }


def test_installer_profile_accepts_canonical_scope_and_rejects_alias_mismatch(db_path, make_client):
    client = make_client(db_path)
    client_scope, location_scope = create_scope(
        client,
        client_key="tenant-profile",
        location_key="site-profile",
    )
    payload = {
        "name": "Scoped Linux",
        "platform": "linux",
        "channel": "stable",
        "control_plane_url": "https://sha.example.test",
        "policy_mode": "observe",
        "client_id": client_scope["client_id"],
        "location_id": location_scope["location_id"],
    }
    created = client.post("/api/installer-profiles", json=payload)
    assert created.status_code == 201
    assert created.json()["tenant_id"] == "tenant-profile"
    assert created.json()["site_id"] == "site-profile"

    filtered = client.get(
        "/api/installer-profiles",
        params={
            "client_id": client_scope["client_id"],
            "location_id": location_scope["location_id"],
        },
    )
    assert [item["id"] for item in filtered.json()["items"]] == [created.json()["id"]]

    mismatch = client.post(
        "/api/installer-profiles",
        json={
            **payload,
            "name": "Mismatched Linux",
            "tenant_id": "wrong-tenant",
        },
    )
    assert mismatch.status_code == 422
    assert mismatch.json() == {"detail": "tenant_id does not match client_id"}

    other_client, other_location = create_scope(
        client,
        client_key="tenant-profile-other",
        location_key="site-profile",
    )
    same_name_other_client = client.post(
        "/api/installer-profiles",
        json={
            **payload,
            "client_id": other_client["client_id"],
            "location_id": other_location["location_id"],
        },
    )
    assert same_name_other_client.status_code == 201

    duplicate_same_client = client.post("/api/installer-profiles", json=payload)
    assert duplicate_same_client.status_code == 409
    assert duplicate_same_client.json() == {
        "detail": "installer profile already exists for client and platform"
    }
