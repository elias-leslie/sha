from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.browser_auth import OIDC_TRANSACTION_COOKIE_NAME, OidcClientConfig
from app.main import create_app
from app.models import AuditEvent, Role, User, UserRoleBinding
from app.utils import generate_prefixed_id, to_utc_z, utc_now


class _FakeOidcClient:
    issuer = "https://idp.example.test/tenant-a"

    async def load_server_metadata(self) -> dict[str, object]:
        return {
            "issuer": self.issuer,
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        }

    async def create_authorization_url(self, redirect_uri: str) -> dict[str, str]:
        assert redirect_uri == "https://sha.example.test/api/auth/oidc/callback"
        return {
            "url": "https://idp.example.test/authorize",
            "state": "fleet-metadata-state",
            "nonce": "fleet-metadata-nonce",
            "code_verifier": "fleet-metadata-verifier",
        }

    async def fetch_access_token(self, **kwargs: str) -> dict[str, str]:
        assert kwargs["code"] == "fleet-metadata-code"
        return {"id_token": "fleet-metadata-id-token"}

    async def parse_id_token(
        self,
        token: dict[str, str],
        *,
        nonce: str,
        claims_options: dict[str, object],
    ) -> dict[str, str]:
        assert token["id_token"] == "fleet-metadata-id-token"
        assert nonce == "fleet-metadata-nonce"
        assert claims_options == {"iss": {"values": [self.issuer]}}
        return {
            "iss": self.issuer,
            "sub": "fleet-metadata-user",
            "name": "Scoped fleet operator",
        }


def _oidc_config() -> OidcClientConfig:
    return OidcClientConfig(
        issuer=_FakeOidcClient.issuer,
        metadata_url=(
            "https://idp.example.test/tenant-a/.well-known/openid-configuration"
        ),
        client_id="sha-client",
        client_secret="oidc-client-secret",
        public_base_url="https://sha.example.test",
    )


def _complete_login(client: TestClient) -> None:
    login = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert login.status_code == 302
    assert client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME)
    callback = client.get(
        "/api/auth/oidc/callback",
        params={"state": "fleet-metadata-state", "code": "fleet-metadata-code"},
        follow_redirects=False,
    )
    assert callback.status_code == 303


def _create_scope(client: TestClient, suffix: str) -> tuple[str, str, str]:
    created_client = client.post(
        "/api/clients",
        json={"key": f"tenant-{suffix}", "name": f"Tenant {suffix.upper()}"},
    )
    assert created_client.status_code == 201
    client_id = created_client.json()["client_id"]
    created_location = client.post(
        f"/api/clients/{client_id}/locations",
        json={"key": f"site-{suffix}", "name": f"Site {suffix.upper()}"},
    )
    assert created_location.status_code == 201
    location_id = created_location.json()["location_id"]
    enrolled = client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": f"fleet-metadata-{suffix}",
            "hostname": f"host-{suffix}",
            "platform": "linux" if suffix == "a" else "windows",
            "agent_version": "1.0.0",
            "tenant_id": f"tenant-{suffix}",
            "site_id": f"site-{suffix}",
        },
    )
    assert enrolled.status_code == 201
    return client_id, location_id, enrolled.json()["endpoint_id"]


def _create_saved_view(
    client: TestClient,
    *,
    name: str,
    client_id: str,
    location_id: str | None = None,
    platform: str = "linux",
    visibility: str = "shared",
) -> dict[str, object]:
    response = client.post(
        "/api/saved-views",
        json={
            "name": name,
            "visibility": visibility,
            "scope_type": "location" if location_id else "client",
            "client_id": client_id,
            "location_id": location_id,
            "filter": {
                "schema_version": 1,
                "match": "all",
                "rules": [{"field": "platform", "op": "eq", "value": platform}],
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_group(client: TestClient, name: str, saved_view_id: str) -> dict[str, object]:
    response = client.post(
        "/api/dynamic-groups",
        json={"name": name, "saved_view_id": saved_view_id},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_tags_saved_views_and_dynamic_groups_form_a_scoped_audited_slice(
    db_path,
    make_client,
) -> None:
    client = make_client(db_path)
    client_a, location_a, endpoint_a = _create_scope(client, "a")
    client_b, _location_b, endpoint_b = _create_scope(client, "b")

    created_tag = client.post(
        "/api/tags",
        json={
            "name": "IR priority",
            "description": "Incident-response target",
            "scope_type": "client",
            "client_id": client_a,
        },
    )
    assert created_tag.status_code == 201
    tag_id = created_tag.json()["tag_id"]
    assigned = client.post(
        f"/api/endpoints/{endpoint_a}/tags",
        json={"tag_id": tag_id},
    )
    assert assigned.status_code == 201
    assert assigned.json()["assigned_by"] == "development:operator"
    assert client.post(
        f"/api/endpoints/{endpoint_b}/tags",
        json={"tag_id": tag_id},
    ).status_code == 404
    endpoint_tags = client.get(f"/api/endpoints/{endpoint_a}/tags")
    assert [item["tag_id"] for item in endpoint_tags.json()["items"]] == [tag_id]

    saved_view = _create_saved_view(
        client,
        name="Linux response targets",
        client_id=client_a,
    )
    assert saved_view["current_version"] == 1
    group = _create_group(client, "Linux response group", str(saved_view["saved_view_id"]))
    preview = client.get(f"/api/dynamic-groups/{group['dynamic_group_id']}/preview")
    assert preview.status_code == 200
    assert preview.json() == {
        "dynamic_group_id": group["dynamic_group_id"],
        "saved_view_id": saved_view["saved_view_id"],
        "saved_view_version": 1,
        "filter_hash": saved_view["content_hash"],
        "evaluated_endpoint_count": 1,
        "matched_endpoint_count": 1,
        "result_limit": 100,
        "truncated": False,
        "items": [
            {
                "endpoint_id": endpoint_a,
                "hostname": "host-a",
                "platform": "linux",
                "status": "active",
                "connectivity_status": None,
                "client_id": client_a,
                "location_id": location_a,
            }
        ],
    }

    updated = client.put(
        f"/api/saved-views/{saved_view['saved_view_id']}",
        json={
            "filter": {
                "schema_version": 1,
                "match": "all",
                "rules": [{"field": "platform", "op": "eq", "value": "windows"}],
            }
        },
    )
    assert updated.status_code == 200
    assert updated.json()["current_version"] == 2
    updated_preview = client.get(
        f"/api/dynamic-groups/{group['dynamic_group_id']}/preview"
    ).json()
    assert updated_preview["saved_view_version"] == 2
    assert updated_preview["matched_endpoint_count"] == 0

    scoped_tags = client.get("/api/tags", params={"client_id": client_a})
    assert [item["tag_id"] for item in scoped_tags.json()["items"]] == [tag_id]
    assert client.get(
        "/api/tags",
        params={"client_id": client_b, "location_id": location_a},
    ).status_code == 422

    removed = client.delete(f"/api/endpoints/{endpoint_a}/tags/{tag_id}")
    assert removed.status_code == 204
    assert client.get(f"/api/endpoints/{endpoint_a}/tags").json()["items"] == []

    with client.app.state.store.session() as session:
        event_types = {
            event.event_type
            for event in session.scalars(select(AuditEvent)).all()
        }
    assert {
        "tag_created",
        "endpoint_tag_assigned",
        "endpoint_tag_removed",
        "saved_view_created",
        "saved_view_version_created",
        "dynamic_group_created",
    } <= event_types


def test_filter_contract_rejects_raw_or_unbounded_expressions(db_path, make_client) -> None:
    client = make_client(db_path)
    client_id, _location_id, _endpoint_id = _create_scope(client, "a")
    raw_sql = client.post(
        "/api/saved-views",
        json={
            "name": "Unsafe",
            "scope_type": "client",
            "client_id": client_id,
            "filter": {"sql": "SELECT * FROM endpoints"},
        },
    )
    assert raw_sql.status_code == 422
    unknown_field = client.post(
        "/api/saved-views",
        json={
            "name": "Unknown field",
            "scope_type": "client",
            "client_id": client_id,
            "filter": {
                "schema_version": 1,
                "match": "all",
                "rules": [{"field": "shell", "op": "eq", "value": "whoami"}],
            },
        },
    )
    assert unknown_field.status_code == 422
    too_many_rules = client.post(
        "/api/saved-views",
        json={
            "name": "Too broad",
            "scope_type": "client",
            "client_id": client_id,
            "filter": {
                "schema_version": 1,
                "match": "all",
                "rules": [
                    {"field": "status", "op": "eq", "value": "active"}
                    for _ in range(17)
                ],
            },
        },
    )
    assert too_many_rules.status_code == 422


def test_location_principal_cannot_infer_foreign_metadata_or_membership(
    db_path,
    make_client,
) -> None:
    setup_client = make_client(db_path)
    client_a, location_a, endpoint_a = _create_scope(setup_client, "a")
    client_b, _location_b, _endpoint_b = _create_scope(setup_client, "b")
    tag_a = setup_client.post(
        "/api/tags",
        json={
            "name": "Visible tag",
            "scope_type": "location",
            "client_id": client_a,
            "location_id": location_a,
        },
    ).json()
    tag_b = setup_client.post(
        "/api/tags",
        json={
            "name": "Hidden tag",
            "scope_type": "client",
            "client_id": client_b,
        },
    ).json()
    view_a = _create_saved_view(
        setup_client,
        name="Visible view",
        client_id=client_a,
        location_id=location_a,
    )
    view_b = _create_saved_view(
        setup_client,
        name="Hidden view",
        client_id=client_b,
    )
    group_a = _create_group(setup_client, "Visible group", str(view_a["saved_view_id"]))
    group_b = _create_group(setup_client, "Hidden group", str(view_b["saved_view_id"]))

    app = create_app(
        database_url=f"sqlite:///{db_path}",
        auth_mode="protected",
        browser_session_key=b"f" * 32,
        oidc_client=_FakeOidcClient(),
        oidc_config=_oidc_config(),
    )
    with TestClient(app, base_url="https://sha.example.test") as client:
        _complete_login(client)
        now = to_utc_z(utc_now())
        with app.state.store.session() as session:
            with session.begin():
                user = session.scalar(select(User))
                operator_role = session.scalar(select(Role).where(Role.key == "operator"))
                assert user is not None and operator_role is not None
                user.status = "active"
                session.add(
                    UserRoleBinding(
                        binding_id=generate_prefixed_id("urb"),
                        user_id=user.user_id,
                        role_id=operator_role.role_id,
                        scope_type="location",
                        client_id=client_a,
                        location_id=location_a,
                        created_by="test",
                        created_at=now,
                        revoked_at=None,
                    )
                )

        assert [item["tag_id"] for item in client.get("/api/tags").json()["items"]] == [
            tag_a["tag_id"]
        ]
        assert tag_b["tag_id"] not in {
            item["tag_id"] for item in client.get("/api/tags").json()["items"]
        }
        assert [
            item["saved_view_id"]
            for item in client.get("/api/saved-views").json()["items"]
        ] == [view_a["saved_view_id"]]
        assert [
            item["dynamic_group_id"]
            for item in client.get("/api/dynamic-groups").json()["items"]
        ] == [group_a["dynamic_group_id"]]
        visible_preview = client.get(
            f"/api/dynamic-groups/{group_a['dynamic_group_id']}/preview"
        )
        assert visible_preview.status_code == 200
        assert [item["endpoint_id"] for item in visible_preview.json()["items"]] == [
            endpoint_a
        ]
        assert client.get(
            f"/api/dynamic-groups/{group_b['dynamic_group_id']}/preview"
        ).status_code == 404
        assert client.get("/api/tags", params={"client_id": client_b}).status_code == 404
