from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import logging
import os
import sqlite3
from threading import Lock
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from app.authorization import LEGACY_OPERATOR_PERMISSIONS, classify_api_routes
from app.bootstrap_admin import bootstrap_global_admin
from app.browser_auth import (
    OIDC_TRANSACTION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    OidcClientConfig,
    build_oidc_client,
    keyed_hash,
    validate_oidc_config,
)
import app.config as config_module
from app.main import create_app
from app.models import (
    AuditEvent,
    BrowserSession,
    OidcIdentity,
    OidcLoginTransaction,
    Role,
    User,
    UserRoleBinding,
)
from app.utils import generate_prefixed_id, to_utc_z, utc_now


class FakeOidcClient:
    def __init__(
        self,
        issuer: str,
        *,
        subject: str = "oidc-subject",
        claims_issuer: str | None = None,
    ) -> None:
        self.issuer = issuer
        self.subject = subject
        self.claims_issuer = claims_issuer or issuer

    async def load_server_metadata(self) -> dict[str, object]:
        return {
            "issuer": self.issuer,
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        }

    async def create_authorization_url(self, redirect_uri: str) -> dict[str, str]:
        assert redirect_uri == "https://sha.example.test/api/auth/oidc/callback"
        return {
            "url": "https://idp.example.test/authorize?opaque=1",
            "state": "provider-state-secret",
            "nonce": "provider-nonce-secret",
            "code_verifier": "provider-pkce-verifier-secret",
        }

    async def fetch_access_token(self, **kwargs: str) -> dict[str, str]:
        assert kwargs == {
            "redirect_uri": "https://sha.example.test/api/auth/oidc/callback",
            "code": "authorization-code-secret",
            "code_verifier": "provider-pkce-verifier-secret",
        }
        return {
            "access_token": "provider-access-token-secret",
            "id_token": "provider-id-token-secret",
        }

    async def parse_id_token(
        self,
        token: dict[str, str],
        *,
        nonce: str,
        claims_options: dict[str, object],
    ) -> dict[str, str]:
        assert token["access_token"] == "provider-access-token-secret"
        assert nonce == "provider-nonce-secret"
        assert claims_options == {"iss": {"values": [self.issuer]}}
        return {
            "iss": self.claims_issuer,
            "sub": self.subject,
            "name": "Incident Responder",
            "email": "responder@example.test",
        }


class ConcurrentFakeOidcClient(FakeOidcClient):
    def __init__(self, issuer: str) -> None:
        super().__init__(issuer, subject="shared-concurrent-subject")
        self._lock = Lock()
        self.issued: list[tuple[str, str]] = []

    async def create_authorization_url(self, redirect_uri: str) -> dict[str, str]:
        assert redirect_uri == "https://sha.example.test/api/auth/oidc/callback"
        with self._lock:
            attempt = len(self.issued) + 1
            state = f"concurrent-state-{attempt}"
            code = f"concurrent-code-{attempt}"
            self.issued.append((state, code))
        return {
            "url": f"https://idp.example.test/authorize?attempt={attempt}",
            "state": state,
            "nonce": f"concurrent-nonce-{attempt}",
            "code_verifier": f"concurrent-verifier-{attempt}",
        }

    async def fetch_access_token(self, **kwargs: str) -> dict[str, str]:
        attempt = kwargs["code"].removeprefix("concurrent-code-")
        assert kwargs["code_verifier"] == f"concurrent-verifier-{attempt}"
        return {"id_token": f"concurrent-id-token-{attempt}", "attempt": attempt}

    async def parse_id_token(
        self,
        token: dict[str, str],
        *,
        nonce: str,
        claims_options: dict[str, object],
    ) -> dict[str, str]:
        attempt = token["attempt"]
        assert nonce == f"concurrent-nonce-{attempt}"
        assert claims_options == {"iss": {"values": [self.issuer]}}
        return {
            "iss": self.issuer,
            "sub": self.subject,
            "name": "Concurrent user",
        }


def _oidc_config() -> OidcClientConfig:
    return OidcClientConfig(
        issuer="https://idp.example.test/tenant-a",
        metadata_url="https://idp.example.test/tenant-a/.well-known/openid-configuration",
        client_id="sha-client",
        client_secret="oidc-client-secret",
        public_base_url="https://sha.example.test",
    )


def _oidc_app(db_path, fake_client: FakeOidcClient):
    return create_app(
        database_url=f"sqlite:///{db_path}",
        auth_mode="protected",
        browser_session_key=b"b" * 32,
        oidc_client=fake_client,
        oidc_config=_oidc_config(),
    )


def _complete_login(client: TestClient) -> tuple[str, str]:
    login = client.get("/api/auth/oidc/login?return_to=/fleet", follow_redirects=False)
    assert login.status_code == 302
    assert login.headers["location"] == "https://idp.example.test/authorize?opaque=1"
    assert login.headers["cache-control"] == "no-store"
    transaction_binding = client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME)
    assert transaction_binding
    callback = client.get(
        "/api/auth/oidc/callback",
        params={"state": "provider-state-secret", "code": "authorization-code-secret"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/fleet"
    assert callback.headers["cache-control"] == "no-store"
    session_header = next(
        header
        for header in callback.headers.get_list("set-cookie")
        if header.startswith(f"{SESSION_COOKIE_NAME}=")
    )
    assert "Secure" in session_header
    assert "HttpOnly" in session_header
    assert "SameSite=lax" in session_header
    assert "Path=/" in session_header
    raw_session_token = client.cookies.get(SESSION_COOKIE_NAME)
    assert raw_session_token
    return str(transaction_binding), str(raw_session_token)


def test_oidc_flow_is_one_shot_pending_and_stores_only_hashes(db_path) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        transaction_binding, raw_session_token = _complete_login(client)

        with app.state.store.session() as session:
            transaction = session.scalar(select(OidcLoginTransaction))
            browser_session = session.scalar(select(BrowserSession))
            user = session.scalar(select(User))
            identity = session.scalar(select(OidcIdentity))
            assert transaction is not None
            assert transaction.consumed_at is not None
            assert transaction.state_hash != "provider-state-secret"
            assert transaction.encrypted_code_verifier != "provider-pkce-verifier-secret"
            assert browser_session is not None
            assert browser_session.token_hash == keyed_hash(
                b"b" * 32,
                "session-token",
                raw_session_token,
            )
            assert raw_session_token != browser_session.token_hash
            assert user is not None and user.status == "pending"
            assert identity is not None
            assert (identity.issuer, identity.subject) == (
                _oidc_config().issuer,
                "oidc-subject",
            )

        auth_session = client.get("/api/auth/session")
        assert auth_session.status_code == 200
        assert auth_session.headers["cache-control"] == "no-store"
        assert auth_session.json()["status"] == "pending"
        assert auth_session.json()["bindings"] == []
        assert client.get("/api/endpoints").status_code == 403

        replay = client.get(
            "/api/auth/oidc/callback",
            params={"state": "provider-state-secret", "code": "authorization-code-secret"},
            headers={"cookie": f"{OIDC_TRANSACTION_COOKIE_NAME}={transaction_binding}"},
            follow_redirects=False,
        )
        assert replay.status_code == 401

        with sqlite3.connect(db_path) as connection:
            database_dump = "\n".join(connection.iterdump())
        for provider_secret in (
            "provider-access-token-secret",
            "provider-id-token-secret",
            "provider-pkce-verifier-secret",
            raw_session_token,
        ):
            assert provider_secret not in database_dump


def test_oidc_state_and_browser_binding_are_both_required(db_path) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        login = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert login.status_code == 302
        correct_binding = client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME)
        assert correct_binding

        wrong_state = client.get(
            "/api/auth/oidc/callback",
            params={"state": "wrong-state", "code": "authorization-code-secret"},
            follow_redirects=False,
        )
        assert wrong_state.status_code == 401
        client.cookies.set(
            OIDC_TRANSACTION_COOKIE_NAME,
            "wrong-browser-binding",
            domain="sha.example.test",
            path="/",
        )
        wrong_binding = client.get(
            "/api/auth/oidc/callback",
            params={"state": "provider-state-secret", "code": "authorization-code-secret"},
            follow_redirects=False,
        )
        assert wrong_binding.status_code == 401

        client.cookies.set(
            OIDC_TRANSACTION_COOKIE_NAME,
            str(correct_binding),
            domain="sha.example.test",
            path="/",
        )
        completed = client.get(
            "/api/auth/oidc/callback",
            params={"state": "provider-state-secret", "code": "authorization-code-secret"},
            follow_redirects=False,
        )
        assert completed.status_code == 303


def test_simultaneous_first_login_reuses_one_exact_identity(db_path) -> None:
    fake = ConcurrentFakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with (
        TestClient(app, base_url="https://sha.example.test") as first_client,
        TestClient(app, base_url="https://sha.example.test") as second_client,
    ):
        assert first_client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 302
        assert second_client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 302

        def complete(client: TestClient, state: str, code: str):
            return client.get(
                "/api/auth/oidc/callback",
                params={"state": state, "code": code},
                follow_redirects=False,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(complete, first_client, *fake.issued[0])
            second = pool.submit(complete, second_client, *fake.issued[1])
            responses = [first.result(), second.result()]
        assert [response.status_code for response in responses] == [303, 303]

        with app.state.store.session() as session:
            assert len(session.scalars(select(User)).all()) == 1
            assert len(session.scalars(select(OidcIdentity)).all()) == 1
            assert len(session.scalars(select(BrowserSession)).all()) == 2


def test_bootstrap_promotes_exact_identity_and_refuses_second_admin(db_path) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        _complete_login(client)
        user, identity, binding = bootstrap_global_admin(
            app.state.store,
            issuer=_oidc_config().issuer,
            subject="oidc-subject",
            display_name="Bootstrap Admin",
        )
        assert user.status == "active"
        assert identity.user_id == user.user_id
        assert binding.scope_type == "global"

        session_response = client.get("/api/auth/session")
        assert session_response.status_code == 200
        assert session_response.json()["status"] == "active"
        assert session_response.json()["bindings"][0]["role"] == "admin"

        with pytest.raises(RuntimeError, match="active global Admin binding already exists"):
            bootstrap_global_admin(
                app.state.store,
                issuer=_oidc_config().issuer,
                subject="different-subject",
            )


@pytest.mark.parametrize("expiry_field", ["idle_expires_at", "absolute_expires_at"])
def test_browser_session_idle_and_absolute_expiry_are_enforced(
    db_path,
    expiry_field: str,
) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        _complete_login(client)
        with app.state.store.session() as session:
            with session.begin():
                browser_session = session.scalar(select(BrowserSession))
                assert browser_session is not None
                setattr(browser_session, expiry_field, "2000-01-01T00:00:00Z")
        expired = client.get("/api/auth/session")
        assert expired.status_code == 401
        assert expired.headers["cache-control"] == "no-store"
        assert any(
            header.startswith(f"{SESSION_COOKIE_NAME}=") and "Max-Age=0" in header
            for header in expired.headers.get_list("set-cookie")
        )


def test_logout_all_revokes_every_server_session_and_clears_cookie(db_path) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        _complete_login(client)
        session_response = client.get("/api/auth/session")
        csrf = session_response.json()["csrf_token"]
        with app.state.store.session() as session:
            with session.begin():
                current = session.scalar(select(BrowserSession))
                assert current is not None
                session.add(
                    BrowserSession(
                        session_id=generate_prefixed_id("sess"),
                        user_id=current.user_id,
                        identity_id=current.identity_id,
                        token_hash="f" * 64,
                        hash_key_id="primary",
                        authenticated_at=current.authenticated_at,
                        last_seen_at=current.last_seen_at,
                        idle_expires_at=current.idle_expires_at,
                        absolute_expires_at=current.absolute_expires_at,
                        revoked_at=None,
                        created_at=current.created_at,
                        updated_at=current.updated_at,
                    )
                )
        logout = client.post(
            "/api/auth/logout-all",
            headers={
                "origin": "https://sha.example.test",
                "x-sha-csrf": csrf,
                "sec-fetch-site": "same-origin",
            },
        )
        assert logout.status_code == 200
        assert logout.headers["cache-control"] == "no-store"
        assert any(
            header.startswith(f"{SESSION_COOKIE_NAME}=") and "Max-Age=0" in header
            for header in logout.headers.get_list("set-cookie")
        )
        with app.state.store.session() as session:
            assert all(
                browser_session.revoked_at is not None
                for browser_session in session.scalars(select(BrowserSession)).all()
            )
        assert client.get("/api/auth/session").status_code == 401


@pytest.mark.parametrize("failure_mode", ["expired", "provider_error"])
def test_invalid_oidc_transactions_fail_closed(db_path, failure_mode: str) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        login = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert login.status_code == 302
        if failure_mode == "expired":
            with app.state.store.session() as session:
                with session.begin():
                    transaction = session.scalar(select(OidcLoginTransaction))
                    assert transaction is not None
                    transaction.expires_at = "2000-01-01T00:00:00Z"
            callback = client.get(
                "/api/auth/oidc/callback",
                params={"state": "provider-state-secret", "code": "authorization-code-secret"},
                follow_redirects=False,
            )
        else:
            callback = client.get(
                "/api/auth/oidc/callback",
                params={"state": "provider-state-secret", "error": "access_denied"},
                follow_redirects=False,
            )
        assert callback.status_code == 401
        with app.state.store.session() as session:
            transaction = session.scalar(select(OidcLoginTransaction))
            assert transaction is not None
            assert (transaction.consumed_at is not None) is (failure_mode == "provider_error")
            assert session.scalar(select(BrowserSession)) is None


def test_oidc_claim_issuer_must_match_exactly(db_path) -> None:
    fake = FakeOidcClient(
        _oidc_config().issuer,
        claims_issuer="https://idp.example.test/tenant-b",
    )
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        login = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert login.status_code == 302
        callback = client.get(
            "/api/auth/oidc/callback",
            params={"state": "provider-state-secret", "code": "authorization-code-secret"},
            follow_redirects=False,
        )
        assert callback.status_code == 401
        with app.state.store.session() as session:
            assert session.scalar(select(User)) is None
            assert session.scalar(select(BrowserSession)) is None


def test_disabled_oidc_identity_is_denied_and_audited(db_path) -> None:
    fake = FakeOidcClient(_oidc_config().issuer)
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        now = to_utc_z(utc_now())
        with app.state.store.session() as session:
            with session.begin():
                user = User(
                    user_id="usr_disabled",
                    status="disabled",
                    display_name="Disabled user",
                    email_snapshot=None,
                    last_login_at=None,
                    disabled_at=now,
                    created_at=now,
                    updated_at=now,
                )
                session.add(user)
                session.flush()
                session.add(
                    OidcIdentity(
                        identity_id="oidc_disabled",
                        user_id=user.user_id,
                        issuer=_oidc_config().issuer,
                        subject="oidc-subject",
                        display_name_snapshot="Disabled user",
                        email_snapshot=None,
                        created_at=now,
                        updated_at=now,
                        last_seen_at=None,
                    )
                )
        login = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert login.status_code == 302
        callback = client.get(
            "/api/auth/oidc/callback",
            params={"state": "provider-state-secret", "code": "authorization-code-secret"},
            follow_redirects=False,
        )
        assert callback.status_code == 403
        with app.state.store.session() as session:
            assert session.scalar(select(BrowserSession)) is None
            event = session.scalar(select(AuditEvent).where(AuditEvent.outcome == "denied"))
            assert event is not None
            assert event.actor == "user:usr_disabled"


def test_location_scoped_session_conceals_foreign_objects_and_enforces_csrf(
    db_path,
    make_client,
) -> None:
    setup_client = make_client(db_path)
    scopes: list[tuple[str, str, str]] = []
    for suffix in ("a", "b"):
        created_client = setup_client.post(
            "/api/clients",
            json={"key": f"tenant-{suffix}", "name": f"Tenant {suffix.upper()}"},
        ).json()
        created_location = setup_client.post(
            f"/api/clients/{created_client['client_id']}/locations",
            json={"key": f"site-{suffix}", "name": f"Site {suffix.upper()}"},
        ).json()
        endpoint = setup_client.post(
            "/api/endpoints/enroll",
            json={
                "agent_fingerprint": f"fingerprint-{suffix}",
                "hostname": f"host-{suffix}",
                "platform": "linux",
                "agent_version": "1.0.0",
                "tenant_id": f"tenant-{suffix}",
                "site_id": f"site-{suffix}",
            },
        ).json()
        scopes.append(
            (
                created_client["client_id"],
                created_location["location_id"],
                endpoint["endpoint_id"],
            )
        )

    fake = FakeOidcClient(_oidc_config().issuer, subject="scoped-user")
    app = _oidc_app(db_path, fake)
    with TestClient(app, base_url="https://sha.example.test") as client:
        _complete_login(client)
        now = to_utc_z(utc_now())
        with app.state.store.session() as session:
            with session.begin():
                user = session.scalar(select(User))
                admin_role = session.scalar(select(Role).where(Role.key == "admin"))
                assert user is not None and admin_role is not None
                user.status = "active"
                session.add(
                    UserRoleBinding(
                        binding_id=generate_prefixed_id("urb"),
                        user_id=user.user_id,
                        role_id=admin_role.role_id,
                        scope_type="location",
                        client_id=scopes[0][0],
                        location_id=scopes[0][1],
                        created_by="test",
                        created_at=now,
                        revoked_at=None,
                    )
                )

        auth_session = client.get("/api/auth/session")
        csrf = auth_session.json()["csrf_token"]
        listed = client.get("/api/endpoints")
        assert [item["endpoint_id"] for item in listed.json()["items"]] == [scopes[0][2]]
        assert client.get(f"/api/endpoints/{scopes[1][2]}").status_code == 404
        assert client.get(
            "/api/endpoints",
            params={"client_id": scopes[1][0], "location_id": scopes[1][1]},
        ).status_code == 404
        evidence = client.get("/api/compliance/evidence")
        assert evidence.status_code == 200
        assert [item["endpoint_id"] for item in evidence.json()["endpoints"]] == [
            scopes[0][2]
        ]
        assert client.get(
            "/api/compliance/evidence",
            params={"client_id": scopes[1][0], "location_id": scopes[1][1]},
        ).status_code == 404
        assert client.get(
            "/api/endpoints",
            params={"client_id": "cl_unknown", "location_id": "loc_unknown"},
        ).status_code == 404

        assert client.post(
            f"/api/endpoints/{scopes[0][2]}/approve-enrollment"
        ).status_code == 403
        mutation_headers = {
            "origin": "https://sha.example.test",
            "x-sha-csrf": csrf,
            "sec-fetch-site": "same-origin",
        }
        assert client.post(
            f"/api/endpoints/{scopes[1][2]}/approve-enrollment",
            headers=mutation_headers,
        ).status_code == 404
        assert client.post(
            f"/api/endpoints/{scopes[0][2]}/approve-enrollment",
            headers={**mutation_headers, "origin": "https://attacker.example.test"},
        ).status_code == 403
        assert client.post(
            f"/api/endpoints/{scopes[0][2]}/approve-enrollment",
            headers=mutation_headers,
        ).status_code == 200
        audit = client.get("/api/audit-events")
        assert audit.status_code == 200
        assert audit.json()["items"]
        assert {
            item["client_id"] for item in audit.json()["items"]
        } == {scopes[0][0]}
        assert client.get(
            "/api/audit-events",
            params={"client_id": scopes[1][0], "location_id": scopes[1][1]},
        ).status_code == 404
        assert client.patch(
            f"/api/users/{auth_session.json()['subject'].removeprefix('user:')}",
            headers=mutation_headers,
            json={"status": "active"},
        ).status_code == 403


def test_every_api_route_has_a_fail_closed_authorization_classification() -> None:
    app = create_app(database_url="sqlite:///:memory:")
    policies = classify_api_routes(app)
    assert policies == app.state.route_authorization_policies
    assert policies[("POST", "/api/response-actions")] == "human:response_action.create"
    assert policies[("GET", "/api/auth/oidc/login")] == "public:oidc_login"
    assert policies[("POST", "/api/agent/bootstrap")] == "enrollment:bootstrap"
    assert LEGACY_OPERATOR_PERMISSIONS.isdisjoint(
        {
            "bulk_action.execute",
            "command.execute",
            "containment.execute",
            "credential.admin",
            "enrollment.admin",
            "schedule.create",
            "terminal.open",
        }
    )


def test_oidc_configuration_is_validated_for_injected_clients_and_secure_ca_files(
    db_path,
    tmp_path,
    monkeypatch,
) -> None:
    config = _oidc_config()
    with pytest.raises(ValueError, match="must not contain a path"):
        create_app(
            database_url=f"sqlite:///{db_path}",
            browser_session_key=b"b" * 32,
            oidc_client=FakeOidcClient(config.issuer),
            oidc_config=replace(config, public_base_url="https://sha.example.test/subpath"),
        )

    ca_bundle = tmp_path / "oidc-ca.pem"
    ca_bundle.write_text("not a certificate", encoding="utf-8")
    ca_bundle.chmod(0o622)
    with pytest.raises(ValueError, match="group- or world-writable"):
        validate_oidc_config(replace(config, ca_bundle_file=str(ca_bundle)))
    ca_bundle.chmod(0o644)
    with pytest.raises(ValueError, match="parseable PEM certificates"):
        validate_oidc_config(replace(config, ca_bundle_file=str(ca_bundle)))

    real_fstat = config_module.os.fstat

    def untrusted_owner(descriptor: int) -> SimpleNamespace:
        file_stat = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=file_stat.st_mode,
            st_uid=max(1, os.geteuid() + 10_000),
        )

    monkeypatch.setattr(config_module.os, "fstat", untrusted_owner)
    with pytest.raises(ValueError, match="owned by root or the service effective user"):
        validate_oidc_config(replace(config, ca_bundle_file=str(ca_bundle)))

    for logger_name in ("authlib", "httpx", "httpcore"):
        logging.getLogger(logger_name).setLevel(logging.DEBUG)
    build_oidc_client(config)
    assert all(
        logging.getLogger(logger_name).getEffectiveLevel() >= logging.INFO
        for logger_name in ("authlib", "httpx", "httpcore")
    )
