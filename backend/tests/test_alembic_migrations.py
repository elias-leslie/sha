from __future__ import annotations

from pathlib import Path
import sqlite3

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.db import DatabaseStore


_ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
_PRIOR_REVISION = "20260717_0001"
_HEAD_REVISION = "20260717_0009"
_AUTHORIZATION_REVISION = "20260717_0007"
_FLEET_METADATA_REVISION = "20260717_0008"


def _alembic_config(database_url: str, connection: Connection) -> Config:
    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["connection"] = connection
    return config


def test_authorization_migration_empty_downgrade_is_safe(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                _AUTHORIZATION_REVISION,
            )
            command.downgrade(_alembic_config(database_url, connection), "20260717_0006")
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == "20260717_0006"
            assert "users" not in {
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
    finally:
        engine.dispose()


def test_fleet_metadata_migration_empty_downgrade_is_safe(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                _FLEET_METADATA_REVISION,
            )
            table_names = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            assert {
                "tags",
                "endpoint_tag_assignments",
                "saved_views",
                "saved_view_versions",
                "dynamic_groups",
            } <= table_names
            assert connection.exec_driver_sql(
                """
                SELECT COUNT(*) FROM role_permissions
                WHERE permission IN (
                    'tag.read', 'tag.manage', 'saved_view.read',
                    'saved_view.manage', 'dynamic_group.read',
                    'dynamic_group.manage'
                )
                """
            ).scalar_one() == 24
            command.downgrade(
                _alembic_config(database_url, connection),
                _AUTHORIZATION_REVISION,
            )
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == _AUTHORIZATION_REVISION
            remaining_tables = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            assert "tags" not in remaining_tables
            assert connection.exec_driver_sql(
                "SELECT COUNT(*) FROM role_permissions WHERE permission LIKE 'tag.%'"
            ).scalar_one() == 0
    finally:
        engine.dispose()


def test_fleet_metadata_downgrade_refuses_live_rows_without_schema_change(
    db_path: Path,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                _FLEET_METADATA_REVISION,
            )
            connection.exec_driver_sql(
                """
                INSERT INTO tags (
                    tag_id, name, name_normalized, scope_type, scope_key,
                    created_by, created_at, updated_at
                ) VALUES (
                    'tag_downgrade', 'Downgrade', 'downgrade', 'global',
                    'global', 'test', '2026-07-17T12:00:00Z',
                    '2026-07-17T12:00:00Z'
                )
                """
            )
            with pytest.raises(RuntimeError, match="live fleet metadata in tags"):
                command.downgrade(
                    _alembic_config(database_url, connection),
                    _AUTHORIZATION_REVISION,
                )
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == _FLEET_METADATA_REVISION
            assert connection.exec_driver_sql(
                "SELECT name FROM tags WHERE tag_id = 'tag_downgrade'"
            ).scalar_one() == "Downgrade"
    finally:
        engine.dispose()


@pytest.mark.parametrize("mutation", ["user", "role_catalog", "permission_catalog"])
def test_authorization_downgrade_refuses_security_data_without_schema_change(
    db_path: Path,
    mutation: str,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                _AUTHORIZATION_REVISION,
            )
            if mutation == "user":
                connection.exec_driver_sql(
                    """
                    INSERT INTO users (
                        user_id, status, display_name, created_at, updated_at
                    ) VALUES (
                        'usr_downgrade_refusal', 'pending', 'Pending user',
                        '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                    )
                    """
                )
                expected_message = "users"
            elif mutation == "role_catalog":
                connection.exec_driver_sql(
                    "UPDATE roles SET name = 'Changed Admin' WHERE key = 'admin'"
                )
                expected_message = "modified role or permission catalog"
            else:
                connection.exec_driver_sql(
                    """
                    INSERT INTO role_permissions (role_id, permission)
                    VALUES ('role_viewer', 'terminal.open')
                    """
                )
                expected_message = "modified role or permission catalog"
            with pytest.raises(RuntimeError, match=expected_message):
                command.downgrade(
                    _alembic_config(database_url, connection),
                    "20260717_0006",
                )
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == _AUTHORIZATION_REVISION
            if mutation == "user":
                assert connection.exec_driver_sql(
                    "SELECT display_name FROM users WHERE user_id = 'usr_downgrade_refusal'"
                ).scalar_one() == "Pending user"
            elif mutation == "role_catalog":
                assert connection.exec_driver_sql(
                    "SELECT name FROM roles WHERE key = 'admin'"
                ).scalar_one() == "Changed Admin"
            else:
                assert connection.exec_driver_sql(
                    """
                    SELECT COUNT(*) FROM role_permissions
                    WHERE role_id = 'role_viewer' AND permission = 'terminal.open'
                    """
                ).scalar_one() == 1
    finally:
        engine.dispose()


def test_audit_events_are_database_enforced_append_only(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(_alembic_config(database_url, connection), _HEAD_REVISION)
            connection.exec_driver_sql(
                """
                INSERT INTO audit_events (
                    audit_event_id, event_type, outcome, actor, auth_method,
                    metadata_json, created_at
                ) VALUES (
                    'aud_append_only', 'test_event', 'success', 'test',
                    'test', '{}', '2026-07-17T12:00:00Z'
                )
                """
            )
            with pytest.raises(IntegrityError, match="append-only"):
                connection.exec_driver_sql(
                    "UPDATE audit_events SET outcome = 'failure' WHERE audit_event_id = 'aud_append_only'"
                )
            with pytest.raises(IntegrityError, match="append-only"):
                connection.exec_driver_sql(
                    "DELETE FROM audit_events WHERE audit_event_id = 'aud_append_only'"
                )
            assert connection.exec_driver_sql(
                "SELECT outcome FROM audit_events WHERE audit_event_id = 'aud_append_only'"
            ).scalar_one() == "success"
    finally:
        engine.dispose()


def _create_unversioned_prior_schema(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                _PRIOR_REVISION,
            )
            connection.exec_driver_sql(
                """
                INSERT INTO endpoints (
                    endpoint_id, agent_fingerprint, hostname, platform,
                    agent_version, status, last_seen_at, created_at, updated_at
                ) VALUES (
                    'ep_existing', 'fingerprint-existing', 'existing-host', 'windows',
                    '0.1.0', 'active', '2026-07-17T12:00:00Z',
                    '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO posture_snapshots (
                    snapshot_id, endpoint_id, observed_at, platform_profile, created_at
                ) VALUES
                    (
                        'snap_existing', 'ep_existing', '2026-07-17T12:00:00Z',
                        'windows-workstation', '2026-07-17T12:00:00Z'
                    ),
                    (
                        'snap_duplicate', 'ep_existing', '2026-07-17T12:01:00Z',
                        'windows-workstation', '2026-07-17T12:01:00Z'
                    ),
                    (
                        'snap_new_alias', 'ep_existing', '2026-07-17T12:02:00Z',
                        'windows-workstation', '2026-07-17T12:02:00Z'
                    )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO posture_results (
                    result_id, snapshot_id, endpoint_id, control_key,
                    control_key_normalized, status, evidence_summary,
                    reboot_required, created_at
                ) VALUES
                    (
                        'result_existing', 'snap_existing', 'ep_existing',
                        'windows.firewall.all-profiles-enabled',
                        'windows.firewall.all-profiles-enabled', 'fail',
                        'Legacy control identifier', false, '2026-07-17T12:00:00Z'
                    ),
                    (
                        'result_duplicate_alias', 'snap_duplicate', 'ep_existing',
                        'windows.firewall.all-profiles-enabled',
                        'windows.firewall.all-profiles-enabled', 'fail',
                        'Duplicate legacy identifier', false, '2026-07-17T12:01:00Z'
                    ),
                    (
                        'result_duplicate_canonical', 'snap_duplicate', 'ep_existing',
                        'control.windows.firewall-all-profiles',
                        'control.windows.firewall-all-profiles', 'pass',
                        'Canonical identifier', false, '2026-07-17T12:01:00Z'
                    ),
                    (
                        'result_new_alias', 'snap_new_alias', 'ep_existing',
                        'windows.defender.real_time_protection',
                        'windows.defender.real_time_protection', 'pass',
                        'Later legacy identifier', false, '2026-07-17T12:02:00Z'
                    )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO approval_grants (
                    approval_grant_id, endpoint_ids, allowed_actions, control_ids,
                    troubleshooting_scopes, requested_by, approved_by, reason,
                    expires_at, status, created_at, updated_at
                ) VALUES (
                    'grant_existing', '["ep_existing"]', '["apply_control"]',
                    '["control.windows.firewall-all-profiles"]', '[]',
                    'operator', 'approver', 'Existing approved action',
                    '2026-07-18T12:00:00Z', 'approved',
                    '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO response_actions (
                    response_action_id, endpoint_id, approval_grant_id, action,
                    control_id, requested_by, reason, status, created_at, updated_at
                ) VALUES (
                    'act_existing', 'ep_existing', 'grant_existing', 'apply_control',
                    'control.windows.firewall-all-profiles', 'operator',
                    'Existing queued action', 'queued',
                    '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql("DROP TABLE alembic_version")
    finally:
        engine.dispose()


def _create_device_identity_prior_schema(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            command.upgrade(
                _alembic_config(database_url, connection),
                "20260717_0005",
            )
            connection.exec_driver_sql(
                """
                INSERT INTO endpoints (
                    endpoint_id, agent_fingerprint, hostname, platform,
                    agent_version, client_id, location_id, status, last_seen_at,
                    created_at, updated_at
                ) VALUES (
                    'ep_identity', 'fingerprint-identity', 'identity-host', 'linux',
                    'legacy-agent', 'cl_legacy_quarantine', 'loc_legacy_quarantine',
                    'active', '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z',
                    '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO posture_snapshots (
                    snapshot_id, endpoint_id, observed_at, platform_profile, created_at
                ) VALUES (
                    'snap_identity', 'ep_identity', '2026-07-17T12:00:00Z',
                    'linux-server', '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO posture_results (
                    result_id, snapshot_id, endpoint_id, control_key,
                    control_key_normalized, status, evidence_summary,
                    reboot_required, created_at
                ) VALUES (
                    'result_identity', 'snap_identity', 'ep_identity',
                    'control.linux.firewall-enabled', 'control.linux.firewall-enabled',
                    'pass', 'Identity migration preservation row', false,
                    '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO approval_grants (
                    approval_grant_id, endpoint_ids, allowed_actions, control_ids,
                    troubleshooting_scopes, requested_by, approved_by, reason,
                    expires_at, status, created_at, updated_at
                ) VALUES (
                    'grant_identity', '["ep_identity"]', '["apply_control"]',
                    '["control.linux.firewall-enabled"]', '[]', 'operator',
                    'approver', 'Identity migration preservation grant',
                    '2026-07-18T12:00:00Z', 'approved',
                    '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO response_actions (
                    response_action_id, endpoint_id, approval_grant_id, action,
                    control_id, idempotency_key, requested_by, reason, status,
                    attempt_count, created_at, updated_at
                ) VALUES (
                    'act_identity', 'ep_identity', 'grant_identity', 'apply_control',
                    'control.linux.firewall-enabled', 'identity-action', 'operator',
                    'Identity migration preservation action', 'queued', 0,
                    '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """
            )
    finally:
        engine.dispose()


def test_upgrade_adopts_prior_unversioned_schema_and_preserves_rows(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    _create_unversioned_prior_schema(database_url)

    store = DatabaseStore(database_url, migration_mode="upgrade")
    try:
        store.prepare()
    finally:
        store.dispose()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchall() == [
            (_HEAD_REVISION,)
        ]
        assert connection.execute(
            """
            SELECT control_key, control_key_normalized
            FROM posture_results
            WHERE result_id = 'result_existing'
            """
        ).fetchone() == (
            "control.windows.firewall-all-profiles",
            "control.windows.firewall-all-profiles",
        )
        assert connection.execute(
            """
            SELECT result_id
            FROM posture_results
            WHERE snapshot_id = 'snap_duplicate'
            ORDER BY result_id
            """
        ).fetchall() == [("result_duplicate_canonical",)]
        assert connection.execute(
            """
            SELECT control_key, control_key_normalized
            FROM posture_results
            WHERE result_id = 'result_new_alias'
            """
        ).fetchone() == (
            "control.windows.defender-real-time-protection",
            "control.windows.defender-real-time-protection",
        )
        assert connection.execute(
            """
            SELECT idempotency_key, lease_token_hash, lease_expires_at, leased_at,
                   attempt_count, status
            FROM response_actions
            WHERE response_action_id = 'act_existing'
            """
        ).fetchone() == ("act_existing", None, None, None, 0, "queued")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert {
            (str(row[2]), str(row[3]), str(row[6]))
            for row in connection.execute("PRAGMA foreign_key_list(response_actions)")
        } == {
            ("approval_grants", "approval_grant_id", "CASCADE"),
            ("endpoints", "endpoint_id", "CASCADE"),
        }


def test_response_action_lease_migration_enforces_new_constraints(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    _create_unversioned_prior_schema(database_url)

    store = DatabaseStore(database_url, migration_mode="upgrade")
    try:
        store.prepare()
    finally:
        store.dispose()

    with sqlite3.connect(db_path) as connection:
        columns = {
            str(row[1]): {"not_null": bool(row[3]), "default": row[4]}
            for row in connection.execute("PRAGMA table_info(response_actions)")
        }
        assert columns["idempotency_key"] == {"not_null": True, "default": None}
        assert columns["attempt_count"] == {"not_null": True, "default": None}

        connection.execute(
            """
            UPDATE response_actions
            SET status = 'leased', lease_token_hash = ?, attempt_count = 1
            WHERE response_action_id = 'act_existing'
            """,
            ("a" * 64,),
        )
        connection.commit()

        with sqlite3.connect(db_path) as constraint_connection:
            with pytest.raises(sqlite3.IntegrityError), constraint_connection:
                constraint_connection.execute(
                    "UPDATE response_actions SET status = 'invalid' WHERE response_action_id = 'act_existing'"
                )

            with pytest.raises(sqlite3.IntegrityError), constraint_connection:
                constraint_connection.execute(
                    "UPDATE response_actions SET idempotency_key = NULL WHERE response_action_id = 'act_existing'"
                )

            with pytest.raises(sqlite3.IntegrityError), constraint_connection:
                constraint_connection.execute(
                    """
                    INSERT INTO response_actions (
                        response_action_id, endpoint_id, approval_grant_id, action,
                        control_id, idempotency_key, requested_by, reason, status,
                        attempt_count, created_at, updated_at
                    ) VALUES (
                        'act_duplicate', 'ep_existing', 'grant_existing', 'apply_control',
                        'control.windows.firewall-all-profiles', 'act_existing',
                        'operator', 'Duplicate idempotency key', 'queued', 0,
                        '2026-07-17T12:01:00Z', '2026-07-17T12:01:00Z'
                    )
                    """
                )


def test_response_action_lease_migration_downgrade_requeues_active_lease(
    db_path: Path,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    _create_unversioned_prior_schema(database_url)

    store = DatabaseStore(database_url, migration_mode="upgrade")
    try:
        store.prepare()
    finally:
        store.dispose()

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                """
                UPDATE response_actions
                SET status = 'leased', lease_token_hash = ?, attempt_count = 1
                WHERE response_action_id = 'act_existing'
                """,
                ("b" * 64,),
            )
            command.downgrade(
                _alembic_config(database_url, connection),
                "20260717_0002",
            )
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260717_0002",
        )
        assert connection.execute(
            "SELECT status FROM response_actions WHERE response_action_id = 'act_existing'"
        ).fetchone() == ("queued",)
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(response_actions)")
        }
        assert "idempotency_key" not in columns
        assert "lease_token_hash" not in columns


def test_device_identity_migration_backfills_and_enforces_schema(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    _create_device_identity_prior_schema(database_url)

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            command.upgrade(
                _alembic_config(database_url, connection),
                _HEAD_REVISION,
            )
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            _HEAD_REVISION,
        )
        assert connection.execute(
            """
            SELECT installation_id, credential_mode, enrollment_token_id,
                   protocol_version, architecture
            FROM endpoints
            WHERE endpoint_id = 'ep_identity'
            """
        ).fetchone() == (None, "legacy_shared", None, "legacy-v1", None)

        endpoint_columns = {
            str(row[1]): {"not_null": bool(row[3]), "default": row[4]}
            for row in connection.execute("PRAGMA table_info(endpoints)")
        }
        assert endpoint_columns["installation_id"]["not_null"] is False
        assert endpoint_columns["credential_mode"]["not_null"] is True
        assert endpoint_columns["enrollment_token_id"]["not_null"] is False
        assert endpoint_columns["protocol_version"]["not_null"] is True
        assert endpoint_columns["architecture"]["not_null"] is False

        expected_tables = {
            "enrollment_tokens",
            "device_credentials",
            "enrollment_redemptions",
        }
        assert {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name IN (
                    'enrollment_tokens', 'device_credentials', 'enrollment_redemptions'
                )
                """
            )
        } == expected_tables

        token_columns = {
            str(row[1]): {"not_null": bool(row[3]), "default": row[4]}
            for row in connection.execute("PRAGMA table_info(enrollment_tokens)")
        }
        assert token_columns["client_id"]["not_null"] is True
        assert token_columns["location_id"]["not_null"] is True
        assert token_columns["installer_profile_id"]["not_null"] is False
        assert token_columns["platform"]["not_null"] is False
        assert token_columns["use_count"] == {"not_null": True, "default": "0"}

        active_indexes = {
            str(row[1]): {"unique": bool(row[2]), "partial": bool(row[4])}
            for row in connection.execute("PRAGMA index_list(device_credentials)")
        }
        assert active_indexes["uq_device_credentials_active_endpoint"] == {
            "unique": True,
            "partial": True,
        }
        active_index_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'index' AND name = 'uq_device_credentials_active_endpoint'
            """
        ).fetchone()
        assert active_index_sql is not None
        assert "WHERE status = 'active'" in str(active_index_sql[0])

        assert connection.execute("SELECT COUNT(*) FROM posture_snapshots").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM posture_results").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM response_actions").fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            """
            INSERT INTO enrollment_tokens (
                token_id, secret_hash, hash_key_id, client_id, location_id,
                approval_policy, expires_at, max_uses, created_by, created_at, updated_at
            ) VALUES (
                'et_identity', ?, 'key-v1', 'cl_legacy_quarantine',
                'loc_legacy_quarantine', 'approved', '2026-07-17T13:00:00Z',
                1, 'operator', '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
            )
            """,
            ("a" * 64,),
        )
        assert connection.execute(
            "SELECT use_count FROM enrollment_tokens WHERE token_id = 'et_identity'"
        ).fetchone() == (0,)
        connection.execute(
            """
            UPDATE endpoints
            SET installation_id = 'install-identity', credential_mode = 'device',
                enrollment_token_id = 'et_identity'
            WHERE endpoint_id = 'ep_identity'
            """
        )
        connection.execute(
            """
            INSERT INTO device_credentials (
                credential_id, endpoint_id, secret_hash, hash_key_id, status,
                created_at, updated_at
            ) VALUES (
                'dc_identity', 'ep_identity', ?, 'key-v1', 'active',
                '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
            )
            """,
            ("b" * 64,),
        )
        connection.execute(
            """
            INSERT INTO enrollment_redemptions (
                redemption_id, enrollment_token_id, installation_id, endpoint_id,
                credential_id, request_hash, created_at
            ) VALUES (
                'er_identity', 'et_identity', 'install-identity', 'ep_identity',
                'dc_identity', ?, '2026-07-17T12:00:00Z'
            )
            """,
            ("c" * 64,),
        )
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO device_credentials (
                    credential_id, endpoint_id, secret_hash, hash_key_id, status,
                    created_at, updated_at
                ) VALUES (
                    'dc_duplicate_active', 'ep_identity', ?, 'key-v1', 'active',
                    '2026-07-17T12:01:00Z', '2026-07-17T12:01:00Z'
                )
                """,
                ("d" * 64,),
            )
        connection.rollback()

    with sqlite3.connect(db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError), connection:
            connection.execute(
                """
                UPDATE endpoints
                SET credential_mode = 'invalid'
                WHERE endpoint_id = 'ep_identity'
                """
            )

        with pytest.raises(sqlite3.IntegrityError), connection:
            connection.execute(
                """
                UPDATE enrollment_tokens
                SET use_count = 2
                WHERE token_id = 'et_identity'
                """
            )


def test_device_identity_downgrade_refuses_live_identity_rows(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    _create_device_identity_prior_schema(database_url)

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            command.upgrade(
                _alembic_config(database_url, connection),
                _HEAD_REVISION,
            )
            connection.exec_driver_sql(
                """
                INSERT INTO enrollment_tokens (
                    token_id, secret_hash, hash_key_id, client_id, location_id,
                    approval_policy, expires_at, max_uses, created_by,
                    created_at, updated_at
                ) VALUES (
                    'et_downgrade', ?, 'key-v1', 'cl_legacy_quarantine',
                    'loc_legacy_quarantine', 'approved', '2026-07-17T13:00:00Z',
                    1, 'operator', '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """,
                ("e" * 64,),
            )
            connection.exec_driver_sql(
                """
                UPDATE endpoints
                SET installation_id = 'install-downgrade', credential_mode = 'device',
                    enrollment_token_id = 'et_downgrade'
                WHERE endpoint_id = 'ep_identity'
                """
            )
            connection.exec_driver_sql(
                """
                INSERT INTO device_credentials (
                    credential_id, endpoint_id, secret_hash, hash_key_id, status,
                    created_at, updated_at
                ) VALUES (
                    'dc_downgrade', 'ep_identity', ?, 'key-v1', 'active',
                    '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                )
                """,
                ("f" * 64,),
            )
            connection.exec_driver_sql(
                """
                INSERT INTO enrollment_redemptions (
                    redemption_id, enrollment_token_id, installation_id, endpoint_id,
                    credential_id, request_hash, created_at
                ) VALUES (
                    'er_downgrade', 'et_downgrade', 'install-downgrade',
                    'ep_identity', 'dc_downgrade', ?, '2026-07-17T12:00:00Z'
                )
                """,
                ("1" * 64,),
            )
            with pytest.raises(
                RuntimeError,
                match="device-mode endpoints or identity records exist",
            ):
                command.downgrade(
                    _alembic_config(database_url, connection),
                    "20260717_0005",
                )
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260717_0006",
        )
        endpoint_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(endpoints)")
        }
        assert "installation_id" in endpoint_columns
        assert "credential_mode" in endpoint_columns
        assert "enrollment_token_id" in endpoint_columns
        assert connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name IN (
                'enrollment_tokens', 'device_credentials', 'enrollment_redemptions'
            )
            ORDER BY name
            """
        ).fetchall() == [
            ("device_credentials",),
            ("enrollment_redemptions",),
            ("enrollment_tokens",),
        ]
        assert connection.execute(
            "SELECT credential_mode FROM endpoints WHERE endpoint_id = 'ep_identity'"
        ).fetchone() == ("device",)
        assert connection.execute("SELECT COUNT(*) FROM enrollment_tokens").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM device_credentials").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM enrollment_redemptions").fetchone() == (1,)


def test_device_identity_empty_downgrade_preserves_endpoint_dependents(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    _create_device_identity_prior_schema(database_url)

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            command.upgrade(
                _alembic_config(database_url, connection),
                _HEAD_REVISION,
            )
            command.downgrade(
                _alembic_config(database_url, connection),
                "20260717_0005",
            )
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260717_0005",
        )
        endpoint_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(endpoints)")
        }
        assert "installation_id" not in endpoint_columns
        assert "credential_mode" not in endpoint_columns
        assert "enrollment_token_id" not in endpoint_columns
        assert connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name IN (
                'enrollment_tokens', 'device_credentials', 'enrollment_redemptions'
            )
            """
        ).fetchall() == []
        assert connection.execute(
            "SELECT snapshot_id, endpoint_id FROM posture_snapshots"
        ).fetchall() == [("snap_identity", "ep_identity")]
        assert connection.execute(
            "SELECT result_id, endpoint_id FROM posture_results"
        ).fetchall() == [("result_identity", "ep_identity")]
        assert connection.execute(
            "SELECT response_action_id, endpoint_id FROM response_actions"
        ).fetchall() == [("act_identity", "ep_identity")]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_scope_hierarchy_migration_preserves_exact_legacy_pairs_and_quarantines_nulls(
    db_path: Path,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    endpoint_rows = [
        ("ep_tenant_a", "fp-a", "tenant-a", "shared-site"),
        ("ep_tenant_b", "fp-b", "tenant-b", "shared-site"),
        ("ep_tenant_upper", "fp-upper", "Tenant-A", "shared-site"),
        ("ep_tenant_only", "fp-tenant-only", "tenant-a", None),
        ("ep_site_only", "fp-site-only", None, "orphan-site"),
        ("ep_unscoped", "fp-unscoped", None, None),
    ]
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                "20260717_0004",
            )
            for endpoint_id, fingerprint, tenant_id, site_id in endpoint_rows:
                connection.exec_driver_sql(
                    """
                    INSERT INTO endpoints (
                        endpoint_id, agent_fingerprint, hostname, platform,
                        agent_version, tenant_id, site_id, status, last_seen_at,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'linux', 'legacy-agent', ?, ?, 'active',
                              '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z',
                              '2026-07-17T12:00:00Z')
                    """,
                    (endpoint_id, fingerprint, endpoint_id, tenant_id, site_id),
                )
            connection.exec_driver_sql(
                """
                INSERT INTO installer_profiles (
                    id, name, name_normalized, platform, channel,
                    control_plane_url, policy_mode, tenant_id, site_id,
                    created_at, updated_at
                ) VALUES (
                    'ip_legacy', 'Legacy profile', 'legacy profile', 'linux',
                    'stable', 'https://sha.example.test', 'observe',
                    'tenant-a', 'shared-site', '2026-07-17T12:00:00Z',
                    '2026-07-17T12:00:00Z'
                )
                """
            )
            command.upgrade(_alembic_config(database_url, connection), _HEAD_REVISION)
            command.check(_alembic_config(database_url, connection))
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        assert {
            row[0] for row in connection.execute("SELECT key FROM clients").fetchall()
        } == {None, "tenant-a", "tenant-b", "Tenant-A"}
        assert connection.execute(
            "SELECT tenant_id, site_id FROM endpoints ORDER BY endpoint_id"
        ).fetchall() == [
            (tenant_id, site_id)
            for _endpoint_id, _fingerprint, tenant_id, site_id in sorted(endpoint_rows)
        ]

        mappings = {
            str(row[0]): (str(row[1]), str(row[2]))
            for row in connection.execute(
                "SELECT endpoint_id, client_id, location_id FROM endpoints"
            ).fetchall()
        }
        assert mappings["ep_tenant_a"][0] != mappings["ep_tenant_b"][0]
        assert mappings["ep_tenant_a"][1] != mappings["ep_tenant_b"][1]
        assert mappings["ep_tenant_a"][0] != mappings["ep_tenant_upper"][0]
        assert mappings["ep_site_only"][0] == "cl_legacy_quarantine"
        assert mappings["ep_site_only"][1] != "loc_legacy_quarantine"
        assert mappings["ep_unscoped"] == (
            "cl_legacy_quarantine",
            "loc_legacy_quarantine",
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.downgrade(
                _alembic_config(database_url, connection),
                "20260717_0004",
            )
            columns = {
                str(column[1])
                for column in connection.exec_driver_sql("PRAGMA table_info(endpoints)").all()
            }
            assert "client_id" not in columns
            assert "location_id" not in columns
            command.upgrade(
                _alembic_config(database_url, connection),
                _HEAD_REVISION,
            )
            command.check(_alembic_config(database_url, connection))
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        remapped = {
            str(row[0]): (str(row[1]), str(row[2]))
            for row in connection.execute(
                "SELECT endpoint_id, client_id, location_id FROM endpoints"
            ).fetchall()
        }
        assert remapped == mappings
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_scope_hierarchy_downgrade_rejects_cross_client_profile_name_collision(
    db_path: Path,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{db_path}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(
                _alembic_config(database_url, connection),
                "20260717_0005",
            )
            for suffix in ("a", "b"):
                client_id = f"cl_collision_{suffix}"
                location_id = f"loc_collision_{suffix}"
                connection.exec_driver_sql(
                    """
                    INSERT INTO clients (
                        client_id, key, name, name_normalized, state, is_system,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                    """,
                    (
                        client_id,
                        f"tenant-{suffix}",
                        f"Tenant {suffix}",
                        f"tenant {suffix}",
                        "2026-07-17T12:00:00Z",
                        "2026-07-17T12:00:00Z",
                    ),
                )
                connection.exec_driver_sql(
                    """
                    INSERT INTO locations (
                        location_id, client_id, key, name, name_normalized,
                        state, is_system, created_at, updated_at
                    ) VALUES (?, ?, 'site', 'Site', 'site', 'active', 0, ?, ?)
                    """,
                    (
                        location_id,
                        client_id,
                        "2026-07-17T12:00:00Z",
                        "2026-07-17T12:00:00Z",
                    ),
                )
                connection.exec_driver_sql(
                    """
                    INSERT INTO installer_profiles (
                        id, name, name_normalized, platform, channel,
                        control_plane_url, policy_mode, tenant_id, site_id,
                        created_at, updated_at, client_id, location_id
                    ) VALUES (?, 'Shared profile name', 'shared profile name',
                              'linux', 'stable', 'https://sha.example.test',
                              'observe', ?, 'site', ?, ?, ?, ?)
                    """,
                    (
                        f"ip_collision_{suffix}",
                        f"tenant-{suffix}",
                        "2026-07-17T12:00:00Z",
                        "2026-07-17T12:00:00Z",
                        client_id,
                        location_id,
                    ),
                )
            with pytest.raises(
                RuntimeError,
                match="installer profile names collide across clients",
            ):
                command.downgrade(
                    _alembic_config(database_url, connection),
                    "20260717_0004",
                )
    finally:
        engine.dispose()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260717_0005",
        )
        assert connection.execute("SELECT COUNT(*) FROM installer_profiles").fetchone() == (2,)
