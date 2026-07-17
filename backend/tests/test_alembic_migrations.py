from __future__ import annotations

from pathlib import Path
import sqlite3

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

from app.db import DatabaseStore


_ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
_PRIOR_REVISION = "20260717_0001"
_HEAD_REVISION = "20260717_0004"


def _alembic_config(database_url: str, connection: Connection) -> Config:
    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["connection"] = connection
    return config


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
