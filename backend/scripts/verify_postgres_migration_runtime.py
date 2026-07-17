from __future__ import annotations

import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection, make_url

from app.config import get_settings
from app.db import DatabaseStore
from app.migrations import database_revisions

_ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
_BASELINE_REVISION = "20260717_0001"
_PRE_LEASE_REVISION = "20260717_0002"
_HEAD_REVISION = "20260717_0004"


def _config(database_url: str, connection: Connection) -> Config:
    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["connection"] = connection
    return config


def _seed_representative_unversioned_database(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            command.upgrade(_config(database_url, connection), _BASELINE_REVISION)
            connection.execute(
                text(
                    """
                    INSERT INTO endpoints (
                        endpoint_id, agent_fingerprint, hostname, platform,
                        agent_version, status, last_seen_at, created_at, updated_at
                    ) VALUES (
                        'ep_pg_upgrade', 'postgres-upgrade-fixture',
                        'postgres-upgrade-fixture', 'windows', '0.1.0', 'active',
                        '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z',
                        '2026-07-17T12:00:00Z'
                    )
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO posture_snapshots (
                        snapshot_id, endpoint_id, observed_at, platform_profile, created_at
                    ) VALUES
                        ('snap_pg_alias', 'ep_pg_upgrade', '2026-07-17T12:00:00Z',
                         'windows-server', '2026-07-17T12:00:00Z'),
                        ('snap_pg_duplicate', 'ep_pg_upgrade', '2026-07-17T12:01:00Z',
                         'windows-server', '2026-07-17T12:01:00Z')
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO posture_results (
                        result_id, snapshot_id, endpoint_id, control_key,
                        control_key_normalized, status, evidence_summary,
                        reboot_required, created_at
                    ) VALUES
                        ('result_pg_alias', 'snap_pg_alias', 'ep_pg_upgrade',
                         'windows.defender.real_time_protection',
                         'windows.defender.real_time_protection', 'pass',
                         'Representative later alias', false, '2026-07-17T12:00:00Z'),
                        ('result_pg_duplicate_alias', 'snap_pg_duplicate', 'ep_pg_upgrade',
                         'windows.firewall.all-profiles-enabled',
                         'windows.firewall.all-profiles-enabled', 'fail',
                         'Representative duplicate alias', false, '2026-07-17T12:01:00Z'),
                        ('result_pg_duplicate_canonical', 'snap_pg_duplicate', 'ep_pg_upgrade',
                         'control.windows.firewall-all-profiles',
                         'control.windows.firewall-all-profiles', 'pass',
                         'Representative canonical row', false, '2026-07-17T12:01:00Z')
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO approval_grants (
                        approval_grant_id, endpoint_ids, allowed_actions, control_ids,
                        troubleshooting_scopes, requested_by, approved_by, reason,
                        expires_at, status, created_at, updated_at
                    ) VALUES (
                        'grant_pg_upgrade', '["ep_pg_upgrade"]', '["apply_control"]',
                        '["control.windows.firewall-all-profiles"]', '[]',
                        'operator', 'approver', 'Representative approved action',
                        '2026-07-18T12:00:00Z', 'approved',
                        '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                    )
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO response_actions (
                        response_action_id, endpoint_id, approval_grant_id, action,
                        control_id, requested_by, reason, status, created_at, updated_at
                    ) VALUES (
                        'act_pg_upgrade', 'ep_pg_upgrade', 'grant_pg_upgrade',
                        'apply_control', 'control.windows.firewall-all-profiles',
                        'operator', 'Representative queued action', 'queued',
                        '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z'
                    )
                    """
                )
            )
            connection.execute(text("DROP TABLE alembic_version"))
    finally:
        engine.dispose()


def _upgrade_with_runtime(database_url: str) -> None:
    store = DatabaseStore(database_url, migration_mode="upgrade")
    try:
        store.prepare()
    finally:
        store.dispose()


def _verify_head(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            current, head = database_revisions(connection, database_url)
            assert current == head == _HEAD_REVISION
            assert connection.execute(
                text(
                    """
                    SELECT control_key FROM posture_results
                    WHERE result_id = 'result_pg_alias'
                    """
                )
            ).scalar_one() == "control.windows.defender-real-time-protection"
            assert connection.execute(
                text(
                    """
                    SELECT result_id FROM posture_results
                    WHERE snapshot_id = 'snap_pg_duplicate'
                    ORDER BY result_id
                    """
                )
            ).scalars().all() == ["result_pg_duplicate_canonical"]
            assert connection.execute(
                text(
                    """
                    SELECT idempotency_key, attempt_count, status
                    FROM response_actions WHERE response_action_id = 'act_pg_upgrade'
                    """
                )
            ).one() == ("act_pg_upgrade", 0, "queued")
            columns = {column["name"] for column in inspect(connection).get_columns("response_actions")}
            assert {
                "idempotency_key",
                "lease_token_hash",
                "lease_expires_at",
                "leased_at",
                "attempt_count",
            } <= columns
            command.check(_config(database_url, connection))
    finally:
        engine.dispose()


def _verify_downgrade_and_reupgrade(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE response_actions
                    SET status = 'leased', lease_token_hash = :lease_hash,
                        lease_expires_at = '2026-07-17T12:05:00Z',
                        leased_at = '2026-07-17T12:00:00Z', attempt_count = 1
                    WHERE response_action_id = 'act_pg_upgrade'
                    """
                ),
                {"lease_hash": "a" * 64},
            )
            command.downgrade(_config(database_url, connection), _PRE_LEASE_REVISION)
            assert connection.execute(
                text(
                    """
                    SELECT status FROM response_actions
                    WHERE response_action_id = 'act_pg_upgrade'
                    """
                )
            ).scalar_one() == "queued"
            assert "lease_token_hash" not in {
                column["name"] for column in inspect(connection).get_columns("response_actions")
            }
    finally:
        engine.dispose()

    _upgrade_with_runtime(database_url)
    _verify_head(database_url)


def main() -> None:
    database_url = get_settings().resolved_database_url()
    if not make_url(database_url).drivername.startswith("postgresql"):
        raise SystemExit("PostgreSQL database URL required")

    _seed_representative_unversioned_database(database_url)
    _upgrade_with_runtime(database_url)
    _verify_head(database_url)
    _verify_downgrade_and_reupgrade(database_url)
    print(
        json.dumps(
            {
                "adopted_unversioned_schema": True,
                "alias_rows_normalized": True,
                "downgrade_requeued_lease": True,
                "head": _HEAD_REVISION,
                "schema_drift": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
