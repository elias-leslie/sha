from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.exc import DBAPIError

from app.config import get_settings
from app.db import DatabaseStore
from app.migrations import database_revisions

_ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
_BASELINE_REVISION = "20260717_0001"
_PRE_LEASE_REVISION = "20260717_0002"
_HEAD_REVISION = "20260717_0009"


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
                        agent_version, tenant_id, site_id, status, last_seen_at,
                        created_at, updated_at
                    ) VALUES (
                        'ep_pg_upgrade', 'postgres-upgrade-fixture',
                        'postgres-upgrade-fixture', 'windows', '0.1.0',
                        'Tenant-PG', 'shared-site', 'active',
                        '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z',
                        '2026-07-17T12:00:00Z'
                    ), (
                        'ep_pg_upgrade_lower', 'postgres-upgrade-fixture-lower',
                        'postgres-upgrade-fixture-lower', 'linux', '0.1.0',
                        'tenant-pg', 'shared-site', 'active',
                        '2026-07-17T12:00:00Z', '2026-07-17T12:00:00Z',
                        '2026-07-17T12:00:00Z'
                    )
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO installer_profiles (
                        id, name, name_normalized, platform, channel,
                        control_plane_url, policy_mode, tenant_id, site_id,
                        created_at, updated_at
                    ) VALUES (
                        'ip_pg_upgrade', 'PostgreSQL migration profile',
                        'postgresql migration profile', 'windows', 'stable',
                        'https://sha.example.test', 'observe', 'Tenant-PG',
                        'shared-site', '2026-07-17T12:00:00Z',
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
            assert {
                "tags",
                "endpoint_tag_assignments",
                "saved_views",
                "saved_view_versions",
                "dynamic_groups",
            } <= set(inspect(connection).get_table_names())
            assert connection.execute(
                text(
                    """
                    SELECT COUNT(*) FROM role_permissions
                    WHERE permission IN (
                        'tag.read', 'tag.manage', 'saved_view.read',
                        'saved_view.manage', 'dynamic_group.read',
                        'dynamic_group.manage'
                    )
                    """
                )
            ).scalar_one() == 24
            scope_rows = connection.execute(
                text(
                    """
                    SELECT endpoint_id, client_id, location_id, tenant_id, site_id
                    FROM endpoints
                    WHERE endpoint_id IN ('ep_pg_upgrade', 'ep_pg_upgrade_lower')
                    ORDER BY endpoint_id
                    """
                )
            ).all()
            assert [row[3:] for row in scope_rows] == [
                ("Tenant-PG", "shared-site"),
                ("tenant-pg", "shared-site"),
            ]
            assert scope_rows[0][1] != scope_rows[1][1]
            assert scope_rows[0][2] != scope_rows[1][2]
            assert connection.execute(
                text(
                    """
                    SELECT credential_mode, protocol_version, architecture,
                           installation_id, enrollment_token_id
                    FROM endpoints
                    WHERE endpoint_id = 'ep_pg_upgrade'
                    """
                )
            ).one() == ("legacy_shared", "legacy-v1", None, None, None)
            profile_scope = connection.execute(
                text(
                    """
                    SELECT client_id, location_id, tenant_id, site_id
                    FROM installer_profiles
                    WHERE id = 'ip_pg_upgrade'
                    """
                )
            ).one()
            assert profile_scope == (
                scope_rows[0][1],
                scope_rows[0][2],
                "Tenant-PG",
                "shared-site",
            )
            columns = {column["name"] for column in inspect(connection).get_columns("response_actions")}
            assert {
                "idempotency_key",
                "lease_token_hash",
                "lease_expires_at",
                "leased_at",
                "attempt_count",
            } <= columns
            assert {
                "sha_audit_events_no_update",
                "sha_audit_events_no_delete",
            } <= {
                str(row[0])
                for row in connection.execute(
                    text(
                        """
                        SELECT tgname FROM pg_trigger
                        WHERE tgrelid = 'audit_events'::regclass
                          AND NOT tgisinternal
                        """
                    )
                )
            }
            command.check(_config(database_url, connection))
    finally:
        engine.dispose()


def _verify_audit_immutability(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            outer = connection.begin()
            try:
                connection.execute(
                    text(
                        """
                        INSERT INTO audit_events (
                            audit_event_id, event_type, outcome, actor,
                            auth_method, metadata_json, created_at
                        ) VALUES (
                            'aud_pg_append_only', 'test_event', 'success',
                            'postgres-verifier', 'test', '{}'::json,
                            '2026-07-17T12:00:00Z'
                        )
                        """
                    )
                )
                for mutation in (
                    "UPDATE audit_events SET outcome = 'failure' "
                    "WHERE audit_event_id = 'aud_pg_append_only'",
                    "DELETE FROM audit_events WHERE audit_event_id = 'aud_pg_append_only'",
                ):
                    savepoint = connection.begin_nested()
                    try:
                        connection.execute(text(mutation))
                    except DBAPIError:
                        savepoint.rollback()
                    else:
                        raise AssertionError("audit event mutation unexpectedly succeeded")
            finally:
                outer.rollback()
    finally:
        engine.dispose()


def _verify_enrollment_use_limit_concurrency(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            scope = connection.execute(
                text(
                    """
                    SELECT client_id, location_id
                    FROM endpoints
                    WHERE endpoint_id = 'ep_pg_upgrade'
                    """
                )
            ).one()
            connection.execute(
                text(
                    """
                    INSERT INTO enrollment_tokens (
                        token_id, secret_hash, hash_key_id, client_id, location_id,
                        approval_policy, expires_at, max_uses, use_count, created_by,
                        created_at, updated_at
                    ) VALUES (
                        'et_pg_concurrency', :secret_hash, 'primary', :client_id,
                        :location_id, 'approved', '2099-01-01T00:00:00Z', 1, 0,
                        'runtime-verifier', '2026-07-17T12:00:00Z',
                        '2026-07-17T12:00:00Z'
                    )
                    """
                ),
                {
                    "secret_hash": "d" * 64,
                    "client_id": scope.client_id,
                    "location_id": scope.location_id,
                },
            )

        def consume_once() -> int | None:
            with engine.begin() as connection:
                return connection.execute(
                    text(
                        """
                        UPDATE enrollment_tokens
                        SET use_count = use_count + 1,
                            updated_at = '2026-07-17T12:01:00Z'
                        WHERE token_id = 'et_pg_concurrency'
                          AND revoked_at IS NULL
                          AND expires_at > '2026-07-17T12:01:00Z'
                          AND use_count < max_uses
                        RETURNING use_count
                        """
                    )
                ).scalar_one_or_none()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _attempt: consume_once(), range(2)))
        assert sorted(results, key=lambda value: value is None) == [1, None]

        with engine.begin() as connection:
            assert connection.execute(
                text(
                    """
                    SELECT use_count FROM enrollment_tokens
                    WHERE token_id = 'et_pg_concurrency'
                    """
                )
            ).scalar_one() == 1
            connection.execute(
                text(
                    """
                    DELETE FROM enrollment_tokens
                    WHERE token_id = 'et_pg_concurrency'
                    """
                )
            )
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
    _verify_audit_immutability(database_url)


def main() -> None:
    database_url = get_settings().resolved_database_url()
    if not make_url(database_url).drivername.startswith("postgresql"):
        raise SystemExit("PostgreSQL database URL required")

    _seed_representative_unversioned_database(database_url)
    _upgrade_with_runtime(database_url)
    _verify_head(database_url)
    _verify_enrollment_use_limit_concurrency(database_url)
    _verify_downgrade_and_reupgrade(database_url)
    print(
        json.dumps(
            {
                "adopted_unversioned_schema": True,
                "alias_rows_normalized": True,
                "downgrade_requeued_lease": True,
                "hierarchy_backfill_preserved": True,
                "enrollment_use_limit_atomic": True,
                "audit_events_append_only": True,
                "fleet_metadata_upgrade_downgrade": True,
                "head": _HEAD_REVISION,
                "schema_drift": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
