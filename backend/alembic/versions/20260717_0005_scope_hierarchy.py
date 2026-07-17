from __future__ import annotations

import hashlib

from alembic import op
import sqlalchemy as sa

revision = "20260717_0005"
down_revision = "20260717_0004"
branch_labels = None
depends_on = None

QUARANTINE_CLIENT_ID = "cl_legacy_quarantine"
QUARANTINE_LOCATION_ID = "loc_legacy_quarantine"
_MIGRATION_TIMESTAMP = "2026-07-17T00:00:00Z"


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}_{digest}"


def _client_id(tenant_id: str | None) -> str:
    if tenant_id is None:
        return QUARANTINE_CLIENT_ID
    return _stable_id("cl", tenant_id)


def _location_id(tenant_id: str | None, site_id: str | None) -> str:
    if tenant_id is None and site_id is None:
        return QUARANTINE_LOCATION_ID
    return _stable_id("loc", tenant_id if tenant_id is not None else "<null>", site_id if site_id is not None else "<null>")


def _insert_client(
    connection: sa.Connection,
    *,
    client_id: str,
    key: str | None,
    name: str,
    state: str,
    is_system: bool,
) -> None:
    connection.execute(
        sa.text(
            """
            INSERT INTO clients (
                client_id, key, name, name_normalized, state, is_system,
                created_at, updated_at
            ) VALUES (
                :client_id, :key, :name, :name_normalized, :state, :is_system,
                :created_at, :updated_at
            )
            """
        ),
        {
            "client_id": client_id,
            "key": key,
            "name": name,
            "name_normalized": name.lower(),
            "state": state,
            "is_system": is_system,
            "created_at": _MIGRATION_TIMESTAMP,
            "updated_at": _MIGRATION_TIMESTAMP,
        },
    )


def _insert_location(
    connection: sa.Connection,
    *,
    location_id: str,
    client_id: str,
    key: str | None,
    name: str,
    state: str,
    is_system: bool,
) -> None:
    connection.execute(
        sa.text(
            """
            INSERT INTO locations (
                location_id, client_id, key, name, name_normalized, state,
                is_system, created_at, updated_at
            ) VALUES (
                :location_id, :client_id, :key, :name, :name_normalized, :state,
                :is_system, :created_at, :updated_at
            )
            """
        ),
        {
            "location_id": location_id,
            "client_id": client_id,
            "key": key,
            "name": name,
            "name_normalized": name.lower(),
            "state": state,
            "is_system": is_system,
            "created_at": _MIGRATION_TIMESTAMP,
            "updated_at": _MIGRATION_TIMESTAMP,
        },
    )


def _legacy_scope_pairs(connection: sa.Connection) -> list[tuple[str | None, str | None]]:
    rows = connection.execute(
        sa.text(
            """
            SELECT tenant_id, site_id FROM endpoints
            UNION
            SELECT tenant_id, site_id FROM installer_profiles
            """
        )
    ).all()
    return [(row[0], row[1]) for row in rows]


def _create_scope_rows(connection: sa.Connection) -> None:
    _insert_client(
        connection,
        client_id=QUARANTINE_CLIENT_ID,
        key=None,
        name="Legacy scope quarantine",
        state="migration_quarantine",
        is_system=True,
    )
    _insert_location(
        connection,
        location_id=QUARANTINE_LOCATION_ID,
        client_id=QUARANTINE_CLIENT_ID,
        key=None,
        name="Unassigned",
        state="migration_quarantine",
        is_system=True,
    )

    pairs = _legacy_scope_pairs(connection)
    tenant_keys = sorted({tenant_id for tenant_id, _site_id in pairs if tenant_id is not None})
    for tenant_id in tenant_keys:
        client_id = _client_id(tenant_id)
        _insert_client(
            connection,
            client_id=client_id,
            key=tenant_id,
            name=tenant_id,
            state="active",
            is_system=False,
        )
        if any(pair_tenant == tenant_id and site_id is None for pair_tenant, site_id in pairs):
            _insert_location(
                connection,
                location_id=_location_id(tenant_id, None),
                client_id=client_id,
                key=None,
                name="Unassigned",
                state="migration_quarantine",
                is_system=True,
            )

    for tenant_id, site_id in sorted(
        {(tenant_id, site_id) for tenant_id, site_id in pairs if site_id is not None},
        key=lambda pair: ((pair[0] or ""), pair[1] or ""),
    ):
        client_id = _client_id(tenant_id)
        _insert_location(
            connection,
            location_id=_location_id(tenant_id, site_id),
            client_id=client_id,
            key=site_id,
            name=site_id,
            state="active" if tenant_id is not None else "migration_quarantine",
            is_system=False,
        )


def _backfill_table(connection: sa.Connection, table_name: str, id_column: str) -> None:
    rows = connection.execute(
        sa.text(f'SELECT "{id_column}", tenant_id, site_id FROM "{table_name}"')
    ).all()
    for row_id, tenant_id, site_id in rows:
        connection.execute(
            sa.text(
                f"""
                UPDATE "{table_name}"
                SET client_id = :client_id, location_id = :location_id
                WHERE "{id_column}" = :row_id
                """
            ),
            {
                "client_id": _client_id(tenant_id),
                "location_id": _location_id(tenant_id, site_id),
                "row_id": row_id,
            },
        )


def _backup_sqlite_endpoint_dependents(connection: sa.Connection) -> bool:
    if connection.dialect.name != "sqlite":
        return False
    for table_name in ("posture_results", "posture_snapshots", "response_actions"):
        backup_name = f"sha_0005_{table_name}_backup"
        connection.exec_driver_sql(f'DROP TABLE IF EXISTS "{backup_name}"')
        connection.exec_driver_sql(
            f'CREATE TEMPORARY TABLE "{backup_name}" AS SELECT * FROM "{table_name}"'
        )
    return True


def _restore_sqlite_endpoint_dependents(connection: sa.Connection, backed_up: bool) -> None:
    if not backed_up:
        return
    primary_keys = {
        "posture_snapshots": "snapshot_id",
        "posture_results": "result_id",
        "response_actions": "response_action_id",
    }
    for table_name, primary_key in primary_keys.items():
        backup_name = f"sha_0005_{table_name}_backup"
        connection.exec_driver_sql(
            f"""
            INSERT INTO "{table_name}"
            SELECT backup.*
            FROM "{backup_name}" AS backup
            LEFT JOIN "{table_name}" AS current
              ON current."{primary_key}" = backup."{primary_key}"
            WHERE current."{primary_key}" IS NULL
            """
        )
        backup_count = int(
            connection.exec_driver_sql(
                f'SELECT COUNT(*) FROM "{backup_name}"'
            ).scalar_one()
        )
        restored_count = int(
            connection.exec_driver_sql(
                f'SELECT COUNT(*) FROM "{table_name}"'
            ).scalar_one()
        )
        missing_count = int(
            connection.exec_driver_sql(
                f"""
                SELECT COUNT(*)
                FROM (
                    SELECT * FROM "{backup_name}"
                    EXCEPT
                    SELECT * FROM "{table_name}"
                ) AS missing_rows
                """
            ).scalar_one()
        )
        if restored_count != backup_count or missing_count != 0:
            raise RuntimeError(
                f"SQLite hierarchy migration did not preserve every {table_name} row"
            )
        connection.exec_driver_sql(f'DROP TABLE "{backup_name}"')


def _assert_downgrade_profile_names_compatible(connection: sa.Connection) -> None:
    collision = connection.execute(
        sa.text(
            """
            SELECT platform, name_normalized
            FROM installer_profiles
            GROUP BY platform, name_normalized
            HAVING COUNT(DISTINCT client_id) > 1
            LIMIT 1
            """
        )
    ).first()
    if collision is not None:
        raise RuntimeError(
            "cannot downgrade hierarchy while installer profile names collide across clients"
        )


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("client_id", sa.String(64), primary_key=True),
        sa.Column("key", sa.String(255)),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("name_normalized", sa.String(255), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        sa.UniqueConstraint("key", name="uq_clients_key"),
        sa.CheckConstraint(
            "state IN ('active', 'archived', 'migration_quarantine')",
            name="ck_clients_state",
        ),
    )
    op.create_table(
        "locations",
        sa.Column("location_id", sa.String(64), primary_key=True),
        sa.Column(
            "client_id",
            sa.String(64),
            sa.ForeignKey("clients.client_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("key", sa.String(255)),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("name_normalized", sa.String(255), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        sa.UniqueConstraint("location_id", "client_id", name="uq_locations_id_client"),
        sa.UniqueConstraint("client_id", "key", name="uq_locations_client_key"),
        sa.CheckConstraint(
            "state IN ('active', 'archived', 'migration_quarantine')",
            name="ck_locations_state",
        ),
    )

    op.add_column("endpoints", sa.Column("client_id", sa.String(64), nullable=True))
    op.add_column("endpoints", sa.Column("location_id", sa.String(64), nullable=True))
    op.add_column("installer_profiles", sa.Column("client_id", sa.String(64), nullable=True))
    op.add_column("installer_profiles", sa.Column("location_id", sa.String(64), nullable=True))

    connection = op.get_bind()
    _create_scope_rows(connection)
    _backfill_table(connection, "endpoints", "endpoint_id")
    _backfill_table(connection, "installer_profiles", "id")

    endpoint_dependents_backed_up = _backup_sqlite_endpoint_dependents(connection)
    with op.batch_alter_table("endpoints") as batch:
        batch.alter_column("client_id", existing_type=sa.String(64), nullable=False)
        batch.alter_column("location_id", existing_type=sa.String(64), nullable=False)
        batch.create_foreign_key(
            "fk_endpoints_location_client",
            "locations",
            ["location_id", "client_id"],
            ["location_id", "client_id"],
            ondelete="RESTRICT",
        )
    _restore_sqlite_endpoint_dependents(connection, endpoint_dependents_backed_up)
    with op.batch_alter_table("installer_profiles") as batch:
        batch.alter_column("client_id", existing_type=sa.String(64), nullable=False)
        batch.alter_column("location_id", existing_type=sa.String(64), nullable=False)
        batch.drop_constraint("uq_installer_profiles_platform_name", type_="unique")
        batch.create_unique_constraint(
            "uq_installer_profiles_client_platform_name",
            ["client_id", "platform", "name_normalized"],
        )
        batch.create_foreign_key(
            "fk_installer_profiles_location_client",
            "locations",
            ["location_id", "client_id"],
            ["location_id", "client_id"],
            ondelete="RESTRICT",
        )

    op.create_index("ix_endpoints_client_location", "endpoints", ["client_id", "location_id"])
    op.create_index(
        "ix_installer_profiles_client_location",
        "installer_profiles",
        ["client_id", "location_id"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    _assert_downgrade_profile_names_compatible(connection)
    op.drop_index("ix_installer_profiles_client_location", table_name="installer_profiles")
    op.drop_index("ix_endpoints_client_location", table_name="endpoints")
    with op.batch_alter_table("installer_profiles") as batch:
        batch.drop_constraint("fk_installer_profiles_location_client", type_="foreignkey")
        batch.drop_constraint(
            "uq_installer_profiles_client_platform_name",
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_installer_profiles_platform_name",
            ["platform", "name_normalized"],
        )
        batch.drop_column("location_id")
        batch.drop_column("client_id")
    endpoint_dependents_backed_up = _backup_sqlite_endpoint_dependents(connection)
    with op.batch_alter_table("endpoints") as batch:
        batch.drop_constraint("fk_endpoints_location_client", type_="foreignkey")
        batch.drop_column("location_id")
        batch.drop_column("client_id")
    _restore_sqlite_endpoint_dependents(connection, endpoint_dependents_backed_up)
    op.drop_table("locations")
    op.drop_table("clients")
