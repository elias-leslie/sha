from __future__ import annotations

import json
from typing import Any

from alembic import op
import sqlalchemy as sa

revision = "20260717_0007"
down_revision = "20260717_0006"
branch_labels = None
depends_on = None

_SEEDED_AT = "2026-07-17T00:00:00Z"

_ROLE_NAMES = {
    "viewer": "Viewer",
    "operator": "Operator",
    "responder": "Responder",
    "approver": "Approver",
    "admin": "Admin",
}

_ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "viewer": (
        "approval.read",
        "audit.read",
        "catalog.read",
        "compliance_evidence.export",
        "endpoint.read",
        "evidence.read",
        "hierarchy.read",
        "installer_profile.read",
        "inventory.read",
        "response_action.read",
    ),
    "operator": (
        "action.request",
        "approval.read",
        "approval.request",
        "audit.read",
        "catalog.read",
        "compliance_evidence.export",
        "endpoint.read",
        "evidence.read",
        "hierarchy.read",
        "installer_profile.read",
        "inventory.read",
        "inventory.refresh",
        "response_action.create",
        "response_action.read",
    ),
    "responder": (
        "action.request",
        "approval.read",
        "approval.request",
        "audit.read",
        "catalog.read",
        "compliance_evidence.export",
        "containment.execute",
        "containment.release",
        "endpoint.read",
        "evidence.collect",
        "evidence.read",
        "hierarchy.read",
        "incident.manage",
        "installer_profile.read",
        "inventory.read",
        "inventory.refresh",
        "process.mutate",
        "response_action.create",
        "response_action.read",
        "service.mutate",
    ),
    "approver": (
        "action.approve",
        "approval.decide",
        "approval.read",
        "audit.read",
        "catalog.read",
        "compliance_evidence.export",
        "endpoint.read",
        "evidence.read",
        "hierarchy.read",
        "installer_profile.read",
        "inventory.read",
        "response_action.read",
        "schedule.approve",
    ),
    "admin": (
        "action.approve",
        "action.request",
        "approval.decide",
        "approval.grant",
        "approval.read",
        "approval.request",
        "audit.export",
        "audit.read",
        "bulk_action.execute",
        "catalog.read",
        "command.execute",
        "compliance.exception",
        "compliance_evidence.export",
        "containment.execute",
        "containment.release",
        "credential.admin",
        "device_credential.manage",
        "endpoint.approve",
        "endpoint.read",
        "enrollment.admin",
        "enrollment.manage",
        "enrollment.read",
        "evidence.collect",
        "evidence.read",
        "hierarchy.manage",
        "hierarchy.read",
        "identity.manage",
        "incident.manage",
        "installer_artifact.download",
        "installer_profile.manage",
        "installer_profile.read",
        "inventory.read",
        "inventory.refresh",
        "process.mutate",
        "reboot.execute",
        "response_action.create",
        "response_action.read",
        "schedule.approve",
        "schedule.create",
        "service.mutate",
        "terminal.open",
    ),
}


def _decode_endpoint_ids(raw_value: Any) -> list[str]:
    value = json.loads(raw_value) if isinstance(raw_value, str) else raw_value
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _scope_for_endpoint_ids(
    connection: sa.Connection,
    raw_endpoint_ids: Any,
) -> tuple[str, str | None, str | None]:
    endpoint_ids = _decode_endpoint_ids(raw_endpoint_ids)
    if not endpoint_ids:
        return "migration_quarantine", None, None
    endpoint_rows = connection.execute(
        sa.text(
            "SELECT endpoint_id, client_id, location_id FROM endpoints "
            "WHERE endpoint_id IN :endpoint_ids"
        ).bindparams(sa.bindparam("endpoint_ids", expanding=True)),
        {"endpoint_ids": endpoint_ids},
    ).mappings().all()
    if len(endpoint_rows) != len(set(endpoint_ids)):
        return "migration_quarantine", None, None
    client_ids = {str(row["client_id"]) for row in endpoint_rows}
    if len(client_ids) != 1:
        return "migration_quarantine", None, None
    location_ids = {str(row["location_id"]) for row in endpoint_rows}
    return (
        "active",
        next(iter(client_ids)),
        next(iter(location_ids)) if len(location_ids) == 1 else None,
    )


def _backfill_approval_scopes(connection: sa.Connection) -> None:
    for table_name, id_column in (
        ("approval_requests", "approval_request_id"),
        ("approval_grants", "approval_grant_id"),
    ):
        rows = connection.execute(
            sa.text(f'SELECT "{id_column}", endpoint_ids FROM "{table_name}"')
        ).mappings()
        for row in rows:
            scope_state, client_id, location_id = _scope_for_endpoint_ids(
                connection,
                row["endpoint_ids"],
            )
            connection.execute(
                sa.text(
                    f'UPDATE "{table_name}" '
                    "SET scope_state = :scope_state, client_id = :client_id, "
                    "location_id = :location_id "
                    f'WHERE "{id_column}" = :record_id'
                ),
                {
                    "scope_state": scope_state,
                    "client_id": client_id,
                    "location_id": location_id,
                    "record_id": row[id_column],
                },
            )


def _backup_sqlite_tables(connection: sa.Connection, table_names: tuple[str, ...]) -> bool:
    if connection.dialect.name != "sqlite":
        return False
    for table_name in table_names:
        backup_name = f"sha_0007_{table_name}_backup"
        connection.exec_driver_sql(f'DROP TABLE IF EXISTS "{backup_name}"')
        connection.exec_driver_sql(
            f'CREATE TEMPORARY TABLE "{backup_name}" AS SELECT * FROM "{table_name}"'
        )
    return True


def _restore_sqlite_table(
    connection: sa.Connection,
    table_name: str,
    primary_key: str,
    backed_up: bool,
) -> None:
    if not backed_up:
        return
    backup_name = f"sha_0007_{table_name}_backup"
    connection.exec_driver_sql(
        f'''
        INSERT INTO "{table_name}"
        SELECT backup.*
        FROM "{backup_name}" AS backup
        LEFT JOIN "{table_name}" AS current
          ON current."{primary_key}" = backup."{primary_key}"
        WHERE current."{primary_key}" IS NULL
        '''
    )
    backup_count = int(
        connection.exec_driver_sql(f'SELECT COUNT(*) FROM "{backup_name}"').scalar_one()
    )
    restored_count = int(
        connection.exec_driver_sql(f'SELECT COUNT(*) FROM "{table_name}"').scalar_one()
    )
    if backup_count != restored_count:
        raise RuntimeError(f"SQLite authorization migration did not preserve every {table_name} row")
    connection.exec_driver_sql(f'DROP TABLE "{backup_name}"')


def _seed_roles(connection: sa.Connection) -> None:
    for role_key, permissions in _ROLE_PERMISSIONS.items():
        role_id = f"role_{role_key}"
        connection.execute(
            sa.text(
                "INSERT INTO roles "
                "(role_id, key, name, is_system, created_at, updated_at) "
                "VALUES (:role_id, :key, :name, :is_system, :created_at, :updated_at)"
            ),
            {
                "role_id": role_id,
                "key": role_key,
                "name": _ROLE_NAMES[role_key],
                "is_system": True,
                "created_at": _SEEDED_AT,
                "updated_at": _SEEDED_AT,
            },
        )
        for permission in permissions:
            connection.execute(
                sa.text(
                    "INSERT INTO role_permissions (role_id, permission) "
                    "VALUES (:role_id, :permission)"
                ),
                {"role_id": role_id, "permission": permission},
            )


def _create_audit_immutability(connection: sa.Connection) -> None:
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql(
            """
            CREATE TRIGGER sha_audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER sha_audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END
            """
        )
        return
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            """
            CREATE FUNCTION sha_reject_audit_event_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'audit events are append-only';
            END;
            $$
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER sha_audit_events_no_update
            BEFORE UPDATE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION sha_reject_audit_event_mutation()
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER sha_audit_events_no_delete
            BEFORE DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION sha_reject_audit_event_mutation()
            """
        )
        return
    raise RuntimeError("audit immutability is unsupported for this database dialect")


def _drop_audit_immutability(connection: sa.Connection) -> None:
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("DROP TRIGGER sha_audit_events_no_update")
        connection.exec_driver_sql("DROP TRIGGER sha_audit_events_no_delete")
        return
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("DROP TRIGGER sha_audit_events_no_update ON audit_events")
        connection.exec_driver_sql("DROP TRIGGER sha_audit_events_no_delete ON audit_events")
        connection.exec_driver_sql("DROP FUNCTION sha_reject_audit_event_mutation()")
        return
    raise RuntimeError("audit immutability is unsupported for this database dialect")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("email_snapshot", sa.String(320)),
        sa.Column("last_login_at", sa.String(32)),
        sa.Column("disabled_at", sa.String(32)),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'disabled')",
            name="ck_users_status",
        ),
    )
    op.create_table(
        "oidc_identities",
        sa.Column("identity_id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("display_name_snapshot", sa.String(255), nullable=False),
        sa.Column("email_snapshot", sa.String(320)),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        sa.Column("last_seen_at", sa.String(32)),
        sa.UniqueConstraint("issuer", "subject", name="uq_oidc_identities_issuer_subject"),
    )
    op.create_index("ix_oidc_identities_user", "oidc_identities", ["user_id"])
    op.create_table(
        "roles",
        sa.Column("role_id", sa.String(64), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
    )
    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            sa.String(64),
            sa.ForeignKey("roles.role_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("permission", sa.String(128), primary_key=True),
    )
    op.create_table(
        "user_role_bindings",
        sa.Column("binding_id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "role_id",
            sa.String(64),
            sa.ForeignKey("roles.role_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("client_id", sa.String(64)),
        sa.Column("location_id", sa.String(64)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("revoked_at", sa.String(32)),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_user_role_bindings_client",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_user_role_bindings_location_client",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(scope_type = 'global' AND client_id IS NULL AND location_id IS NULL) OR "
            "(scope_type = 'client' AND client_id IS NOT NULL AND location_id IS NULL) OR "
            "(scope_type = 'location' AND client_id IS NOT NULL AND location_id IS NOT NULL)",
            name="ck_user_role_bindings_scope",
        ),
    )
    op.create_index(
        "ix_user_role_bindings_user",
        "user_role_bindings",
        ["user_id", "revoked_at"],
    )
    op.create_index(
        "uq_user_role_bindings_active_global",
        "user_role_bindings",
        ["user_id", "role_id"],
        unique=True,
        sqlite_where=sa.text("scope_type = 'global' AND revoked_at IS NULL"),
        postgresql_where=sa.text("scope_type = 'global' AND revoked_at IS NULL"),
    )
    op.create_index(
        "uq_user_role_bindings_active_client",
        "user_role_bindings",
        ["user_id", "role_id", "client_id"],
        unique=True,
        sqlite_where=sa.text("scope_type = 'client' AND revoked_at IS NULL"),
        postgresql_where=sa.text("scope_type = 'client' AND revoked_at IS NULL"),
    )
    op.create_index(
        "uq_user_role_bindings_active_location",
        "user_role_bindings",
        ["user_id", "role_id", "client_id", "location_id"],
        unique=True,
        sqlite_where=sa.text("scope_type = 'location' AND revoked_at IS NULL"),
        postgresql_where=sa.text("scope_type = 'location' AND revoked_at IS NULL"),
    )
    op.create_table(
        "oidc_login_transactions",
        sa.Column("transaction_id", sa.String(64), primary_key=True),
        sa.Column("state_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("browser_binding_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("hash_key_id", sa.String(32), nullable=False),
        sa.Column("nonce", sa.String(255), nullable=False),
        sa.Column("encrypted_code_verifier", sa.String(1024), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("redirect_uri", sa.String(2048), nullable=False),
        sa.Column("return_to", sa.String(2048), nullable=False),
        sa.Column("expires_at", sa.String(32), nullable=False),
        sa.Column("consumed_at", sa.String(32)),
        sa.Column("created_at", sa.String(32), nullable=False),
    )
    op.create_index(
        "ix_oidc_login_transactions_expiry",
        "oidc_login_transactions",
        ["expires_at", "consumed_at"],
    )
    op.create_table(
        "browser_sessions",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "identity_id",
            sa.String(64),
            sa.ForeignKey("oidc_identities.identity_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("hash_key_id", sa.String(32), nullable=False),
        sa.Column("authenticated_at", sa.String(32), nullable=False),
        sa.Column("last_seen_at", sa.String(32), nullable=False),
        sa.Column("idle_expires_at", sa.String(32), nullable=False),
        sa.Column("absolute_expires_at", sa.String(32), nullable=False),
        sa.Column("revoked_at", sa.String(32)),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
    )
    op.create_index(
        "ix_browser_sessions_user",
        "browser_sessions",
        ["user_id", "revoked_at"],
    )
    op.create_index(
        "ix_browser_sessions_expiry",
        "browser_sessions",
        ["idle_expires_at", "absolute_expires_at"],
    )
    op.create_table(
        "audit_events",
        sa.Column("audit_event_id", sa.String(64), primary_key=True),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("users.user_id", ondelete="SET NULL")),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("client_id", sa.String(64)),
        sa.Column("location_id", sa.String(64)),
        sa.Column("endpoint_id", sa.String(64)),
        sa.Column("target_type", sa.String(64)),
        sa.Column("target_id", sa.String(128)),
        sa.Column("request_id", sa.String(128)),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_audit_events_client",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_audit_events_location_client",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="ck_audit_events_outcome",
        ),
    )
    op.create_index(
        "ix_audit_events_scope_time",
        "audit_events",
        ["client_id", "location_id", "created_at"],
    )
    op.create_index(
        "ix_audit_events_actor_time",
        "audit_events",
        ["actor", "created_at"],
    )
    _create_audit_immutability(op.get_bind())

    op.add_column(
        "approval_requests",
        sa.Column("scope_state", sa.String(32), nullable=True, server_default="active"),
    )
    op.add_column("approval_requests", sa.Column("client_id", sa.String(64), nullable=True))
    op.add_column("approval_requests", sa.Column("location_id", sa.String(64), nullable=True))
    op.add_column(
        "approval_grants",
        sa.Column("scope_state", sa.String(32), nullable=True, server_default="active"),
    )
    op.add_column("approval_grants", sa.Column("client_id", sa.String(64), nullable=True))
    op.add_column("approval_grants", sa.Column("location_id", sa.String(64), nullable=True))

    connection = op.get_bind()
    _backfill_approval_scopes(connection)
    dependent_tables = (
        "approval_request_events",
        "approval_grants",
        "response_actions",
    )
    backed_up = _backup_sqlite_tables(connection, dependent_tables)
    with op.batch_alter_table("approval_requests") as batch:
        batch.alter_column("scope_state", existing_type=sa.String(32), nullable=False)
        batch.create_foreign_key(
            "fk_approval_requests_client",
            "clients",
            ["client_id"],
            ["client_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_approval_requests_location_client",
            "locations",
            ["location_id", "client_id"],
            ["location_id", "client_id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_approval_requests_scope_state",
            "(scope_state = 'active' AND client_id IS NOT NULL) OR "
            "(scope_state = 'migration_quarantine' AND client_id IS NULL AND location_id IS NULL)",
        )
    _restore_sqlite_table(
        connection,
        "approval_request_events",
        "approval_event_id",
        backed_up,
    )
    _restore_sqlite_table(
        connection,
        "approval_grants",
        "approval_grant_id",
        backed_up,
    )
    with op.batch_alter_table("approval_grants") as batch:
        batch.alter_column("scope_state", existing_type=sa.String(32), nullable=False)
        batch.create_foreign_key(
            "fk_approval_grants_client",
            "clients",
            ["client_id"],
            ["client_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_approval_grants_location_client",
            "locations",
            ["location_id", "client_id"],
            ["location_id", "client_id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_approval_grants_scope_state",
            "(scope_state = 'active' AND client_id IS NOT NULL) OR "
            "(scope_state = 'migration_quarantine' AND client_id IS NULL AND location_id IS NULL)",
        )
    _restore_sqlite_table(
        connection,
        "response_actions",
        "response_action_id",
        backed_up,
    )
    op.create_index(
        "ix_approval_requests_scope",
        "approval_requests",
        ["client_id", "location_id", "created_at"],
    )
    op.create_index(
        "ix_approval_grants_scope",
        "approval_grants",
        ["client_id", "location_id", "created_at"],
    )
    _seed_roles(connection)


def _assert_downgrade_safe(connection: sa.Connection) -> None:
    protected_tables = (
        "users",
        "oidc_identities",
        "user_role_bindings",
        "browser_sessions",
        "oidc_login_transactions",
        "audit_events",
    )
    populated = [
        table_name
        for table_name in protected_tables
        if int(
            connection.execute(
                sa.text(f'SELECT COUNT(*) FROM "{table_name}"')
            ).scalar_one()
        )
        > 0
    ]
    actual_roles = {
        (
            str(row.role_id),
            str(row.key),
            str(row.name),
            bool(row.is_system),
            str(row.created_at),
            str(row.updated_at),
        )
        for row in connection.execute(
            sa.text(
                "SELECT role_id, key, name, is_system, created_at, updated_at FROM roles"
            )
        )
    }
    expected_roles = {
        (
            f"role_{role_key}",
            role_key,
            _ROLE_NAMES[role_key],
            True,
            _SEEDED_AT,
            _SEEDED_AT,
        )
        for role_key in _ROLE_PERMISSIONS
    }
    actual_permissions = {
        (str(row.role_id), str(row.permission))
        for row in connection.execute(
            sa.text("SELECT role_id, permission FROM role_permissions")
        )
    }
    expected_permissions = {
        (f"role_{role_key}", permission)
        for role_key, permissions in _ROLE_PERMISSIONS.items()
        for permission in permissions
    }
    system_catalog_changed = (
        actual_roles != expected_roles or actual_permissions != expected_permissions
    )
    if populated or system_catalog_changed:
        details = ", ".join(populated)
        if system_catalog_changed:
            catalog_detail = "modified role or permission catalog"
            details = f"{details}, {catalog_detail}" if details else catalog_detail
        raise RuntimeError(
            "refusing authorization downgrade because it would destroy security data: "
            f"{details}"
        )


def downgrade() -> None:
    connection = op.get_bind()
    # Keep this as the first operation. A refused downgrade must not execute
    # schema DDL or change the current revision.
    _assert_downgrade_safe(connection)
    op.drop_index("ix_approval_grants_scope", table_name="approval_grants")
    op.drop_index("ix_approval_requests_scope", table_name="approval_requests")
    dependent_tables = (
        "approval_request_events",
        "approval_grants",
        "response_actions",
    )
    backed_up = _backup_sqlite_tables(connection, dependent_tables)
    with op.batch_alter_table("approval_requests") as batch:
        batch.drop_constraint("ck_approval_requests_scope_state", type_="check")
        batch.drop_constraint("fk_approval_requests_location_client", type_="foreignkey")
        batch.drop_constraint("fk_approval_requests_client", type_="foreignkey")
        batch.drop_column("location_id")
        batch.drop_column("client_id")
        batch.drop_column("scope_state")
    _restore_sqlite_table(
        connection,
        "approval_request_events",
        "approval_event_id",
        backed_up,
    )
    _restore_sqlite_table(
        connection,
        "approval_grants",
        "approval_grant_id",
        backed_up,
    )
    with op.batch_alter_table("approval_grants") as batch:
        batch.drop_constraint("ck_approval_grants_scope_state", type_="check")
        batch.drop_constraint("fk_approval_grants_location_client", type_="foreignkey")
        batch.drop_constraint("fk_approval_grants_client", type_="foreignkey")
        batch.drop_column("location_id")
        batch.drop_column("client_id")
        batch.drop_column("scope_state")
    _restore_sqlite_table(
        connection,
        "response_actions",
        "response_action_id",
        backed_up,
    )

    _drop_audit_immutability(connection)
    op.drop_table("audit_events")
    op.drop_table("browser_sessions")
    op.drop_table("oidc_login_transactions")
    op.drop_table("user_role_bindings")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("oidc_identities")
    op.drop_table("users")
