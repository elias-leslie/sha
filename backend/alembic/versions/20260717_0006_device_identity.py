from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260717_0006"
down_revision = "20260717_0005"
branch_labels = None
depends_on = None


def _backup_sqlite_endpoint_dependents(connection: sa.Connection) -> bool:
    if connection.dialect.name != "sqlite":
        return False
    for table_name in ("posture_results", "posture_snapshots", "response_actions"):
        backup_name = f"sha_0006_{table_name}_backup"
        connection.exec_driver_sql(f'DROP TABLE IF EXISTS "{backup_name}"')
        connection.exec_driver_sql(
            f'CREATE TEMPORARY TABLE "{backup_name}" AS SELECT * FROM "{table_name}"'
        )
    return True


def _restore_sqlite_endpoint_dependents(
    connection: sa.Connection,
    backed_up: bool,
) -> None:
    if not backed_up:
        return
    primary_keys = {
        "posture_snapshots": "snapshot_id",
        "posture_results": "result_id",
        "response_actions": "response_action_id",
    }
    for table_name, primary_key in primary_keys.items():
        backup_name = f"sha_0006_{table_name}_backup"
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
                f"SQLite device identity migration did not preserve every {table_name} row"
            )
        connection.exec_driver_sql(f'DROP TABLE "{backup_name}"')


def _assert_downgrade_has_no_device_identity(connection: sa.Connection) -> None:
    live_device_endpoint = connection.execute(
        sa.text(
            """
            SELECT endpoint_id
            FROM endpoints
            WHERE credential_mode = 'device'
            LIMIT 1
            """
        )
    ).first()
    populated_table = None
    for table_name in (
        "enrollment_tokens",
        "device_credentials",
        "enrollment_redemptions",
    ):
        if connection.execute(
            sa.text(f'SELECT 1 FROM "{table_name}" LIMIT 1')
        ).first() is not None:
            populated_table = table_name
            break
    if live_device_endpoint is not None or populated_table is not None:
        raise RuntimeError(
            "cannot downgrade device identity while device-mode endpoints or identity records exist"
        )


def upgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("token_id", sa.String(64), primary_key=True),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("hash_key_id", sa.String(32), nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("location_id", sa.String(64), nullable=False),
        sa.Column(
            "installer_profile_id",
            sa.String(64),
            sa.ForeignKey("installer_profiles.id", ondelete="RESTRICT"),
        ),
        sa.Column("platform", sa.String(32)),
        sa.Column("approval_policy", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.String(32), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column(
            "use_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("revoked_at", sa.String(32)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_enrollment_tokens_location_client",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "platform IS NULL OR platform IN ('windows', 'linux', 'macos')",
            name="ck_enrollment_tokens_platform",
        ),
        sa.CheckConstraint(
            "approval_policy IN ('pending', 'approved')",
            name="ck_enrollment_tokens_approval_policy",
        ),
        sa.CheckConstraint(
            "max_uses > 0",
            name="ck_enrollment_tokens_max_uses",
        ),
        sa.CheckConstraint(
            "use_count >= 0 AND use_count <= max_uses",
            name="ck_enrollment_tokens_use_count",
        ),
    )
    op.create_index(
        "ix_enrollment_tokens_scope",
        "enrollment_tokens",
        ["client_id", "location_id"],
    )

    op.add_column("endpoints", sa.Column("installation_id", sa.String(128)))
    op.add_column("endpoints", sa.Column("credential_mode", sa.String(32)))
    op.add_column("endpoints", sa.Column("enrollment_token_id", sa.String(64)))
    op.add_column("endpoints", sa.Column("protocol_version", sa.String(32)))
    op.add_column("endpoints", sa.Column("architecture", sa.String(32)))
    op.execute(
        sa.text(
            """
            UPDATE endpoints
            SET credential_mode = 'legacy_shared',
                protocol_version = 'legacy-v1'
            WHERE credential_mode IS NULL OR protocol_version IS NULL
            """
        )
    )

    connection = op.get_bind()
    endpoint_dependents_backed_up = _backup_sqlite_endpoint_dependents(connection)
    with op.batch_alter_table("endpoints") as batch:
        batch.alter_column(
            "credential_mode",
            existing_type=sa.String(32),
            nullable=False,
            server_default=sa.text("'legacy_shared'"),
        )
        batch.alter_column(
            "protocol_version",
            existing_type=sa.String(32),
            nullable=False,
            server_default=sa.text("'legacy-v1'"),
        )
        batch.create_unique_constraint(
            "uq_endpoints_installation_id",
            ["installation_id"],
        )
        batch.create_check_constraint(
            "ck_endpoints_credential_mode",
            "credential_mode IN ('legacy_shared', 'device')",
        )
        batch.create_foreign_key(
            "fk_endpoints_enrollment_token_id",
            "enrollment_tokens",
            ["enrollment_token_id"],
            ["token_id"],
            ondelete="RESTRICT",
        )
    _restore_sqlite_endpoint_dependents(connection, endpoint_dependents_backed_up)

    op.create_table(
        "device_credentials",
        sa.Column("credential_id", sa.String(96), primary_key=True),
        sa.Column(
            "endpoint_id",
            sa.String(64),
            sa.ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("hash_key_id", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column(
            "replaced_by_credential_id",
            sa.String(96),
            sa.ForeignKey("device_credentials.credential_id", ondelete="SET NULL"),
        ),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        sa.Column("replaced_at", sa.String(32)),
        sa.Column("revoked_at", sa.String(32)),
        sa.CheckConstraint(
            "status IN ('active', 'replaced', 'revoked')",
            name="ck_device_credentials_status",
        ),
    )
    op.create_index(
        "ix_device_credentials_endpoint",
        "device_credentials",
        ["endpoint_id"],
    )
    active_credential_predicate = sa.text("status = 'active'")
    op.create_index(
        "uq_device_credentials_active_endpoint",
        "device_credentials",
        ["endpoint_id"],
        unique=True,
        sqlite_where=active_credential_predicate,
        postgresql_where=active_credential_predicate,
    )

    op.create_table(
        "enrollment_redemptions",
        sa.Column("redemption_id", sa.String(64), primary_key=True),
        sa.Column(
            "enrollment_token_id",
            sa.String(64),
            sa.ForeignKey("enrollment_tokens.token_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("installation_id", sa.String(128), nullable=False),
        sa.Column(
            "endpoint_id",
            sa.String(64),
            sa.ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "credential_id",
            sa.String(96),
            sa.ForeignKey("device_credentials.credential_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.UniqueConstraint(
            "enrollment_token_id",
            "installation_id",
            name="uq_enrollment_redemptions_token_installation",
        ),
        sa.UniqueConstraint(
            "credential_id",
            name="uq_enrollment_redemptions_credential",
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    _assert_downgrade_has_no_device_identity(connection)
    op.drop_table("enrollment_redemptions")
    op.drop_index(
        "uq_device_credentials_active_endpoint",
        table_name="device_credentials",
    )
    op.drop_index(
        "ix_device_credentials_endpoint",
        table_name="device_credentials",
    )
    op.drop_table("device_credentials")

    endpoint_dependents_backed_up = _backup_sqlite_endpoint_dependents(connection)
    with op.batch_alter_table("endpoints") as batch:
        batch.drop_constraint(
            "fk_endpoints_enrollment_token_id",
            type_="foreignkey",
        )
        batch.drop_constraint(
            "ck_endpoints_credential_mode",
            type_="check",
        )
        batch.drop_constraint(
            "uq_endpoints_installation_id",
            type_="unique",
        )
        batch.drop_column("enrollment_token_id")
        batch.drop_column("credential_mode")
        batch.drop_column("installation_id")
        batch.drop_column("architecture")
        batch.drop_column("protocol_version")
    _restore_sqlite_endpoint_dependents(connection, endpoint_dependents_backed_up)
    op.drop_index("ix_enrollment_tokens_scope", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")
