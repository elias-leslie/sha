from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260717_0009"
down_revision = "20260717_0008"
branch_labels = None
depends_on = None


def _assert_downgrade_safe(connection: sa.Connection) -> None:
    live_protocol_state = connection.execute(
        sa.text(
            "SELECT endpoint_id FROM endpoints "
            "WHERE capability_manifest_json IS NOT NULL LIMIT 1"
        )
    ).first()
    live_credential_state = connection.execute(
        sa.text(
            "SELECT credential_id FROM device_credentials "
            "WHERE last_used_at IS NOT NULL OR expires_at IS NOT NULL LIMIT 1"
        )
    ).first()
    canonical_profile = connection.execute(
        sa.text(
            "SELECT id FROM installer_profiles "
            "WHERE runtime_kind = 'go_agent' LIMIT 1"
        )
    ).first()
    if live_protocol_state or live_credential_state or canonical_profile:
        raise RuntimeError(
            "refusing agent protocol downgrade because canonical agent capability, "
            "credential lifecycle, or installer profile state would be lost"
        )


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column("capability_manifest_json", sa.String(16_384)),
    )
    op.add_column(
        "device_credentials",
        sa.Column("last_used_at", sa.String(32)),
    )
    op.add_column(
        "device_credentials",
        sa.Column("expires_at", sa.String(32)),
    )
    op.add_column(
        "installer_profiles",
        sa.Column("runtime_kind", sa.String(32)),
    )
    op.execute(
        sa.text(
            "UPDATE installer_profiles "
            "SET runtime_kind = 'legacy_reporter' "
            "WHERE runtime_kind IS NULL"
        )
    )
    with op.batch_alter_table("installer_profiles") as batch:
        batch.alter_column(
            "runtime_kind",
            existing_type=sa.String(32),
            nullable=False,
            server_default=sa.text("'go_agent'"),
        )
        batch.create_check_constraint(
            "ck_installer_profiles_runtime_kind",
            "runtime_kind IN ('go_agent', 'legacy_reporter')",
        )


def downgrade() -> None:
    connection = op.get_bind()
    _assert_downgrade_safe(connection)
    with op.batch_alter_table("installer_profiles") as batch:
        batch.drop_constraint(
            "ck_installer_profiles_runtime_kind",
            type_="check",
        )
        batch.drop_column("runtime_kind")
    op.drop_column("device_credentials", "expires_at")
    op.drop_column("device_credentials", "last_used_at")
    op.drop_column("endpoints", "capability_manifest_json")
