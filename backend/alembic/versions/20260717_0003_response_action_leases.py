from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260717_0003"
down_revision = "20260717_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("response_actions") as batch:
        batch.add_column(sa.Column("idempotency_key", sa.String(128), nullable=True))
        batch.add_column(sa.Column("lease_token_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("lease_expires_at", sa.String(32), nullable=True))
        batch.add_column(sa.Column("leased_at", sa.String(32), nullable=True))
        batch.add_column(
            sa.Column(
                "attempt_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
        batch.drop_constraint("ck_response_actions_status", type_="check")
        batch.create_check_constraint(
            "ck_response_actions_status",
            "status IN ('queued', 'leased', 'succeeded', 'failed', 'cancelled')",
        )

    op.execute(
        sa.text(
            """
            UPDATE response_actions
            SET idempotency_key = response_action_id
            WHERE idempotency_key IS NULL
            """
        )
    )

    with op.batch_alter_table("response_actions") as batch:
        batch.alter_column(
            "idempotency_key",
            existing_type=sa.String(128),
            nullable=False,
        )
        batch.alter_column(
            "attempt_count",
            existing_type=sa.Integer(),
            server_default=None,
        )
        batch.create_unique_constraint(
            "uq_response_actions_endpoint_idempotency",
            ["endpoint_id", "idempotency_key"],
        )


def downgrade() -> None:
    # The prior application does not understand leased actions. Requeue them before
    # restoring its status constraint so rollback remains possible and work is not
    # silently stranded in an unsupported state.
    op.execute(
        sa.text(
            """
            UPDATE response_actions
            SET status = 'queued'
            WHERE status = 'leased'
            """
        )
    )
    with op.batch_alter_table("response_actions") as batch:
        batch.drop_constraint(
            "uq_response_actions_endpoint_idempotency",
            type_="unique",
        )
        batch.drop_constraint("ck_response_actions_status", type_="check")
        batch.create_check_constraint(
            "ck_response_actions_status",
            "status IN ('queued', 'succeeded', 'failed', 'cancelled')",
        )
        batch.drop_column("attempt_count")
        batch.drop_column("leased_at")
        batch.drop_column("lease_expires_at")
        batch.drop_column("lease_token_hash")
        batch.drop_column("idempotency_key")
