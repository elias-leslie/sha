from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260717_0004"
down_revision = "20260717_0003"
branch_labels = None
depends_on = None

_ALIASES = {
    "journald.storage-persistent": "linux.telemetry.security-logging",
    "linux.ssh.disable_password_authentication": "linux.ssh.password-authentication-disabled",
    "ssh.disable-password-authentication": "linux.ssh.password-authentication-disabled",
    "ufw.enabled": "linux.firewall.service-active",
    "windows.defender.real-time-protection": "control.windows.defender-real-time-protection",
    "windows.defender.real_time_protection": "control.windows.defender-real-time-protection",
    "windows.firewall.all-profiles-enabled": "control.windows.firewall-all-profiles",
    "windows.firewall.all_profiles": "control.windows.firewall-all-profiles",
}


def upgrade() -> None:
    connection = op.get_bind()
    for alias, canonical in _ALIASES.items():
        rows = connection.execute(
            sa.text(
                """
                SELECT result_id, snapshot_id
                FROM posture_results
                WHERE lower(control_key_normalized) = :alias
                """
            ),
            {"alias": alias},
        ).mappings().all()
        for row in rows:
            duplicate = connection.execute(
                sa.text(
                    """
                    SELECT 1
                    FROM posture_results
                    WHERE snapshot_id = :snapshot_id
                      AND lower(control_key_normalized) = :canonical
                    """
                ),
                {
                    "snapshot_id": row["snapshot_id"],
                    "canonical": canonical,
                },
            ).first()
            if duplicate is not None:
                connection.execute(
                    sa.text("DELETE FROM posture_results WHERE result_id = :result_id"),
                    {"result_id": row["result_id"]},
                )
                continue
            connection.execute(
                sa.text(
                    """
                    UPDATE posture_results
                    SET control_key = :canonical,
                        control_key_normalized = :canonical
                    WHERE result_id = :result_id
                    """
                ),
                {
                    "canonical": canonical,
                    "result_id": row["result_id"],
                },
            )


def downgrade() -> None:
    pass
