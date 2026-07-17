from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260717_0001"
down_revision = None
branch_labels = None
depends_on = None

_baseline = sa.MetaData()

sa.Table(
    "endpoints",
    _baseline,
    sa.Column("endpoint_id", sa.String(64), primary_key=True),
    sa.Column("agent_fingerprint", sa.String(255), nullable=False, unique=True),
    sa.Column("hostname", sa.String(255), nullable=False),
    sa.Column("platform", sa.String(32), nullable=False),
    sa.Column("platform_version", sa.String(255)),
    sa.Column("platform_profile", sa.String(255)),
    sa.Column("agent_version", sa.String(64), nullable=False),
    sa.Column("tenant_id", sa.String(255)),
    sa.Column("site_id", sa.String(255)),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("connectivity_status", sa.String(16)),
    sa.Column("declared_capabilities_json", sa.String(2048)),
    sa.Column("execution_hooks_json", sa.String(255)),
    sa.Column("last_seen_at", sa.String(32), nullable=False),
    sa.Column("last_heartbeat_at", sa.String(32)),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.String(32), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'active', 'stale')", name="ck_endpoints_status"),
    sa.CheckConstraint("platform IN ('windows', 'linux', 'macos')", name="ck_endpoints_platform"),
    sa.CheckConstraint(
        "connectivity_status IS NULL OR connectivity_status IN ('online', 'degraded')",
        name="ck_endpoints_connectivity_status",
    ),
)

sa.Table(
    "posture_snapshots",
    _baseline,
    sa.Column("snapshot_id", sa.String(64), primary_key=True),
    sa.Column(
        "endpoint_id",
        sa.String(64),
        sa.ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("observed_at", sa.String(32), nullable=False),
    sa.Column("platform_profile", sa.String(255), nullable=False),
    sa.Column("created_at", sa.String(32), nullable=False),
)

sa.Table(
    "posture_results",
    _baseline,
    sa.Column("result_id", sa.String(64), primary_key=True),
    sa.Column(
        "snapshot_id",
        sa.String(64),
        sa.ForeignKey("posture_snapshots.snapshot_id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column(
        "endpoint_id",
        sa.String(64),
        sa.ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("control_key", sa.String(255), nullable=False),
    sa.Column("control_key_normalized", sa.String(255), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("current_value", sa.String(2048)),
    sa.Column("recommended_value", sa.String(2048)),
    sa.Column("severity", sa.String(255)),
    sa.Column("evidence_summary", sa.String(4096), nullable=False),
    sa.Column("reboot_required", sa.Boolean(), nullable=False),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.CheckConstraint(
        "status IN ('pass', 'fail', 'warn', 'error', 'not_applicable')",
        name="ck_posture_results_status",
    ),
    sa.UniqueConstraint(
        "snapshot_id",
        "control_key_normalized",
        name="uq_posture_results_snapshot_key",
    ),
)

sa.Table(
    "installer_profiles",
    _baseline,
    sa.Column("id", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(255), nullable=False),
    sa.Column("name_normalized", sa.String(255), nullable=False),
    sa.Column("platform", sa.String(32), nullable=False),
    sa.Column("channel", sa.String(32), nullable=False),
    sa.Column("control_plane_url", sa.String(2048), nullable=False),
    sa.Column("policy_mode", sa.String(32), nullable=False),
    sa.Column("tenant_id", sa.String(255)),
    sa.Column("site_id", sa.String(255)),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.String(32), nullable=False),
    sa.UniqueConstraint(
        "platform",
        "name_normalized",
        name="uq_installer_profiles_platform_name",
    ),
    sa.CheckConstraint(
        "platform IN ('windows', 'linux', 'macos')",
        name="ck_installer_profiles_platform",
    ),
    sa.CheckConstraint(
        "channel IN ('stable', 'preview')",
        name="ck_installer_profiles_channel",
    ),
    sa.CheckConstraint(
        "policy_mode IN ('observe', 'safe_auto', 'approval_required')",
        name="ck_installer_profiles_policy_mode",
    ),
)

sa.Table(
    "approval_requests",
    _baseline,
    sa.Column("approval_request_id", sa.String(64), primary_key=True),
    sa.Column("endpoint_ids", sa.JSON(), nullable=False),
    sa.Column("request_kind", sa.String(64), nullable=False),
    sa.Column("requested_actions", sa.JSON(), nullable=False),
    sa.Column("control_ids", sa.JSON(), nullable=False),
    sa.Column("troubleshooting_scopes", sa.JSON(), nullable=False),
    sa.Column("requested_ttl_minutes", sa.Integer(), nullable=False),
    sa.Column("requested_by", sa.String(255), nullable=False),
    sa.Column("reason", sa.String(4096), nullable=False),
    sa.Column("risk", sa.String(16), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("decision_by", sa.String(255)),
    sa.Column("decision_comment", sa.String(4096)),
    sa.Column("decision_at", sa.String(32)),
    sa.Column("approval_grant_id", sa.String(64)),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.String(32), nullable=False),
    sa.CheckConstraint(
        "request_kind IN ('hardening_change', 'elevated_troubleshooting')",
        name="ck_approval_requests_request_kind",
    ),
    sa.CheckConstraint(
        "risk IN ('low', 'medium', 'high', 'critical')",
        name="ck_approval_requests_risk",
    ),
    sa.CheckConstraint(
        "status IN ('pending', 'approved', 'denied', 'expired', 'revoked')",
        name="ck_approval_requests_status",
    ),
)

sa.Table(
    "approval_request_events",
    _baseline,
    sa.Column("approval_event_id", sa.String(64), primary_key=True),
    sa.Column(
        "approval_request_id",
        sa.String(64),
        sa.ForeignKey("approval_requests.approval_request_id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("event_type", sa.String(16), nullable=False),
    sa.Column("actor", sa.String(255), nullable=False),
    sa.Column("comment", sa.String(4096), nullable=False),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.UniqueConstraint(
        "approval_request_id",
        "event_type",
        name="uq_approval_request_events_request_event_type",
    ),
    sa.CheckConstraint(
        "event_type IN ('requested', 'approved', 'denied', 'revoked', 'expired')",
        name="ck_approval_request_events_event_type",
    ),
)

sa.Table(
    "approval_grants",
    _baseline,
    sa.Column("approval_grant_id", sa.String(64), primary_key=True),
    sa.Column(
        "approval_request_id",
        sa.String(64),
        sa.ForeignKey("approval_requests.approval_request_id", ondelete="SET NULL"),
    ),
    sa.Column("endpoint_ids", sa.JSON(), nullable=False),
    sa.Column("allowed_actions", sa.JSON(), nullable=False),
    sa.Column("control_ids", sa.JSON(), nullable=False),
    sa.Column("troubleshooting_scopes", sa.JSON(), nullable=False),
    sa.Column("requested_by", sa.String(255), nullable=False),
    sa.Column("approved_by", sa.String(255), nullable=False),
    sa.Column("reason", sa.String(4096), nullable=False),
    sa.Column("expires_at", sa.String(32), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.String(32), nullable=False),
    sa.UniqueConstraint("approval_request_id", name="uq_approval_grants_request_id"),
    sa.CheckConstraint(
        "status IN ('approved', 'expired', 'revoked')",
        name="ck_approval_grants_status",
    ),
)

sa.Table(
    "response_actions",
    _baseline,
    sa.Column("response_action_id", sa.String(64), primary_key=True),
    sa.Column(
        "endpoint_id",
        sa.String(64),
        sa.ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column(
        "approval_grant_id",
        sa.String(64),
        sa.ForeignKey("approval_grants.approval_grant_id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("action", sa.String(64), nullable=False),
    sa.Column("control_id", sa.String(255)),
    sa.Column("troubleshooting_scope", sa.String(64)),
    sa.Column("requested_by", sa.String(255), nullable=False),
    sa.Column("reason", sa.String(4096), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("result_summary", sa.String(4096)),
    sa.Column("created_at", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.String(32), nullable=False),
    sa.Column("completed_at", sa.String(32)),
    sa.CheckConstraint(
        "action IN ("
        "'collect_security_context', 'collect_remediation_evidence', 'inspect_control', "
        "'apply_control', 'rollback_control', 'request_elevated_troubleshooting'"
        ")",
        name="ck_response_actions_action",
    ),
    sa.CheckConstraint(
        "status IN ('queued', 'succeeded', 'failed', 'cancelled')",
        name="ck_response_actions_status",
    ),
)


def upgrade() -> None:
    _baseline.create_all(bind=op.get_bind())


def downgrade() -> None:
    raise RuntimeError("the adopted SHA baseline cannot be downgraded automatically")
