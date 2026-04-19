from __future__ import annotations

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Endpoint(Base):
    __tablename__ = "endpoints"

    endpoint_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    platform_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    site_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    connectivity_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    declared_capabilities_json: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    execution_hooks_json: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_seen_at: Mapped[str] = mapped_column(String(32), nullable=False)
    last_heartbeat_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint("status IN ('pending', 'active', 'stale')", name="ck_endpoints_status"),
        CheckConstraint("platform IN ('windows', 'linux')", name="ck_endpoints_platform"),
        CheckConstraint(
            "connectivity_status IS NULL OR connectivity_status IN ('online', 'degraded')",
            name="ck_endpoints_connectivity_status",
        ),
    )


class PostureSnapshot(Base):
    __tablename__ = "posture_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"), nullable=False
    )
    observed_at: Mapped[str] = mapped_column(String(32), nullable=False)
    platform_profile: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)


class PostureResult(Base):
    __tablename__ = "posture_results"

    result_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("posture_snapshots.snapshot_id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"), nullable=False
    )
    control_key: Mapped[str] = mapped_column(String(255), nullable=False)
    control_key_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_value: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    recommended_value: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_summary: Mapped[str] = mapped_column(String(4096), nullable=False)
    reboot_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pass', 'fail', 'warn', 'error', 'not_applicable')",
            name="ck_posture_results_status",
        ),
        UniqueConstraint("snapshot_id", "control_key_normalized", name="uq_posture_results_snapshot_key"),
    )


class InstallerProfile(Base):
    __tablename__ = "installer_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    control_plane_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    policy_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    site_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("platform", "name_normalized", name="uq_installer_profiles_platform_name"),
        CheckConstraint("platform IN ('windows', 'linux')", name="ck_installer_profiles_platform"),
        CheckConstraint("channel IN ('stable', 'preview')", name="ck_installer_profiles_channel"),
        CheckConstraint(
            "policy_mode IN ('observe', 'safe_auto', 'approval_required')",
            name="ck_installer_profiles_policy_mode",
        ),
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    approval_request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    endpoint_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    request_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    control_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    troubleshooting_scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    requested_ttl_minutes: Mapped[int] = mapped_column(nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(4096), nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    decision_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_comment: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    decision_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approval_grant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "request_kind IN ('hardening_change', 'elevated_troubleshooting')",
            name="ck_approval_requests_request_kind",
        ),
        CheckConstraint(
            "risk IN ('low', 'medium', 'high', 'critical')",
            name="ck_approval_requests_risk",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'expired', 'revoked')",
            name="ck_approval_requests_status",
        ),
    )


class ApprovalRequestEvent(Base):
    __tablename__ = "approval_request_events"

    approval_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    approval_request_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("approval_requests.approval_request_id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    comment: Mapped[str] = mapped_column(String(4096), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "approval_request_id",
            "event_type",
            name="uq_approval_request_events_request_event_type",
        ),
        CheckConstraint(
            "event_type IN ('requested', 'approved', 'denied', 'revoked', 'expired')",
            name="ck_approval_request_events_event_type",
        ),
    )


class ApprovalGrant(Base):
    __tablename__ = "approval_grants"

    approval_grant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    approval_request_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("approval_requests.approval_request_id", ondelete="SET NULL"),
        nullable=True,
    )
    endpoint_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    allowed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    control_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    troubleshooting_scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(4096), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("approval_request_id", name="uq_approval_grants_request_id"),
        CheckConstraint(
            "status IN ('approved', 'expired', 'revoked')",
            name="ck_approval_grants_status",
        ),
    )
