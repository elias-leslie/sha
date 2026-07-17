from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Client(Base):
    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("key", name="uq_clients_key"),
        CheckConstraint(
            "state IN ('active', 'archived', 'migration_quarantine')",
            name="ck_clients_state",
        ),
    )


class Location(Base):
    __tablename__ = "locations"

    location_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("clients.client_id", ondelete="RESTRICT"), nullable=False
    )
    key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("location_id", "client_id", name="uq_locations_id_client"),
        UniqueConstraint("client_id", "key", name="uq_locations_client_key"),
        CheckConstraint(
            "state IN ('active', 'archived', 'migration_quarantine')",
            name="ck_locations_state",
        ),
    )


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email_snapshot: Mapped[str | None] = mapped_column(String(320), nullable=True)
    last_login_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    disabled_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'active', 'disabled')",
            name="ck_users_status",
        ),
    )


class OidcIdentity(Base):
    __tablename__ = "oidc_identities"

    identity_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name_snapshot: Mapped[str] = mapped_column(String(255), nullable=False)
    email_snapshot: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)
    last_seen_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_oidc_identities_issuer_subject"),
        Index("ix_oidc_identities_user", "user_id"),
    )


class Role(Base):
    __tablename__ = "roles"

    role_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("roles.role_id", ondelete="CASCADE"), primary_key=True
    )
    permission: Mapped[str] = mapped_column(String(128), primary_key=True)


class UserRoleBinding(Base):
    __tablename__ = "user_role_bindings"

    binding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("roles.role_id", ondelete="RESTRICT"), nullable=False
    )
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_user_role_bindings_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_user_role_bindings_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_type = 'global' AND client_id IS NULL AND location_id IS NULL) OR "
            "(scope_type = 'client' AND client_id IS NOT NULL AND location_id IS NULL) OR "
            "(scope_type = 'location' AND client_id IS NOT NULL AND location_id IS NOT NULL)",
            name="ck_user_role_bindings_scope",
        ),
        Index("ix_user_role_bindings_user", "user_id", "revoked_at"),
        Index(
            "uq_user_role_bindings_active_global",
            "user_id",
            "role_id",
            unique=True,
            sqlite_where=text("scope_type = 'global' AND revoked_at IS NULL"),
            postgresql_where=text("scope_type = 'global' AND revoked_at IS NULL"),
        ),
        Index(
            "uq_user_role_bindings_active_client",
            "user_id",
            "role_id",
            "client_id",
            unique=True,
            sqlite_where=text("scope_type = 'client' AND revoked_at IS NULL"),
            postgresql_where=text("scope_type = 'client' AND revoked_at IS NULL"),
        ),
        Index(
            "uq_user_role_bindings_active_location",
            "user_id",
            "role_id",
            "client_id",
            "location_id",
            unique=True,
            sqlite_where=text("scope_type = 'location' AND revoked_at IS NULL"),
            postgresql_where=text("scope_type = 'location' AND revoked_at IS NULL"),
        ),
    )


class OidcLoginTransaction(Base):
    __tablename__ = "oidc_login_transactions"

    transaction_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    browser_binding_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    hash_key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_code_verifier: Mapped[str] = mapped_column(String(1024), nullable=False)
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    return_to: Mapped[str] = mapped_column(String(2048), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(32), nullable=False)
    consumed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        Index("ix_oidc_login_transactions_expiry", "expires_at", "consumed_at"),
    )


class BrowserSession(Base):
    __tablename__ = "browser_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    identity_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("oidc_identities.identity_id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    hash_key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    authenticated_at: Mapped[str] = mapped_column(String(32), nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(32), nullable=False)
    idle_expires_at: Mapped[str] = mapped_column(String(32), nullable=False)
    absolute_expires_at: Mapped[str] = mapped_column(String(32), nullable=False)
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        Index("ix_browser_sessions_user", "user_id", "revoked_at"),
        Index("ix_browser_sessions_expiry", "idle_expires_at", "absolute_expires_at"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    audit_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_audit_events_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_audit_events_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="ck_audit_events_outcome",
        ),
        Index("ix_audit_events_scope_time", "client_id", "location_id", "created_at"),
        Index("ix_audit_events_actor_time", "actor", "created_at"),
    )


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    token_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    location_id: Mapped[str] = mapped_column(String(64), nullable=False)
    installer_profile_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("installer_profiles.id", ondelete="RESTRICT"), nullable=True
    )
    platform: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approval_policy: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(32), nullable=False)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_enrollment_tokens_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "platform IS NULL OR platform IN ('windows', 'linux', 'macos')",
            name="ck_enrollment_tokens_platform",
        ),
        CheckConstraint(
            "approval_policy IN ('pending', 'approved')",
            name="ck_enrollment_tokens_approval_policy",
        ),
        CheckConstraint("max_uses > 0", name="ck_enrollment_tokens_max_uses"),
        CheckConstraint(
            "use_count >= 0 AND use_count <= max_uses",
            name="ck_enrollment_tokens_use_count",
        ),
        Index("ix_enrollment_tokens_scope", "client_id", "location_id"),
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    endpoint_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    platform_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol_version: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="legacy-v1"
    )
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    installation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    credential_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="legacy_shared"
    )
    enrollment_token_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("enrollment_tokens.token_id", ondelete="RESTRICT"), nullable=True
    )
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    location_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    site_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    connectivity_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    declared_capabilities_json: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    capability_manifest_json: Mapped[str | None] = mapped_column(String(16_384), nullable=True)
    execution_hooks_json: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_seen_at: Mapped[str] = mapped_column(String(32), nullable=False)
    last_heartbeat_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_endpoints_location_client",
            ondelete="RESTRICT",
        ),
        Index(
            "uq_endpoints_id_scope",
            "endpoint_id",
            "client_id",
            "location_id",
            unique=True,
        ),
        Index("ix_endpoints_client_location", "client_id", "location_id"),
        UniqueConstraint("installation_id", name="uq_endpoints_installation_id"),
        CheckConstraint("status IN ('pending', 'active', 'stale')", name="ck_endpoints_status"),
        CheckConstraint(
            "credential_mode IN ('legacy_shared', 'device')",
            name="ck_endpoints_credential_mode",
        ),
        CheckConstraint("platform IN ('windows', 'linux', 'macos')", name="ck_endpoints_platform"),
        CheckConstraint(
            "connectivity_status IS NULL OR connectivity_status IN ('online', 'degraded')",
            name="ck_endpoints_connectivity_status",
        ),
    )


class Tag(Base):
    __tablename__ = "tags"

    tag_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(208), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_tags_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_tags_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_type = 'global' AND client_id IS NULL AND location_id IS NULL "
            "AND scope_key = 'global') OR "
            "(scope_type = 'client' AND client_id IS NOT NULL AND location_id IS NULL "
            "AND scope_key = 'client:' || client_id) OR "
            "(scope_type = 'location' AND client_id IS NOT NULL AND location_id IS NOT NULL "
            "AND scope_key = 'location:' || client_id || ':' || location_id)",
            name="ck_tags_scope",
        ),
        UniqueConstraint("scope_key", "name_normalized", name="uq_tags_scope_name"),
        UniqueConstraint("tag_id", "scope_key", name="uq_tags_id_scope"),
        Index("ix_tags_scope", "scope_type", "client_id", "location_id"),
    )


class EndpointTagAssignment(Base):
    __tablename__ = "endpoint_tag_assignments"

    endpoint_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tag_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    location_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tag_scope_key: Mapped[str] = mapped_column(String(208), nullable=False)
    assigned_by: Mapped[str] = mapped_column(String(255), nullable=False)
    assigned_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["endpoint_id", "client_id", "location_id"],
            ["endpoints.endpoint_id", "endpoints.client_id", "endpoints.location_id"],
            name="fk_endpoint_tag_assignments_endpoint_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tag_id", "tag_scope_key"],
            ["tags.tag_id", "tags.scope_key"],
            name="fk_endpoint_tag_assignments_tag_scope",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "tag_scope_key = 'global' OR "
            "tag_scope_key = 'client:' || client_id OR "
            "tag_scope_key = 'location:' || client_id || ':' || location_id",
            name="ck_endpoint_tag_assignments_scope",
        ),
        Index(
            "ix_endpoint_tag_assignments_scope",
            "client_id",
            "location_id",
            "tag_id",
        ),
    )


class SavedView(Base):
    __tablename__ = "saved_views"

    saved_view_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(208), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner_user_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )
    owner_actor: Mapped[str] = mapped_column(String(255), nullable=False)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_saved_views_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_saved_views_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_type = 'global' AND client_id IS NULL AND location_id IS NULL "
            "AND scope_key = 'global') OR "
            "(scope_type = 'client' AND client_id IS NOT NULL AND location_id IS NULL "
            "AND scope_key = 'client:' || client_id) OR "
            "(scope_type = 'location' AND client_id IS NOT NULL AND location_id IS NOT NULL "
            "AND scope_key = 'location:' || client_id || ':' || location_id)",
            name="ck_saved_views_scope",
        ),
        CheckConstraint(
            "visibility IN ('private', 'shared')",
            name="ck_saved_views_visibility",
        ),
        CheckConstraint("current_version > 0", name="ck_saved_views_current_version"),
        UniqueConstraint(
            "scope_key", "name_normalized", name="uq_saved_views_scope_name"
        ),
        UniqueConstraint(
            "saved_view_id", "scope_key", name="uq_saved_views_id_scope"
        ),
        Index(
            "ix_saved_views_scope",
            "scope_type",
            "client_id",
            "location_id",
            "visibility",
        ),
        Index("ix_saved_views_owner", "owner_user_id", "owner_actor"),
    )


class SavedViewVersion(Base):
    __tablename__ = "saved_view_versions"

    saved_view_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("saved_views.saved_view_id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    filter_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint("version > 0", name="ck_saved_view_versions_version"),
        UniqueConstraint(
            "saved_view_id", "content_hash", name="uq_saved_view_versions_content"
        ),
    )


class DynamicGroup(Base):
    __tablename__ = "dynamic_groups"

    dynamic_group_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(208), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    saved_view_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_user_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )
    owner_actor: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_dynamic_groups_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_dynamic_groups_location_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["saved_view_id", "scope_key"],
            ["saved_views.saved_view_id", "saved_views.scope_key"],
            name="fk_dynamic_groups_saved_view_scope",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "(scope_type = 'global' AND client_id IS NULL AND location_id IS NULL "
            "AND scope_key = 'global') OR "
            "(scope_type = 'client' AND client_id IS NOT NULL AND location_id IS NULL "
            "AND scope_key = 'client:' || client_id) OR "
            "(scope_type = 'location' AND client_id IS NOT NULL AND location_id IS NOT NULL "
            "AND scope_key = 'location:' || client_id || ':' || location_id)",
            name="ck_dynamic_groups_scope",
        ),
        UniqueConstraint(
            "scope_key", "name_normalized", name="uq_dynamic_groups_scope_name"
        ),
        Index(
            "ix_dynamic_groups_scope",
            "scope_type",
            "client_id",
            "location_id",
        ),
        Index("ix_dynamic_groups_saved_view", "saved_view_id"),
    )


class DeviceCredential(Base):
    __tablename__ = "device_credentials"

    credential_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"), nullable=False
    )
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    replaced_by_credential_id: Mapped[str | None] = mapped_column(
        String(96), ForeignKey("device_credentials.credential_id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)
    replaced_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'replaced', 'revoked')",
            name="ck_device_credentials_status",
        ),
        Index("ix_device_credentials_endpoint", "endpoint_id"),
        Index(
            "uq_device_credentials_active_endpoint",
            "endpoint_id",
            unique=True,
            sqlite_where=text("status = 'active'"),
            postgresql_where=text("status = 'active'"),
        ),
    )


class EnrollmentRedemption(Base):
    __tablename__ = "enrollment_redemptions"

    redemption_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enrollment_token_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("enrollment_tokens.token_id", ondelete="RESTRICT"), nullable=False
    )
    installation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    endpoint_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"), nullable=False
    )
    credential_id: Mapped[str] = mapped_column(
        String(96), ForeignKey("device_credentials.credential_id", ondelete="RESTRICT"), nullable=False
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "enrollment_token_id",
            "installation_id",
            name="uq_enrollment_redemptions_token_installation",
        ),
        UniqueConstraint("credential_id", name="uq_enrollment_redemptions_credential"),
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
    runtime_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="go_agent"
    )
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    location_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    site_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_installer_profiles_location_client",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "client_id",
            "platform",
            "name_normalized",
            name="uq_installer_profiles_client_platform_name",
        ),
        Index(
            "ix_installer_profiles_client_location",
            "client_id",
            "location_id",
        ),
        CheckConstraint("platform IN ('windows', 'linux', 'macos')", name="ck_installer_profiles_platform"),
        CheckConstraint("channel IN ('stable', 'preview')", name="ck_installer_profiles_channel"),
        CheckConstraint(
            "policy_mode IN ('observe', 'safe_auto', 'approval_required')",
            name="ck_installer_profiles_policy_mode",
        ),
        CheckConstraint(
            "runtime_kind IN ('go_agent', 'legacy_reporter')",
            name="ck_installer_profiles_runtime_kind",
        ),
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    approval_request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="active")
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
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
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_approval_requests_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_approval_requests_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_state = 'active' AND client_id IS NOT NULL) OR "
            "(scope_state = 'migration_quarantine' AND client_id IS NULL AND location_id IS NULL)",
            name="ck_approval_requests_scope_state",
        ),
        Index("ix_approval_requests_scope", "client_id", "location_id", "created_at"),
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
    scope_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="active")
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
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
        ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name="fk_approval_grants_client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name="fk_approval_grants_location_client",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_state = 'active' AND client_id IS NOT NULL) OR "
            "(scope_state = 'migration_quarantine' AND client_id IS NULL AND location_id IS NULL)",
            name="ck_approval_grants_scope_state",
        ),
        Index("ix_approval_grants_scope", "client_id", "location_id", "created_at"),
        UniqueConstraint("approval_request_id", name="uq_approval_grants_request_id"),
        CheckConstraint(
            "status IN ('approved', 'expired', 'revoked')",
            name="ck_approval_grants_status",
        ),
    )


class ResponseAction(Base):
    __tablename__ = "response_actions"

    response_action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("endpoints.endpoint_id", ondelete="CASCADE"), nullable=False
    )
    approval_grant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("approval_grants.approval_grant_id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    troubleshooting_scope: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(4096), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    lease_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    leased_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_summary: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "action IN ("
            "'collect_security_context', 'collect_remediation_evidence', 'inspect_control', "
            "'apply_control', 'rollback_control', 'request_elevated_troubleshooting'"
            ")",
            name="ck_response_actions_action",
        ),
        CheckConstraint(
            "status IN ('queued', 'leased', 'succeeded', 'failed', 'cancelled')",
            name="ck_response_actions_status",
        ),
        UniqueConstraint("endpoint_id", "idempotency_key", name="uq_response_actions_endpoint_idempotency"),
    )
