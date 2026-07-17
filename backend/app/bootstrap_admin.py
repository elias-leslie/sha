from __future__ import annotations

from urllib.parse import urlsplit

from sqlalchemy import select, update

from app.authorization import record_audit_event
from app.db import DatabaseStore
from app.models import OidcIdentity, Role, User, UserRoleBinding
from app.utils import generate_prefixed_id, normalize_required_string, to_utc_z, utc_now


def bootstrap_global_admin(
    store: DatabaseStore,
    *,
    issuer: str,
    subject: str,
    display_name: str | None = None,
) -> tuple[User, OidcIdentity, UserRoleBinding]:
    if not issuer or issuer != issuer.strip():
        raise ValueError("issuer must be non-empty and must not contain surrounding whitespace")
    normalized_issuer = issuer
    parsed_issuer = urlsplit(normalized_issuer)
    if (
        parsed_issuer.scheme != "https"
        or not parsed_issuer.netloc
        or parsed_issuer.username
        or parsed_issuer.password
        or parsed_issuer.query
        or parsed_issuer.fragment
    ):
        raise ValueError("issuer must be an absolute HTTPS URL without user information or query")
    if not subject:
        raise ValueError("subject must be non-empty")
    normalized_subject = subject
    if len(normalized_issuer) > 2048 or len(normalized_subject) > 255:
        raise ValueError("issuer or subject exceeds the supported OIDC identifier length")
    normalized_name = (
        normalize_required_string(display_name, "display_name")
        if display_name is not None
        else normalized_subject
    )
    if len(normalized_name) > 255:
        raise ValueError("display_name must not exceed 255 characters")

    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            admin_role = session.scalar(
                select(Role).where(Role.key == "admin").with_for_update()
            )
            if admin_role is None:
                raise RuntimeError("system Admin role is missing; migrate the database first")
            # A no-op write also serializes concurrent SQLite bootstrap attempts,
            # where SELECT FOR UPDATE is not available.
            session.execute(
                update(Role)
                .where(Role.role_id == admin_role.role_id)
                .values(updated_at=Role.updated_at)
            )
            existing_admin = session.scalar(
                select(UserRoleBinding)
                .where(
                    UserRoleBinding.role_id == admin_role.role_id,
                    UserRoleBinding.scope_type == "global",
                    UserRoleBinding.revoked_at.is_(None),
                )
                .limit(1)
            )
            if existing_admin is not None:
                raise RuntimeError("an active global Admin binding already exists")

            identity = session.scalar(
                select(OidcIdentity).where(
                    OidcIdentity.issuer == normalized_issuer,
                    OidcIdentity.subject == normalized_subject,
                )
            )
            if identity is None:
                user = User(
                    user_id=generate_prefixed_id("usr"),
                    status="active",
                    display_name=normalized_name,
                    email_snapshot=None,
                    last_login_at=None,
                    disabled_at=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(user)
                session.flush()
                identity = OidcIdentity(
                    identity_id=generate_prefixed_id("oidc"),
                    user_id=user.user_id,
                    issuer=normalized_issuer,
                    subject=normalized_subject,
                    display_name_snapshot=normalized_name,
                    email_snapshot=None,
                    created_at=now,
                    updated_at=now,
                    last_seen_at=None,
                )
                session.add(identity)
            else:
                user = session.get(User, identity.user_id)
                if user is None:
                    raise RuntimeError("OIDC identity has no user")
                if user.status == "disabled":
                    raise RuntimeError("refusing to bootstrap a disabled user")
                user.status = "active"
                user.display_name = normalized_name
                user.disabled_at = None
                user.updated_at = now
                identity.display_name_snapshot = normalized_name
                identity.updated_at = now

            binding = UserRoleBinding(
                binding_id=generate_prefixed_id("urb"),
                user_id=user.user_id,
                role_id=admin_role.role_id,
                scope_type="global",
                client_id=None,
                location_id=None,
                created_by="bootstrap:local-cli",
                created_at=now,
                revoked_at=None,
            )
            session.add(binding)
            record_audit_event(
                session,
                event_type="global_admin_bootstrapped",
                actor="bootstrap:local-cli",
                auth_method="local_cli",
                target_type="user",
                target_id=user.user_id,
                metadata={"issuer": normalized_issuer, "subject": normalized_subject},
                created_at=now,
            )
            session.flush()
            return user, identity, binding
