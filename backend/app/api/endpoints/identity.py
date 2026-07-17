from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import Principal
from app.authorization import record_audit_event, require_global_permission, require_permission
from app.db import DatabaseStore, get_store
from app.models import (
    BrowserSession,
    Client,
    Location,
    OidcIdentity,
    Role,
    RolePermission,
    User,
    UserRoleBinding,
)
from app.schemas.contracts import RoleBindingCreateRequest, UserStatusUpdateRequest
from app.utils import generate_prefixed_id, normalize_required_string, to_utc_z, utc_now

router = APIRouter(prefix="/api", tags=["identity"])


def _binding_payload(binding: UserRoleBinding, role_key: str) -> dict[str, object]:
    return {
        "binding_id": binding.binding_id,
        "user_id": binding.user_id,
        "role_key": role_key,
        "scope_type": binding.scope_type,
        "client_id": binding.client_id,
        "location_id": binding.location_id,
        "created_by": binding.created_by,
        "created_at": binding.created_at,
        "revoked_at": binding.revoked_at,
    }


@router.get("/users")
def list_users(
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("identity.manage")),
) -> dict[str, list[dict[str, object]]]:
    require_global_permission(principal, "identity.manage")
    with store.session() as session:
        users = session.scalars(select(User).order_by(User.created_at.asc(), User.user_id.asc())).all()
        identities = session.scalars(
            select(OidcIdentity).order_by(OidcIdentity.created_at.asc(), OidcIdentity.identity_id.asc())
        ).all()
        identity_by_user: dict[str, list[OidcIdentity]] = {}
        for identity in identities:
            identity_by_user.setdefault(identity.user_id, []).append(identity)
        binding_rows = session.execute(
            select(UserRoleBinding, Role.key)
            .join(Role, Role.role_id == UserRoleBinding.role_id)
            .order_by(UserRoleBinding.created_at.asc(), UserRoleBinding.binding_id.asc())
        ).all()
        bindings_by_user: dict[str, list[dict[str, object]]] = {}
        for binding, role_key in binding_rows:
            bindings_by_user.setdefault(binding.user_id, []).append(
                _binding_payload(binding, role_key)
            )
        return {
            "items": [
                {
                    "user_id": user.user_id,
                    "status": user.status,
                    "display_name": user.display_name,
                    "email_snapshot": user.email_snapshot,
                    "last_login_at": user.last_login_at,
                    "disabled_at": user.disabled_at,
                    "created_at": user.created_at,
                    "updated_at": user.updated_at,
                    "identities": [
                        {
                            "identity_id": identity.identity_id,
                            "issuer": identity.issuer,
                            "subject": identity.subject,
                            "display_name_snapshot": identity.display_name_snapshot,
                            "email_snapshot": identity.email_snapshot,
                            "last_seen_at": identity.last_seen_at,
                        }
                        for identity in identity_by_user.get(user.user_id, [])
                    ],
                    "bindings": bindings_by_user.get(user.user_id, []),
                }
                for user in users
            ]
        }


@router.patch("/users/{user_id}")
def update_user_status(
    user_id: str,
    payload: UserStatusUpdateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("identity.manage")),
) -> dict[str, object]:
    require_global_permission(principal, "identity.manage")
    normalized_user_id = normalize_required_string(user_id, "user_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            user = session.get(User, normalized_user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="user not found")
            previous_status = user.status
            user.status = payload.status
            user.disabled_at = now if payload.status == "disabled" else None
            user.updated_at = now
            if payload.status == "disabled":
                session.execute(
                    update(BrowserSession)
                    .where(
                        BrowserSession.user_id == user.user_id,
                        BrowserSession.revoked_at.is_(None),
                    )
                    .values(revoked_at=now, updated_at=now)
                )
            record_audit_event(
                session,
                event_type="user_status_changed",
                principal=principal,
                target_type="user",
                target_id=user.user_id,
                metadata={"from": previous_status, "to": user.status},
                created_at=now,
            )
            return {
                "user_id": user.user_id,
                "status": user.status,
                "display_name": user.display_name,
                "email_snapshot": user.email_snapshot,
                "updated_at": user.updated_at,
            }


@router.get("/roles")
def list_roles(
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("identity.manage")),
) -> dict[str, list[dict[str, object]]]:
    require_global_permission(principal, "identity.manage")
    with store.session() as session:
        roles = session.scalars(select(Role).order_by(Role.name.asc(), Role.role_id.asc())).all()
        permission_rows = session.execute(
            select(RolePermission.role_id, RolePermission.permission).order_by(
                RolePermission.role_id.asc(),
                RolePermission.permission.asc(),
            )
        ).all()
        permissions: dict[str, list[str]] = {}
        for role_id, permission in permission_rows:
            permissions.setdefault(role_id, []).append(permission)
        return {
            "items": [
                {
                    "role_id": role.role_id,
                    "key": role.key,
                    "name": role.name,
                    "is_system": role.is_system,
                    "permissions": permissions.get(role.role_id, []),
                }
                for role in roles
            ]
        }


def _validate_binding_scope(
    session: Session,
    payload: RoleBindingCreateRequest,
) -> tuple[str | None, str | None]:
    client_id = (
        normalize_required_string(payload.client_id, "client_id")
        if payload.client_id is not None
        else None
    )
    location_id = (
        normalize_required_string(payload.location_id, "location_id")
        if payload.location_id is not None
        else None
    )
    if payload.scope_type == "global":
        if client_id is not None or location_id is not None:
            raise HTTPException(status_code=422, detail="global binding must not include client or location")
        return None, None
    if client_id is None or session.get(Client, client_id) is None:
        raise HTTPException(status_code=404, detail="scope not found")
    if payload.scope_type == "client":
        if location_id is not None:
            raise HTTPException(status_code=422, detail="client binding must not include location")
        return client_id, None
    if location_id is None:
        raise HTTPException(status_code=422, detail="location binding requires location")
    location = session.scalar(
        select(Location).where(
            Location.location_id == location_id,
            Location.client_id == client_id,
        )
    )
    if location is None:
        raise HTTPException(status_code=404, detail="scope not found")
    return client_id, location_id


@router.post(
    "/users/{user_id}/role-bindings",
    status_code=status.HTTP_201_CREATED,
)
def create_role_binding(
    user_id: str,
    payload: RoleBindingCreateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("identity.manage")),
) -> dict[str, object]:
    require_global_permission(principal, "identity.manage")
    normalized_user_id = normalize_required_string(user_id, "user_id")
    role_key = normalize_required_string(payload.role_key, "role_key").lower()
    now = to_utc_z(utc_now())
    try:
        with store.session() as session:
            with session.begin():
                user = session.get(User, normalized_user_id)
                if user is None:
                    raise HTTPException(status_code=404, detail="user not found")
                role = session.scalar(select(Role).where(Role.key == role_key))
                if role is None:
                    raise HTTPException(status_code=404, detail="role not found")
                client_id, location_id = _validate_binding_scope(session, payload)
                binding = UserRoleBinding(
                    binding_id=generate_prefixed_id("urb"),
                    user_id=user.user_id,
                    role_id=role.role_id,
                    scope_type=payload.scope_type,
                    client_id=client_id,
                    location_id=location_id,
                    created_by=principal.audit_actor,
                    created_at=now,
                    revoked_at=None,
                )
                session.add(binding)
                session.flush()
                record_audit_event(
                    session,
                    event_type="role_binding_created",
                    principal=principal,
                    client_id=client_id,
                    location_id=location_id,
                    target_type="role_binding",
                    target_id=binding.binding_id,
                    metadata={"user_id": user.user_id, "role": role.key, "scope_type": payload.scope_type},
                    created_at=now,
                )
                return _binding_payload(binding, role.key)
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="active role binding already exists") from exc


@router.post("/role-bindings/{binding_id}/revoke")
def revoke_role_binding(
    binding_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("identity.manage")),
) -> dict[str, object]:
    require_global_permission(principal, "identity.manage")
    normalized_binding_id = normalize_required_string(binding_id, "binding_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            row = session.execute(
                select(UserRoleBinding, Role.key)
                .join(Role, Role.role_id == UserRoleBinding.role_id)
                .where(UserRoleBinding.binding_id == normalized_binding_id)
            ).one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="role binding not found")
            binding, role_key = row
            if binding.revoked_at is None:
                binding.revoked_at = now
                session.execute(
                    update(BrowserSession)
                    .where(
                        BrowserSession.user_id == binding.user_id,
                        BrowserSession.revoked_at.is_(None),
                    )
                    .values(revoked_at=now, updated_at=now)
                )
                record_audit_event(
                    session,
                    event_type="role_binding_revoked",
                    principal=principal,
                    client_id=binding.client_id,
                    location_id=binding.location_id,
                    target_type="role_binding",
                    target_id=binding.binding_id,
                    metadata={"user_id": binding.user_id, "role": role_key},
                    created_at=now,
                )
            return _binding_payload(binding, role_key)
