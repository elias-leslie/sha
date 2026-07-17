from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from typing import TYPE_CHECKING, Any, Callable, Literal, cast, get_args

from fastapi import HTTPException, Request
from sqlalchemy import ColumnElement, false, or_, select, true
from sqlalchemy.orm import Session

from app.models import AuditEvent, Role, RolePermission, UserRoleBinding
from app.utils import generate_prefixed_id, to_utc_z, utc_now

if TYPE_CHECKING:
    from app.auth import Principal
    from fastapi import FastAPI


SPECIAL_ROUTE_POLICIES: dict[tuple[str, str], str] = {
    ("GET", "/api/auth/oidc/login"): "public:oidc_login",
    ("GET", "/api/auth/oidc/callback"): "public:oidc_callback",
    ("GET", "/api/auth/session"): "self:session",
    ("POST", "/api/auth/logout"): "self:logout",
    ("POST", "/api/auth/logout-all"): "self:logout_all",
    ("POST", "/api/endpoints/enroll"): "agent:legacy_enroll",
    ("POST", "/api/endpoints/{endpoint_id}/heartbeat"): "agent:heartbeat",
    ("POST", "/api/posture-snapshots"): "agent:posture",
    (
        "POST",
        "/api/endpoints/{endpoint_id}/response-actions/claim",
    ): "agent:action_claim",
    ("POST", "/api/response-actions/{response_action_id}/result"): "agent:action_result",
    ("POST", "/api/agent/bootstrap"): "enrollment:bootstrap",
    ("GET", "/api/agent/me"): "device:self",
    ("POST", "/api/agent/credentials/rotate"): "device:credential_rotate",
}


Permission = Literal[
    "action.approve",
    "action.request",
    "approval.decide",
    "approval.grant",
    "approval.read",
    "approval.request",
    "audit.read",
    "audit.export",
    "bulk_action.execute",
    "catalog.read",
    "command.execute",
    "compliance.exception",
    "compliance_evidence.export",
    "containment.execute",
    "containment.release",
    "credential.admin",
    "device_credential.manage",
    "dynamic_group.manage",
    "dynamic_group.read",
    "endpoint.approve",
    "endpoint.read",
    "evidence.collect",
    "evidence.read",
    "enrollment.admin",
    "enrollment.manage",
    "enrollment.read",
    "hierarchy.manage",
    "hierarchy.read",
    "identity.manage",
    "installer_artifact.download",
    "installer_profile.manage",
    "installer_profile.read",
    "incident.manage",
    "inventory.read",
    "inventory.refresh",
    "process.mutate",
    "reboot.execute",
    "response_action.create",
    "response_action.read",
    "saved_view.manage",
    "saved_view.read",
    "schedule.approve",
    "schedule.create",
    "service.mutate",
    "tag.manage",
    "tag.read",
    "terminal.open",
]

ALL_PERMISSIONS: frozenset[str] = frozenset(get_args(Permission))
READONLY_PERMISSIONS: frozenset[str] = frozenset(
    {
        "approval.read",
        "audit.read",
        "catalog.read",
        "compliance_evidence.export",
        "dynamic_group.read",
        "endpoint.read",
        "evidence.read",
        "hierarchy.read",
        "inventory.read",
        "installer_profile.read",
        "response_action.read",
        "saved_view.read",
        "tag.read",
    }
)
LEGACY_OPERATOR_PERMISSIONS: frozenset[str] = frozenset(
    {
        "approval.decide",
        "approval.grant",
        "approval.read",
        "approval.request",
        "audit.read",
        "catalog.read",
        "compliance_evidence.export",
        "device_credential.manage",
        "dynamic_group.manage",
        "dynamic_group.read",
        "endpoint.approve",
        "endpoint.read",
        "enrollment.manage",
        "enrollment.read",
        "hierarchy.manage",
        "hierarchy.read",
        "installer_artifact.download",
        "installer_profile.manage",
        "installer_profile.read",
        "response_action.create",
        "response_action.read",
        "saved_view.manage",
        "saved_view.read",
        "tag.manage",
        "tag.read",
    }
)


@dataclass(frozen=True)
class ScopeGrant:
    binding_id: str
    role_key: str
    scope_type: Literal["global", "client", "location"]
    client_id: str | None
    location_id: str | None
    permissions: frozenset[str]

    def permits(self, permission: str, client_id: str | None, location_id: str | None) -> bool:
        if permission not in self.permissions:
            return False
        if self.scope_type == "global":
            return True
        if client_id is None or self.client_id != client_id:
            return False
        if self.scope_type == "client":
            return True
        return location_id is not None and self.location_id == location_id


def synthetic_global_grant(role_key: str, permissions: frozenset[str]) -> ScopeGrant:
    return ScopeGrant(
        binding_id=f"synthetic:{role_key}",
        role_key=role_key,
        scope_type="global",
        client_id=None,
        location_id=None,
        permissions=permissions,
    )


def load_user_grants(session: Session, user_id: str) -> tuple[ScopeGrant, ...]:
    rows = session.execute(
        select(UserRoleBinding, Role.key, RolePermission.permission)
        .join(Role, Role.role_id == UserRoleBinding.role_id)
        .join(RolePermission, RolePermission.role_id == Role.role_id)
        .where(
            UserRoleBinding.user_id == user_id,
            UserRoleBinding.revoked_at.is_(None),
        )
        .order_by(UserRoleBinding.binding_id.asc(), RolePermission.permission.asc())
    ).all()
    permissions_by_binding: dict[str, set[str]] = defaultdict(set)
    binding_rows: dict[str, tuple[UserRoleBinding, str]] = {}
    for binding, role_key, permission in rows:
        permissions_by_binding[binding.binding_id].add(permission)
        binding_rows[binding.binding_id] = (binding, role_key)
    grants: list[ScopeGrant] = []
    for binding_id in sorted(binding_rows):
        binding, role_key = binding_rows[binding_id]
        grants.append(
            ScopeGrant(
                binding_id=binding.binding_id,
                role_key=role_key,
                scope_type=cast(
                    Literal["global", "client", "location"],
                    binding.scope_type,
                ),
                client_id=binding.client_id,
                location_id=binding.location_id,
                permissions=frozenset(permissions_by_binding[binding_id]),
            )
        )
    return tuple(grants)


def has_permission(principal: Principal, permission: str) -> bool:
    return any(permission in grant.permissions for grant in principal.grants)


def permits_scope(
    principal: Principal,
    permission: str,
    *,
    client_id: str | None,
    location_id: str | None,
) -> bool:
    return any(
        grant.permits(permission, client_id, location_id)
        for grant in principal.grants
    )


def require_permission(permission: Permission) -> Callable[[Request], Principal]:
    def dependency(request: Request) -> Principal:
        from app.auth import current_principal

        principal = current_principal(request)
        if principal.role in {"agent", "enrollment"} or not has_permission(principal, permission):
            raise HTTPException(status_code=403, detail="permission denied")
        return principal

    dependency.__name__ = f"require_{permission.replace('.', '_')}"
    setattr(dependency, "sha_permission", permission)
    return dependency


def classify_api_routes(app: FastAPI) -> dict[tuple[str, str], str]:
    from fastapi.routing import APIRoute

    classifications: dict[tuple[str, str], str] = {}
    actual_routes: set[tuple[str, str]] = set()
    errors: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/"):
            continue
        for method in sorted(route.methods or ()):
            if method in {"HEAD", "OPTIONS"}:
                continue
            key = (method, route.path)
            actual_routes.add(key)
            permission_dependencies = {
                str(permission)
                for dependency in route.dependant.dependencies
                if (permission := getattr(dependency.call, "sha_permission", None)) is not None
            }
            special_policy = SPECIAL_ROUTE_POLICIES.get(key)
            if special_policy is not None:
                if permission_dependencies:
                    errors.append(f"{method} {route.path} has conflicting special and permission policy")
                classifications[key] = special_policy
                continue
            if len(permission_dependencies) != 1:
                errors.append(
                    f"{method} {route.path} requires exactly one human permission dependency"
                )
                continue
            classifications[key] = f"human:{next(iter(permission_dependencies))}"

    stale_special_routes = set(SPECIAL_ROUTE_POLICIES) - actual_routes
    if stale_special_routes:
        errors.extend(
            f"stale special route policy for {method} {path}"
            for method, path in sorted(stale_special_routes)
        )
    if errors:
        raise RuntimeError("invalid API route authorization policy: " + "; ".join(errors))
    return classifications


def require_global_permission(principal: Principal, permission: Permission) -> None:
    if not any(
        grant.scope_type == "global" and permission in grant.permissions
        for grant in principal.grants
    ):
        raise HTTPException(status_code=403, detail="global permission is required")


def require_scope(
    principal: Principal,
    permission: Permission,
    *,
    client_id: str,
    location_id: str | None,
    conceal: bool = True,
) -> None:
    if permits_scope(
        principal,
        permission,
        client_id=client_id,
        location_id=location_id,
    ):
        return
    if conceal:
        raise HTTPException(status_code=404, detail="resource not found")
    raise HTTPException(status_code=403, detail="permission denied for scope")


def scope_clause(
    principal: Principal,
    permission: Permission,
    client_column: Any,
    location_column: Any,
) -> ColumnElement[bool]:
    clauses: list[ColumnElement[bool]] = []
    for grant in principal.grants:
        if permission not in grant.permissions:
            continue
        if grant.scope_type == "global":
            return true()
        if grant.scope_type == "client" and grant.client_id is not None:
            clauses.append(client_column == grant.client_id)
        elif (
            grant.scope_type == "location"
            and grant.client_id is not None
            and grant.location_id is not None
        ):
            clauses.append(
                (client_column == grant.client_id)
                & (location_column == grant.location_id)
            )
    return or_(*clauses) if clauses else false()


def client_scope_clause(
    principal: Principal,
    permission: Permission,
    client_column: Any,
) -> ColumnElement[bool]:
    client_ids: set[str] = set()
    for grant in principal.grants:
        if permission not in grant.permissions:
            continue
        if grant.scope_type == "global":
            return true()
        if grant.client_id is not None:
            client_ids.add(grant.client_id)
    return client_column.in_(sorted(client_ids)) if client_ids else false()


def _redact_metadata(value: object) -> object:
    if isinstance(value, dict):
        output: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if any(
                marker in lowered
                for marker in ("token", "secret", "password", "credential", "verifier", "code")
            ):
                output[key] = "[REDACTED]"
            else:
                output[key] = _redact_metadata(item)
        return output
    if isinstance(value, list):
        return [_redact_metadata(item) for item in value[:100]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def record_audit_event(
    session: Session,
    *,
    event_type: str,
    principal: Principal | None = None,
    actor: str | None = None,
    auth_method: str | None = None,
    outcome: Literal["success", "denied", "failure"] = "success",
    client_id: str | None = None,
    location_id: str | None = None,
    endpoint_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    request_id: str | None = None,
    metadata: dict[str, object] | None = None,
    created_at: str | None = None,
) -> AuditEvent:
    safe_metadata = _redact_metadata(metadata or {})
    serialized = json.dumps(safe_metadata, separators=(",", ":"), sort_keys=True)
    if len(serialized.encode("utf-8")) > 8192:
        safe_metadata = {"truncated": True}
    event = AuditEvent(
        audit_event_id=generate_prefixed_id("aud"),
        event_type=event_type,
        outcome=outcome,
        actor=actor or (principal.audit_actor if principal is not None else "system"),
        user_id=principal.user_id if principal is not None else None,
        auth_method=auth_method or (principal.auth_method if principal is not None else "system"),
        client_id=client_id,
        location_id=location_id,
        endpoint_id=endpoint_id,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        metadata_json=safe_metadata,
        created_at=created_at or to_utc_z(utc_now()),
    )
    session.add(event)
    return event
