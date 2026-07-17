from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import ColumnElement, and_, false, or_, select, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import Principal
from app.authorization import (
    Permission,
    has_permission,
    record_audit_event,
    require_global_permission,
    require_permission,
    require_scope,
    scope_clause,
)
from app.db import DatabaseStore, get_store
from app.hierarchy import load_scope, validate_scope_filter
from app.models import (
    Client,
    DynamicGroup,
    Endpoint,
    EndpointTagAssignment,
    SavedView,
    SavedViewVersion,
    Tag,
)
from app.schemas.contracts import (
    DynamicGroupCreateRequest,
    DynamicGroupListResponse,
    DynamicGroupPreviewResponse,
    DynamicGroupResponse,
    EndpointFilterDefinition,
    EndpointFilterOperator,
    EndpointFilterRule,
    EndpointTagAssignmentRequest,
    EndpointTagListResponse,
    EndpointTagResponse,
    SavedViewCreateRequest,
    SavedViewListResponse,
    SavedViewResponse,
    SavedViewUpdateRequest,
    TagCreateRequest,
    TagListResponse,
    TagResponse,
)
from app.utils import generate_prefixed_id, normalize_required_string, to_utc_z, utc_now

router = APIRouter(tags=["fleet-metadata"])

MAX_GROUP_EVALUATION_ENDPOINTS = 10_000


def _scope_key(scope_type: str, client_id: str | None, location_id: str | None) -> str:
    if scope_type == "global":
        return "global"
    if scope_type == "client" and client_id is not None:
        return f"client:{client_id}"
    if scope_type == "location" and client_id is not None and location_id is not None:
        return f"location:{client_id}:{location_id}"
    raise HTTPException(status_code=422, detail="invalid fleet metadata scope")


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _require_requested_scope(
    session: Session,
    principal: Principal,
    permission: Permission,
    *,
    scope_type: str,
    client_id: str | None,
    location_id: str | None,
) -> str:
    if scope_type == "global":
        require_global_permission(principal, permission)
        return "global"
    normalized_client_id, normalized_location_id = validate_scope_filter(
        session,
        client_id=client_id,
        location_id=location_id,
    )
    if normalized_client_id is None:
        raise HTTPException(status_code=422, detail="client scope is required")
    if scope_type == "client":
        client = session.get(Client, normalized_client_id)
        if client is None:
            raise HTTPException(status_code=404, detail="client not found")
        if client.state == "archived":
            raise HTTPException(status_code=409, detail="client must be active")
    else:
        if normalized_location_id is None:
            raise HTTPException(status_code=422, detail="location scope is required")
        load_scope(session, normalized_client_id, normalized_location_id)
    require_scope(
        principal,
        permission,
        client_id=normalized_client_id,
        location_id=normalized_location_id,
    )
    return _scope_key(scope_type, normalized_client_id, normalized_location_id)


def _resource_scope_clause(
    principal: Principal,
    permission: Permission,
    scope_type_column: Any,
    client_column: Any,
    location_column: Any,
) -> ColumnElement[bool]:
    clauses: list[ColumnElement[bool]] = []
    for grant in principal.grants:
        if permission not in grant.permissions:
            continue
        if grant.scope_type == "global":
            return true()
        if grant.client_id is None:
            continue
        clauses.append(
            (scope_type_column == "client") & (client_column == grant.client_id)
        )
        if grant.scope_type == "client":
            clauses.append(
                (scope_type_column == "location") & (client_column == grant.client_id)
            )
        elif grant.location_id is not None:
            clauses.append(
                (scope_type_column == "location")
                & (client_column == grant.client_id)
                & (location_column == grant.location_id)
            )
    return or_(*clauses) if clauses else false()


def _selected_resource_scope_clause(
    scope_type_column: Any,
    client_column: Any,
    location_column: Any,
    *,
    client_id: str | None,
    location_id: str | None,
) -> ColumnElement[bool]:
    if client_id is None:
        return true()
    clauses: list[ColumnElement[bool]] = [
        (scope_type_column == "client") & (client_column == client_id)
    ]
    location_clause: ColumnElement[bool] = (
        (scope_type_column == "location") & (client_column == client_id)
    )
    if location_id is not None:
        location_clause = location_clause & (location_column == location_id)
    clauses.append(location_clause)
    return or_(*clauses)


def _owner_clause(principal: Principal, model: type[SavedView]) -> ColumnElement[bool]:
    clauses: list[ColumnElement[bool]] = [model.owner_actor == principal.subject]
    if principal.user_id is not None:
        clauses.append(model.owner_user_id == principal.user_id)
    return or_(*clauses)


def _is_owner(principal: Principal, resource: SavedView | DynamicGroup) -> bool:
    return (
        resource.owner_actor == principal.subject
        or (
            principal.user_id is not None
            and resource.owner_user_id is not None
            and resource.owner_user_id == principal.user_id
        )
    )


def _tag_payload(tag: Tag) -> dict[str, object]:
    return {
        "tag_id": tag.tag_id,
        "name": tag.name,
        "description": tag.description,
        "scope_type": tag.scope_type,
        "client_id": tag.client_id,
        "location_id": tag.location_id,
        "created_by": tag.created_by,
        "created_at": tag.created_at,
        "updated_at": tag.updated_at,
    }


def _canonical_filter(
    filter_definition: EndpointFilterDefinition,
) -> tuple[dict[str, object], str]:
    payload = filter_definition.model_dump(mode="json", by_alias=True)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return payload, hashlib.sha256(encoded).hexdigest()


def _current_view_version(session: Session, saved_view: SavedView) -> SavedViewVersion:
    version = session.get(
        SavedViewVersion,
        (saved_view.saved_view_id, saved_view.current_version),
    )
    if version is None:
        raise RuntimeError("saved view current version is missing")
    return version


def _saved_view_payload(session: Session, saved_view: SavedView) -> dict[str, object]:
    version = _current_view_version(session, saved_view)
    return {
        "saved_view_id": saved_view.saved_view_id,
        "name": saved_view.name,
        "description": saved_view.description,
        "visibility": saved_view.visibility,
        "scope_type": saved_view.scope_type,
        "client_id": saved_view.client_id,
        "location_id": saved_view.location_id,
        "owner_user_id": saved_view.owner_user_id,
        "owner_actor": saved_view.owner_actor,
        "current_version": saved_view.current_version,
        "current_filter": EndpointFilterDefinition.model_validate(version.filter_json).model_dump(
            mode="json", by_alias=True
        ),
        "content_hash": version.content_hash,
        "created_at": saved_view.created_at,
        "updated_at": saved_view.updated_at,
    }


def _dynamic_group_payload(session: Session, group: DynamicGroup) -> dict[str, object]:
    saved_view = session.get(SavedView, group.saved_view_id)
    if saved_view is None:
        raise RuntimeError("dynamic group saved view is missing")
    version = _current_view_version(session, saved_view)
    return {
        "dynamic_group_id": group.dynamic_group_id,
        "name": group.name,
        "description": group.description,
        "scope_type": group.scope_type,
        "client_id": group.client_id,
        "location_id": group.location_id,
        "saved_view_id": group.saved_view_id,
        "saved_view_version": saved_view.current_version,
        "filter_hash": version.content_hash,
        "owner_user_id": group.owner_user_id,
        "owner_actor": group.owner_actor,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
    }


def _load_endpoint_for_metadata(
    session: Session,
    principal: Principal,
    permission: Permission,
    endpoint_id: str,
) -> Endpoint:
    endpoint = session.scalar(
        select(Endpoint).where(
            Endpoint.endpoint_id == endpoint_id,
            scope_clause(
                principal,
                permission,
                Endpoint.client_id,
                Endpoint.location_id,
            ),
        )
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="endpoint not found")
    return endpoint


@router.get("/api/tags", response_model=TagListResponse)
def list_tags(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("tag.read")),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        if normalized_client_id is not None:
            require_scope(
                principal,
                "tag.read",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )
        tags = session.scalars(
            select(Tag)
            .where(
                _resource_scope_clause(
                    principal,
                    "tag.read",
                    Tag.scope_type,
                    Tag.client_id,
                    Tag.location_id,
                ),
                _selected_resource_scope_clause(
                    Tag.scope_type,
                    Tag.client_id,
                    Tag.location_id,
                    client_id=normalized_client_id,
                    location_id=normalized_location_id,
                ),
            )
            .order_by(Tag.name_normalized.asc(), Tag.tag_id.asc())
        ).all()
        return {"items": [_tag_payload(tag) for tag in tags]}


@router.post(
    "/api/tags",
    status_code=status.HTTP_201_CREATED,
    response_model=TagResponse,
)
def create_tag(
    payload: TagCreateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("tag.manage")),
) -> dict[str, object]:
    name = normalize_required_string(payload.name, "name")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            scope_type = payload.scope_type.value
            scope_key = _require_requested_scope(
                session,
                principal,
                "tag.manage",
                scope_type=scope_type,
                client_id=payload.client_id,
                location_id=payload.location_id,
            )
            tag = Tag(
                tag_id=generate_prefixed_id("tag"),
                name=name,
                name_normalized=name.casefold(),
                description=_optional_text(payload.description),
                scope_type=scope_type,
                scope_key=scope_key,
                client_id=payload.client_id,
                location_id=payload.location_id,
                created_by=principal.audit_actor,
                created_at=now,
                updated_at=now,
            )
            session.add(tag)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(status_code=409, detail="tag name already exists in scope") from exc
            record_audit_event(
                session,
                event_type="tag_created",
                principal=principal,
                client_id=tag.client_id,
                location_id=tag.location_id,
                target_type="tag",
                target_id=tag.tag_id,
                metadata={"scope_type": tag.scope_type, "name": tag.name},
                created_at=now,
            )
            session.flush()
            return _tag_payload(tag)


@router.get(
    "/api/endpoints/{endpoint_id}/tags",
    response_model=EndpointTagListResponse,
)
def list_endpoint_tags(
    endpoint_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("tag.read")),
) -> dict[str, list[dict[str, object]]]:
    normalized_endpoint_id = normalize_required_string(endpoint_id, "endpoint_id")
    with store.session() as session:
        endpoint = _load_endpoint_for_metadata(
            session,
            principal,
            "tag.read",
            normalized_endpoint_id,
        )
        rows = session.execute(
            select(Tag, EndpointTagAssignment)
            .join(EndpointTagAssignment, EndpointTagAssignment.tag_id == Tag.tag_id)
            .where(
                EndpointTagAssignment.endpoint_id == endpoint.endpoint_id,
                EndpointTagAssignment.client_id == endpoint.client_id,
                EndpointTagAssignment.location_id == endpoint.location_id,
            )
            .order_by(Tag.name_normalized.asc(), Tag.tag_id.asc())
        ).all()
        return {
            "items": [
                {
                    **_tag_payload(tag),
                    "assigned_by": assignment.assigned_by,
                    "assigned_at": assignment.assigned_at,
                }
                for tag, assignment in rows
            ]
        }


@router.post(
    "/api/endpoints/{endpoint_id}/tags",
    status_code=status.HTTP_201_CREATED,
    response_model=EndpointTagResponse,
)
def assign_endpoint_tag(
    endpoint_id: str,
    payload: EndpointTagAssignmentRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("tag.manage")),
) -> dict[str, object]:
    normalized_endpoint_id = normalize_required_string(endpoint_id, "endpoint_id")
    normalized_tag_id = normalize_required_string(payload.tag_id, "tag_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            endpoint = _load_endpoint_for_metadata(
                session,
                principal,
                "tag.manage",
                normalized_endpoint_id,
            )
            tag = session.scalar(
                select(Tag).where(
                    Tag.tag_id == normalized_tag_id,
                    _resource_scope_clause(
                        principal,
                        "tag.manage",
                        Tag.scope_type,
                        Tag.client_id,
                        Tag.location_id,
                    ),
                    or_(
                        Tag.scope_key == "global",
                        Tag.scope_key == f"client:{endpoint.client_id}",
                        Tag.scope_key
                        == f"location:{endpoint.client_id}:{endpoint.location_id}",
                    ),
                )
            )
            if tag is None:
                raise HTTPException(status_code=404, detail="tag not found")
            assignment = session.get(
                EndpointTagAssignment,
                (endpoint.endpoint_id, tag.tag_id),
            )
            if assignment is None:
                assignment = EndpointTagAssignment(
                    endpoint_id=endpoint.endpoint_id,
                    tag_id=tag.tag_id,
                    client_id=endpoint.client_id,
                    location_id=endpoint.location_id,
                    tag_scope_key=tag.scope_key,
                    assigned_by=principal.audit_actor,
                    assigned_at=now,
                )
                session.add(assignment)
                session.flush()
                record_audit_event(
                    session,
                    event_type="endpoint_tag_assigned",
                    principal=principal,
                    client_id=endpoint.client_id,
                    location_id=endpoint.location_id,
                    endpoint_id=endpoint.endpoint_id,
                    target_type="tag",
                    target_id=tag.tag_id,
                    created_at=now,
                )
                session.flush()
            return {
                **_tag_payload(tag),
                "assigned_by": assignment.assigned_by,
                "assigned_at": assignment.assigned_at,
            }


@router.delete(
    "/api/endpoints/{endpoint_id}/tags/{tag_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_endpoint_tag(
    endpoint_id: str,
    tag_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("tag.manage")),
) -> None:
    normalized_endpoint_id = normalize_required_string(endpoint_id, "endpoint_id")
    normalized_tag_id = normalize_required_string(tag_id, "tag_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            endpoint = _load_endpoint_for_metadata(
                session,
                principal,
                "tag.manage",
                normalized_endpoint_id,
            )
            assignment = session.scalar(
                select(EndpointTagAssignment).where(
                    EndpointTagAssignment.endpoint_id == endpoint.endpoint_id,
                    EndpointTagAssignment.tag_id == normalized_tag_id,
                )
            )
            if assignment is None:
                raise HTTPException(status_code=404, detail="tag assignment not found")
            session.delete(assignment)
            record_audit_event(
                session,
                event_type="endpoint_tag_removed",
                principal=principal,
                client_id=endpoint.client_id,
                location_id=endpoint.location_id,
                endpoint_id=endpoint.endpoint_id,
                target_type="tag",
                target_id=normalized_tag_id,
                created_at=now,
            )


@router.get("/api/saved-views", response_model=SavedViewListResponse)
def list_saved_views(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("saved_view.read")),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        if normalized_client_id is not None:
            require_scope(
                principal,
                "saved_view.read",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )
        views = session.scalars(
            select(SavedView)
            .where(
                _resource_scope_clause(
                    principal,
                    "saved_view.read",
                    SavedView.scope_type,
                    SavedView.client_id,
                    SavedView.location_id,
                ),
                _selected_resource_scope_clause(
                    SavedView.scope_type,
                    SavedView.client_id,
                    SavedView.location_id,
                    client_id=normalized_client_id,
                    location_id=normalized_location_id,
                ),
                or_(SavedView.visibility == "shared", _owner_clause(principal, SavedView)),
            )
            .order_by(SavedView.name_normalized.asc(), SavedView.saved_view_id.asc())
        ).all()
        return {"items": [_saved_view_payload(session, view) for view in views]}


@router.post(
    "/api/saved-views",
    status_code=status.HTTP_201_CREATED,
    response_model=SavedViewResponse,
)
def create_saved_view(
    payload: SavedViewCreateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("saved_view.manage")),
) -> dict[str, object]:
    name = normalize_required_string(payload.name, "name")
    filter_json, content_hash = _canonical_filter(payload.filter)
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            scope_type = payload.scope_type.value
            scope_key = _require_requested_scope(
                session,
                principal,
                "saved_view.manage",
                scope_type=scope_type,
                client_id=payload.client_id,
                location_id=payload.location_id,
            )
            saved_view = SavedView(
                saved_view_id=generate_prefixed_id("view"),
                name=name,
                name_normalized=name.casefold(),
                description=_optional_text(payload.description),
                visibility=payload.visibility.value,
                scope_type=scope_type,
                scope_key=scope_key,
                client_id=payload.client_id,
                location_id=payload.location_id,
                owner_user_id=principal.user_id,
                owner_actor=principal.audit_actor,
                current_version=1,
                created_at=now,
                updated_at=now,
            )
            session.add(saved_view)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(
                    status_code=409,
                    detail="saved view name already exists in scope",
                ) from exc
            session.add(
                SavedViewVersion(
                    saved_view_id=saved_view.saved_view_id,
                    version=1,
                    filter_json=filter_json,
                    content_hash=content_hash,
                    created_by=principal.audit_actor,
                    created_at=now,
                )
            )
            session.flush()
            record_audit_event(
                session,
                event_type="saved_view_created",
                principal=principal,
                client_id=saved_view.client_id,
                location_id=saved_view.location_id,
                target_type="saved_view",
                target_id=saved_view.saved_view_id,
                metadata={"version": 1, "filter_hash": content_hash},
                created_at=now,
            )
            session.flush()
            return _saved_view_payload(session, saved_view)


@router.put(
    "/api/saved-views/{saved_view_id}",
    response_model=SavedViewResponse,
)
def update_saved_view(
    saved_view_id: str,
    payload: SavedViewUpdateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("saved_view.manage")),
) -> dict[str, object]:
    normalized_saved_view_id = normalize_required_string(saved_view_id, "saved_view_id")
    filter_json, content_hash = _canonical_filter(payload.filter)
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            saved_view = session.scalar(
                select(SavedView).where(
                    SavedView.saved_view_id == normalized_saved_view_id,
                    _resource_scope_clause(
                        principal,
                        "saved_view.manage",
                        SavedView.scope_type,
                        SavedView.client_id,
                        SavedView.location_id,
                    ),
                )
            )
            if saved_view is None or not _is_owner(principal, saved_view):
                raise HTTPException(status_code=404, detail="saved view not found")
            current_version = _current_view_version(session, saved_view)
            if current_version.content_hash == content_hash:
                return _saved_view_payload(session, saved_view)
            next_version = saved_view.current_version + 1
            session.add(
                SavedViewVersion(
                    saved_view_id=saved_view.saved_view_id,
                    version=next_version,
                    filter_json=filter_json,
                    content_hash=content_hash,
                    created_by=principal.audit_actor,
                    created_at=now,
                )
            )
            saved_view.current_version = next_version
            saved_view.updated_at = now
            session.flush()
            record_audit_event(
                session,
                event_type="saved_view_version_created",
                principal=principal,
                client_id=saved_view.client_id,
                location_id=saved_view.location_id,
                target_type="saved_view",
                target_id=saved_view.saved_view_id,
                metadata={"version": next_version, "filter_hash": content_hash},
                created_at=now,
            )
            session.flush()
            return _saved_view_payload(session, saved_view)


@router.get("/api/dynamic-groups", response_model=DynamicGroupListResponse)
def list_dynamic_groups(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("dynamic_group.read")),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        if normalized_client_id is not None:
            require_scope(
                principal,
                "dynamic_group.read",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )
        groups = session.scalars(
            select(DynamicGroup)
            .where(
                _resource_scope_clause(
                    principal,
                    "dynamic_group.read",
                    DynamicGroup.scope_type,
                    DynamicGroup.client_id,
                    DynamicGroup.location_id,
                ),
                _selected_resource_scope_clause(
                    DynamicGroup.scope_type,
                    DynamicGroup.client_id,
                    DynamicGroup.location_id,
                    client_id=normalized_client_id,
                    location_id=normalized_location_id,
                ),
            )
            .order_by(DynamicGroup.name_normalized.asc(), DynamicGroup.dynamic_group_id.asc())
        ).all()
        return {"items": [_dynamic_group_payload(session, group) for group in groups]}


@router.post(
    "/api/dynamic-groups",
    status_code=status.HTTP_201_CREATED,
    response_model=DynamicGroupResponse,
)
def create_dynamic_group(
    payload: DynamicGroupCreateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("dynamic_group.manage")),
) -> dict[str, object]:
    name = normalize_required_string(payload.name, "name")
    normalized_view_id = normalize_required_string(payload.saved_view_id, "saved_view_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            saved_view = session.scalar(
                select(SavedView).where(
                    SavedView.saved_view_id == normalized_view_id,
                    _resource_scope_clause(
                        principal,
                        "saved_view.read",
                        SavedView.scope_type,
                        SavedView.client_id,
                        SavedView.location_id,
                    ),
                    or_(SavedView.visibility == "shared", _owner_clause(principal, SavedView)),
                )
            )
            if saved_view is None:
                raise HTTPException(status_code=404, detail="saved view not found")
            _require_requested_scope(
                session,
                principal,
                "dynamic_group.manage",
                scope_type=saved_view.scope_type,
                client_id=saved_view.client_id,
                location_id=saved_view.location_id,
            )
            group = DynamicGroup(
                dynamic_group_id=generate_prefixed_id("grp"),
                name=name,
                name_normalized=name.casefold(),
                description=_optional_text(payload.description),
                scope_type=saved_view.scope_type,
                scope_key=saved_view.scope_key,
                client_id=saved_view.client_id,
                location_id=saved_view.location_id,
                saved_view_id=saved_view.saved_view_id,
                owner_user_id=principal.user_id,
                owner_actor=principal.audit_actor,
                created_at=now,
                updated_at=now,
            )
            session.add(group)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(
                    status_code=409,
                    detail="dynamic group name already exists in scope",
                ) from exc
            version = _current_view_version(session, saved_view)
            record_audit_event(
                session,
                event_type="dynamic_group_created",
                principal=principal,
                client_id=group.client_id,
                location_id=group.location_id,
                target_type="dynamic_group",
                target_id=group.dynamic_group_id,
                metadata={
                    "saved_view_id": group.saved_view_id,
                    "saved_view_version": saved_view.current_version,
                    "filter_hash": version.content_hash,
                },
                created_at=now,
            )
            session.flush()
            return _dynamic_group_payload(session, group)


def _endpoint_scope_clause(group: DynamicGroup) -> ColumnElement[bool]:
    if group.scope_type == "global":
        return true()
    if group.scope_type == "client" and group.client_id is not None:
        return Endpoint.client_id == group.client_id
    if (
        group.scope_type == "location"
        and group.client_id is not None
        and group.location_id is not None
    ):
        return and_(
            Endpoint.client_id == group.client_id,
            Endpoint.location_id == group.location_id,
        )
    return false()


def _rule_values(
    endpoint: Endpoint,
    rule: EndpointFilterRule,
    endpoint_tags: set[str],
) -> list[str]:
    if rule.field.value == "tag":
        return sorted(endpoint_tags)
    raw_value = getattr(endpoint, rule.field.value)
    return ["unknown" if raw_value is None else str(raw_value).casefold()]


def _matches_rule(
    endpoint: Endpoint,
    rule: EndpointFilterRule,
    endpoint_tags: set[str],
) -> bool:
    actual_values = _rule_values(endpoint, rule, endpoint_tags)
    raw_expected = rule.value if isinstance(rule.value, list) else [rule.value]
    expected_values = [value.casefold() for value in raw_expected]
    if rule.operator == EndpointFilterOperator.eq:
        return expected_values[0] in actual_values
    if rule.operator == EndpointFilterOperator.neq:
        return expected_values[0] not in actual_values
    if rule.operator == EndpointFilterOperator.in_:
        return bool(set(actual_values) & set(expected_values))
    if rule.operator == EndpointFilterOperator.contains:
        return any(expected_values[0] in actual for actual in actual_values)
    if rule.operator == EndpointFilterOperator.starts_with:
        return any(actual.startswith(expected_values[0]) for actual in actual_values)
    raise RuntimeError("unsupported endpoint filter operator")


def _matches_filter(
    endpoint: Endpoint,
    filter_definition: EndpointFilterDefinition,
    endpoint_tags: set[str],
) -> bool:
    results = [
        _matches_rule(endpoint, rule, endpoint_tags)
        for rule in filter_definition.rules
    ]
    return all(results) if filter_definition.match.value == "all" else any(results)


@router.get(
    "/api/dynamic-groups/{dynamic_group_id}/preview",
    response_model=DynamicGroupPreviewResponse,
)
def preview_dynamic_group(
    dynamic_group_id: str,
    limit: int = Query(100, ge=1, le=500),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("dynamic_group.read")),
) -> dict[str, object]:
    normalized_group_id = normalize_required_string(dynamic_group_id, "dynamic_group_id")
    if not has_permission(principal, "endpoint.read"):
        raise HTTPException(status_code=403, detail="endpoint read permission is required")
    with store.session() as session:
        group = session.scalar(
            select(DynamicGroup).where(
                DynamicGroup.dynamic_group_id == normalized_group_id,
                _resource_scope_clause(
                    principal,
                    "dynamic_group.read",
                    DynamicGroup.scope_type,
                    DynamicGroup.client_id,
                    DynamicGroup.location_id,
                ),
            )
        )
        if group is None:
            raise HTTPException(status_code=404, detail="dynamic group not found")
        saved_view = session.get(SavedView, group.saved_view_id)
        if saved_view is None:
            raise RuntimeError("dynamic group saved view is missing")
        version = _current_view_version(session, saved_view)
        filter_definition = EndpointFilterDefinition.model_validate(version.filter_json)
        endpoints = session.scalars(
            select(Endpoint)
            .where(
                _endpoint_scope_clause(group),
                scope_clause(
                    principal,
                    "endpoint.read",
                    Endpoint.client_id,
                    Endpoint.location_id,
                ),
            )
            .order_by(Endpoint.endpoint_id.asc())
            .limit(MAX_GROUP_EVALUATION_ENDPOINTS + 1)
        ).all()
        if len(endpoints) > MAX_GROUP_EVALUATION_ENDPOINTS:
            raise HTTPException(
                status_code=413,
                detail="authorized preview scope exceeds the endpoint evaluation limit",
            )
        endpoint_ids = [endpoint.endpoint_id for endpoint in endpoints]
        tag_rows = (
            session.execute(
                select(EndpointTagAssignment.endpoint_id, Tag.tag_id, Tag.name)
                .join(Tag, Tag.tag_id == EndpointTagAssignment.tag_id)
                .where(EndpointTagAssignment.endpoint_id.in_(endpoint_ids))
            ).all()
            if endpoint_ids
            else []
        )
        tags_by_endpoint: dict[str, set[str]] = {endpoint_id: set() for endpoint_id in endpoint_ids}
        for endpoint_id, tag_id, tag_name in tag_rows:
            tags_by_endpoint[str(endpoint_id)].update(
                {str(tag_id).casefold(), str(tag_name).casefold()}
            )
        matching = [
            endpoint
            for endpoint in endpoints
            if _matches_filter(
                endpoint,
                filter_definition,
                tags_by_endpoint.get(endpoint.endpoint_id, set()),
            )
        ]
        visible = matching[:limit]
        return {
            "dynamic_group_id": group.dynamic_group_id,
            "saved_view_id": saved_view.saved_view_id,
            "saved_view_version": saved_view.current_version,
            "filter_hash": version.content_hash,
            "evaluated_endpoint_count": len(endpoints),
            "matched_endpoint_count": len(matching),
            "result_limit": limit,
            "truncated": len(matching) > limit,
            "items": [
                {
                    "endpoint_id": endpoint.endpoint_id,
                    "hostname": endpoint.hostname,
                    "platform": endpoint.platform,
                    "status": endpoint.status,
                    "connectivity_status": endpoint.connectivity_status,
                    "client_id": endpoint.client_id,
                    "location_id": endpoint.location_id,
                }
                for endpoint in visible
            ],
        }
