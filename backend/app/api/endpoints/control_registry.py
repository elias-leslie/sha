from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth import Principal
from app.authorization import require_permission
from app.control_registry import control_registry
from app.schemas.contracts import (
    ControlRegistryAction,
    ControlRegistryItemResponse,
    ControlRegistryKind,
    ControlRegistryResponse,
    EndpointPlatform,
)

router = APIRouter(prefix="/api/control-registry", tags=["control-registry"])

_ACTION_ORDER = {
    "apply_control": 0,
    "rollback_control": 1,
}


@router.get("", response_model=ControlRegistryResponse)
def list_control_registry(
    _principal: Principal = Depends(require_permission("catalog.read")),
) -> ControlRegistryResponse:
    registry = control_registry()
    return ControlRegistryResponse(
        items=[
            ControlRegistryItemResponse(
                control_id=control.control_id,
                title=control.title,
                platform=EndpointPlatform(control.platform),
                kind=ControlRegistryKind(control.kind),
                observation_aliases=sorted(control.observation_aliases),
                supported_actions=[
                    ControlRegistryAction(action)
                    for action in sorted(
                        control.supported_actions,
                        key=_ACTION_ORDER.__getitem__,
                    )
                ],
            )
            for control in (registry[control_id] for control_id in sorted(registry))
        ]
    )
