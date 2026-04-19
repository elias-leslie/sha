from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from app.source_packs.contracts import SourceCatalog, SourcePack, SourcePackControl

PINNED_GENERATED_AT = "2026-04-18T00:00:00Z"


def control_payload(
    *,
    control_id: str = "control.example.alpha",
    title: str = "Example control alpha",
    platform: str = "windows",
    profiles: list[str] | tuple[str, ...] = ("endpoint", "server"),
    severity: str = "medium",
    disruption: str = "minimal",
    rollback_complexity: str = "low",
    auto_remediation_candidate: bool = True,
    reboot_required: bool = False,
    source_locator: str = "Example locator alpha",
    source_name: str = "Example Starter Pack",
    mappings: dict[str, list[str]] | None = None,
) -> dict[str, object]:
    if mappings is None:
        mappings = {
            "cis_control_ids": ["4.1"],
            "nist_csf_ids": [],
            "sp80053_ids": [],
            "legacy_sha_ids": ["SHA001"],
        }

    return {
        "control_id": control_id,
        "title": title,
        "platform": platform,
        "profiles": list(profiles),
        "severity": severity,
        "disruption": disruption,
        "rollback_complexity": rollback_complexity,
        "auto_remediation_candidate": auto_remediation_candidate,
        "reboot_required": reboot_required,
        "guidance_summary": f"Starter guidance for {title}.",
        "detection_summary": f"Check state for {title}.",
        "remediation_summary": f"Apply desired state for {title}.",
        "rollback_summary": f"Rollback desired state for {title}.",
        "provenance": {
            "source_locator": source_locator,
            "notes": f"Starter control selected for {source_name}.",
        },
        "mappings": deepcopy(mappings),
    }


def pack_payload(
    *,
    pack_id: str = "pack.example-starter",
    source_family: str = "microsoft",
    source_name: str = "Example Starter Pack",
    source_version: str = "starter-2026.04",
    source_url: str = "https://example.test",
    controls: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if controls is None:
        controls = [
            control_payload(),
            control_payload(
                control_id="control.example.beta",
                title="Example control beta",
                platform="linux",
                profiles=("domain_controller", "server"),
                severity="high",
                disruption="moderate",
                rollback_complexity="medium",
                auto_remediation_candidate=False,
                reboot_required=True,
                source_locator="Example locator beta",
                source_name=source_name,
                mappings={
                    "cis_control_ids": [],
                    "nist_csf_ids": ["PR.AA-01"],
                    "sp80053_ids": ["AC-17"],
                    "legacy_sha_ids": [],
                },
            ),
        ]

    platforms = []
    for platform in ("windows", "linux"):
        if any(control["platform"] == platform for control in controls) and platform not in platforms:
            platforms.append(platform)

    profiles: list[str] = []
    for profile in ("domain_controller", "endpoint", "server"):
        if any(profile in control["profiles"] for control in controls) and profile not in profiles:
            profiles.append(profile)

    return {
        "pack_id": pack_id,
        "source_family": source_family,
        "source_name": source_name,
        "source_version": source_version,
        "generated_at": PINNED_GENERATED_AT,
        "source_url": source_url,
        "platforms": platforms,
        "profiles": profiles,
        "summary": f"Curated starter pack for {source_name}.",
        "controls": deepcopy(controls),
    }


def catalog_payload() -> dict[str, object]:
    packs = [
        {
            "pack_id": "pack.alpha",
            "source_family": "cis",
            "source_name": "Alpha Starter Pack",
            "source_version": "starter-2026.04",
            "control_count": 2,
        },
        {
            "pack_id": "pack.beta",
            "source_family": "microsoft",
            "source_name": "Beta Starter Pack",
            "source_version": "starter-2026.04",
            "control_count": 2,
        },
    ]
    return {
        "generated_at": PINNED_GENERATED_AT,
        "pack_count": 2,
        "control_count": 4,
        "packs": packs,
    }


def test_source_pack_control_contract_enforces_formulas_and_nested_field_shape() -> None:
    payload = control_payload()
    model = SourcePackControl.model_validate(payload)
    assert model.guidance_summary == "Starter guidance for Example control alpha."
    assert model.detection_summary == "Check state for Example control alpha."
    assert model.remediation_summary == "Apply desired state for Example control alpha."
    assert model.rollback_summary == "Rollback desired state for Example control alpha."

    bad = deepcopy(payload)
    bad["guidance_summary"] = "Starter guidance for Wrong."
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)

    bad = deepcopy(payload)
    bad["profiles"] = ["server", "endpoint"]
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)

    bad = deepcopy(payload)
    bad["mappings"]["cis_control_ids"] = ["SHA002", "SHA001"]
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)

    bad = deepcopy(payload)
    bad["mappings"]["cis_control_ids"] = ["4.1", " 4.1"]
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)

    bad = deepcopy(payload)
    bad["mappings"]["unexpected"] = []
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)

    bad = deepcopy(payload)
    bad["provenance"]["unexpected"] = "x"
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)

    bad = deepcopy(payload)
    bad["title"] = "   "
    with pytest.raises(ValidationError):
        SourcePackControl.model_validate(bad)


def test_source_pack_contract_enforces_sorted_controls_union_and_pinned_timestamp() -> None:
    payload = pack_payload()
    model = SourcePack.model_validate(payload)
    assert model.summary == "Curated starter pack for Example Starter Pack."
    assert model.generated_at == PINNED_GENERATED_AT
    assert [control.control_id for control in model.controls] == [
        "control.example.alpha",
        "control.example.beta",
    ]
    assert model.controls[0].provenance.notes == "Starter control selected for Example Starter Pack."

    bad = deepcopy(payload)
    bad["summary"] = "Curated starter pack for Wrong."
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)

    bad = deepcopy(payload)
    bad["controls"][0]["provenance"]["notes"] = "wrong"
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)

    bad = deepcopy(payload)
    bad["generated_at"] = "2026-04-19T00:00:00Z"
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)

    bad = deepcopy(payload)
    bad["controls"] = []
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)

    bad = deepcopy(payload)
    bad["controls"] = list(reversed(bad["controls"]))
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)

    bad = deepcopy(payload)
    bad["platforms"] = ["windows"]
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)

    bad = deepcopy(payload)
    bad["profiles"] = ["server", "endpoint"]
    with pytest.raises(ValidationError):
        SourcePack.model_validate(bad)


def test_source_pack_contract_accepts_legacy_sha_family() -> None:
    payload = pack_payload(
        source_family="legacy_sha",
        source_name="Legacy SHA Snapshot",
        controls=[
            control_payload(source_name="Legacy SHA Snapshot"),
            control_payload(
                control_id="control.example.beta",
                title="Example control beta",
                platform="linux",
                profiles=("domain_controller", "server"),
                severity="high",
                disruption="moderate",
                rollback_complexity="medium",
                auto_remediation_candidate=False,
                reboot_required=True,
                source_locator="Example locator beta",
                source_name="Legacy SHA Snapshot",
                mappings={
                    "cis_control_ids": [],
                    "nist_csf_ids": ["PR.AA-01"],
                    "sp80053_ids": ["AC-17"],
                    "legacy_sha_ids": [],
                },
            ),
        ],
    )

    model = SourcePack.model_validate(payload)

    assert model.source_family.value == "legacy_sha"
    assert model.summary == "Curated starter pack for Legacy SHA Snapshot."


def test_source_catalog_contract_enforces_order_counts_and_nested_field_shape() -> None:
    payload = catalog_payload()
    model = SourceCatalog.model_validate(payload)
    assert model.generated_at == PINNED_GENERATED_AT
    assert model.pack_count == 2
    assert model.control_count == 4
    assert [pack.pack_id for pack in model.packs] == ["pack.alpha", "pack.beta"]

    bad = deepcopy(payload)
    bad["packs"] = list(reversed(bad["packs"]))
    with pytest.raises(ValidationError):
        SourceCatalog.model_validate(bad)

    bad = deepcopy(payload)
    bad["packs"][0]["unexpected"] = 1
    with pytest.raises(ValidationError):
        SourceCatalog.model_validate(bad)

    bad = deepcopy(payload)
    bad["pack_count"] = 3
    with pytest.raises(ValidationError):
        SourceCatalog.model_validate(bad)

    bad = deepcopy(payload)
    bad["control_count"] = 5
    with pytest.raises(ValidationError):
        SourceCatalog.model_validate(bad)
