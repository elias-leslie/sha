from __future__ import annotations

from enum import Enum
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

PINNED_GENERATED_AT = "2026-04-18T00:00:00Z"
CANONICAL_PLATFORM_ORDER = ("windows", "linux")
CANONICAL_PROFILE_ORDER = ("domain_controller", "endpoint", "server")


class SourceFamily(str, Enum):
    nist_800_53 = "nist_800_53"
    disa_stig = "disa_stig"
    cisa_nsa = "cisa_nsa"


class SourcePlatform(str, Enum):
    windows = "windows"
    linux = "linux"


class SourceProfile(str, Enum):
    domain_controller = "domain_controller"
    endpoint = "endpoint"
    server = "server"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Disruption(str, Enum):
    transparent = "transparent"
    minimal = "minimal"
    moderate = "moderate"
    significant = "significant"
    disruptive = "disruptive"


class RollbackComplexity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


def _ensure_trimmed_text(value: Any, field_name: str) -> Any:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank")
    if value.strip() != value:
        raise ValueError(f"{field_name} must already be trimmed")
    return value


def _ordered_subset(values: Sequence[str], allowed_order: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return [value for value in allowed_order if value in seen]


def _ensure_ordered_unique_sequence(
    value: Any,
    *,
    field_name: str,
    allowed_order: Sequence[str],
    lexical: bool = False,
) -> Any:
    if not isinstance(value, (list, tuple)):
        return value

    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} entries must be strings")
        trimmed = item.strip()
        if not trimmed:
            raise ValueError(f"{field_name} entries must not be blank")
        if trimmed != item:
            raise ValueError(f"{field_name} entries must already be trimmed")
        if trimmed in seen:
            raise ValueError(f"{field_name} entries must be unique")
        seen.add(trimmed)
        normalized.append(trimmed)

    expected = sorted(normalized) if lexical else _ordered_subset(normalized, allowed_order)
    if normalized != expected:
        raise ValueError(f"{field_name} entries must be ordered canonically")
    return value


class SourcePackProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_locator: str
    notes: str

    @field_validator("source_locator", "notes", mode="before")
    @classmethod
    def _validate_text_fields(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_trimmed_text(value, (info.field_name or "value"))


class SourcePackMappings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nist_csf_ids: list[str]
    sp80053_ids: list[str]
    stig_ids: list[str]
    cisa_reference_ids: list[str]

    @field_validator("nist_csf_ids", "sp80053_ids", "stig_ids", "cisa_reference_ids", mode="before")
    @classmethod
    def _validate_mapping_lists(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_ordered_unique_sequence(
            value,
            field_name=(info.field_name or "value"),
            allowed_order=(),
            lexical=True,
        )


class SourcePackControl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    title: str
    platform: SourcePlatform
    profiles: list[SourceProfile]
    severity: Severity
    disruption: Disruption
    rollback_complexity: RollbackComplexity
    auto_remediation_candidate: bool
    reboot_required: bool
    guidance_summary: str
    detection_summary: str
    remediation_summary: str
    rollback_summary: str
    provenance: SourcePackProvenance
    mappings: SourcePackMappings

    @field_validator("control_id", "title", "guidance_summary", "detection_summary", "remediation_summary", "rollback_summary", mode="before")
    @classmethod
    def _validate_text_fields(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_trimmed_text(value, (info.field_name or "value"))

    @field_validator("profiles", mode="before")
    @classmethod
    def _validate_profiles(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_ordered_unique_sequence(
            value,
            field_name=(info.field_name or "value"),
            allowed_order=CANONICAL_PROFILE_ORDER,
        )

    @model_validator(mode="after")
    def _validate_deterministic_formulas(self) -> SourcePackControl:
        expected_guidance = f"Starter guidance for {self.title}."
        expected_detection = f"Check state for {self.title}."
        expected_remediation = f"Apply desired state for {self.title}."
        expected_rollback = f"Rollback desired state for {self.title}."

        if self.guidance_summary != expected_guidance:
            raise ValueError("guidance_summary must follow the pinned starter formula")
        if self.detection_summary != expected_detection:
            raise ValueError("detection_summary must follow the pinned starter formula")
        if self.remediation_summary != expected_remediation:
            raise ValueError("remediation_summary must follow the pinned starter formula")
        if self.rollback_summary != expected_rollback:
            raise ValueError("rollback_summary must follow the pinned starter formula")
        return self


class SourcePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str
    source_family: SourceFamily
    source_name: str
    source_version: str
    generated_at: str
    source_url: str
    platforms: list[SourcePlatform]
    profiles: list[SourceProfile]
    summary: str
    controls: list[SourcePackControl] = Field(min_length=1)

    @field_validator(
        "pack_id",
        "source_name",
        "source_version",
        "source_url",
        "generated_at",
        "summary",
        mode="before",
    )
    @classmethod
    def _validate_text_fields(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_trimmed_text(value, (info.field_name or "value"))

    @field_validator("platforms", mode="before")
    @classmethod
    def _validate_platforms(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_ordered_unique_sequence(
            value,
            field_name=(info.field_name or "value"),
            allowed_order=CANONICAL_PLATFORM_ORDER,
        )

    @field_validator("profiles", mode="before")
    @classmethod
    def _validate_profiles(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_ordered_unique_sequence(
            value,
            field_name=(info.field_name or "value"),
            allowed_order=CANONICAL_PROFILE_ORDER,
        )

    @field_validator("generated_at", mode="after")
    @classmethod
    def _validate_generated_at(cls, value: str, info: ValidationInfo) -> str:
        if value != PINNED_GENERATED_AT:
            field_name = info.field_name or "value"
            raise ValueError(f"{field_name} must be pinned to {PINNED_GENERATED_AT}")
        return value

    @model_validator(mode="after")
    def _validate_pack_shape(self) -> SourcePack:
        expected_summary = f"Curated starter pack for {self.source_name}."
        if self.summary != expected_summary:
            raise ValueError("summary must follow the pinned starter formula")

        control_ids = [control.control_id for control in self.controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("control_id values must be unique within a pack")
        if control_ids != sorted(control_ids):
            raise ValueError("controls must be sorted by control_id")

        expected_platforms = _ordered_subset([control.platform.value for control in self.controls], CANONICAL_PLATFORM_ORDER)
        expected_profiles = _ordered_subset(
            [profile.value for control in self.controls for profile in control.profiles],
            CANONICAL_PROFILE_ORDER,
        )
        actual_platforms = [platform.value for platform in self.platforms]
        actual_profiles = [profile.value for profile in self.profiles]

        if actual_platforms != expected_platforms:
            raise ValueError("platforms must equal the canonical union of control platforms")
        if actual_profiles != expected_profiles:
            raise ValueError("profiles must equal the canonical union of control profiles")

        expected_notes = f"Starter control selected for {self.source_name}."
        for control in self.controls:
            if control.provenance.notes != expected_notes:
                raise ValueError("provenance.notes must follow the pinned starter formula")
        return self


class CatalogPackSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str
    source_family: SourceFamily
    source_name: str
    source_version: str
    control_count: int = Field(ge=1)

    @field_validator("pack_id", "source_name", "source_version", mode="before")
    @classmethod
    def _validate_text_fields(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_trimmed_text(value, (info.field_name or "value"))


class SourceCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    pack_count: int = Field(ge=1)
    control_count: int = Field(ge=1)
    packs: list[CatalogPackSummary] = Field(min_length=1)

    @field_validator("generated_at", mode="before")
    @classmethod
    def _validate_generated_at(cls, value: Any, info: ValidationInfo) -> Any:
        return _ensure_trimmed_text(value, (info.field_name or "value"))

    @field_validator("generated_at", mode="after")
    @classmethod
    def _validate_pinned_generated_at(cls, value: str, info: ValidationInfo) -> str:
        if value != PINNED_GENERATED_AT:
            field_name = info.field_name or "value"
            raise ValueError(f"{field_name} must be pinned to {PINNED_GENERATED_AT}")
        return value

    @model_validator(mode="after")
    def _validate_summary(self) -> SourceCatalog:
        pack_ids = [pack.pack_id for pack in self.packs]
        if len(pack_ids) != len(set(pack_ids)):
            raise ValueError("pack_id values must be unique")
        if pack_ids != sorted(pack_ids):
            raise ValueError("packs must be sorted by pack_id")
        if self.pack_count != len(self.packs):
            raise ValueError("pack_count must match the number of pack summaries")
        if self.control_count != sum(pack.control_count for pack in self.packs):
            raise ValueError("control_count must match the sum of pack control counts")
        return self


__all__ = [
    "CatalogPackSummary",
    "CANONICAL_PLATFORM_ORDER",
    "CANONICAL_PROFILE_ORDER",
    "Disruption",
    "PINNED_GENERATED_AT",
    "RollbackComplexity",
    "Severity",
    "SourceCatalog",
    "SourceFamily",
    "SourcePack",
    "SourcePackControl",
    "SourcePackMappings",
    "SourcePackProvenance",
    "SourcePlatform",
    "SourceProfile",
]
