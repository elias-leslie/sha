from __future__ import annotations

import csv
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Sequence

from pydantic import ValidationError

from app.source_packs.contracts import (
    CANONICAL_PLATFORM_ORDER,
    CANONICAL_PROFILE_ORDER,
    PINNED_GENERATED_AT,
    CatalogPackSummary,
    SourceCatalog,
    SourcePack,
)


def control_spec(
    *,
    control_id: str,
    title: str,
    platform: str,
    profiles: tuple[str, ...] | list[str],
    severity: str,
    disruption: str,
    rollback_complexity: str,
    auto_remediation_candidate: bool,
    reboot_required: bool,
    source_locator: str,
    mappings: dict[str, list[str]],
) -> dict[str, object]:
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
        "source_locator": source_locator,
        "mappings": mappings,
    }


def pack_spec(
    *,
    filename: str,
    pack_id: str,
    source_family: str,
    source_name: str,
    source_version: str,
    source_url: str,
    controls: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "filename": filename,
        "pack_id": pack_id,
        "source_family": source_family,
        "source_name": source_name,
        "source_version": source_version,
        "source_url": source_url,
        "controls": controls,
    }


def control_payload(source_name: str, spec: dict[str, object]) -> dict[str, object]:
    title = str(spec["title"])
    return {
        "control_id": spec["control_id"],
        "title": title,
        "platform": spec["platform"],
        "profiles": list(spec["profiles"]),
        "severity": spec["severity"],
        "disruption": spec["disruption"],
        "rollback_complexity": spec["rollback_complexity"],
        "auto_remediation_candidate": spec["auto_remediation_candidate"],
        "reboot_required": spec["reboot_required"],
        "guidance_summary": f"Starter guidance for {title}.",
        "detection_summary": f"Check state for {title}.",
        "remediation_summary": f"Apply desired state for {title}.",
        "rollback_summary": f"Rollback desired state for {title}.",
        "provenance": {
            "source_locator": spec["source_locator"],
            "notes": f"Starter control selected for {source_name}.",
        },
        "mappings": deepcopy(spec["mappings"]),
    }


MICROSOFT_PACK = pack_spec(
    filename="microsoft.windows-security-baseline-starter.json",
    pack_id="pack.microsoft.windows-security-baseline-starter",
    source_family="microsoft",
    source_name="Microsoft Windows Security Baseline Starter",
    source_version="starter-2026.04",
    source_url="https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines",
    controls=[
        control_spec(
            control_id="control.microsoft-windows-security-baseline-starter.account-lockout-threshold",
            title="Enforce account lockout threshold",
            platform="windows",
            profiles=("endpoint", "server"),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Account Policies / Account lockout threshold",
            mappings={
                "cis_control_ids": ["4.1"],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": ["SHA009"],
            },
        ),
        control_spec(
            control_id="control.microsoft-windows-security-baseline-starter.password-history",
            title="Enforce password history",
            platform="windows",
            profiles=("endpoint", "server"),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Account Policies / Password history",
            mappings={
                "cis_control_ids": ["4.1"],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": ["SHA001"],
            },
        ),
        control_spec(
            control_id="control.microsoft-windows-security-baseline-starter.password-min-length",
            title="Enforce minimum password length",
            platform="windows",
            profiles=("endpoint", "server"),
            severity="high",
            disruption="moderate",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Account Policies / Minimum password length",
            mappings={
                "cis_control_ids": ["4.1"],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": ["SHA004"],
            },
        ),
    ],
)

CIS_PACK = pack_spec(
    filename="cis.windows-server-l1-starter.json",
    pack_id="pack.cis.windows-server-l1-starter",
    source_family="cis",
    source_name="CIS Windows Server Level 1 Starter",
    source_version="starter-2026.04",
    source_url="https://www.cisecurity.org/cis-benchmarks",
    controls=[
        control_spec(
            control_id="control.cis-windows-server-l1-starter.disable-guest-account",
            title="Disable guest account",
            platform="windows",
            profiles=("server",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Accounts / Guest account",
            mappings={
                "cis_control_ids": ["4.1"],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": ["SHA013"],
            },
        ),
        control_spec(
            control_id="control.cis-windows-server-l1-starter.disable-smbv1",
            title="Disable SMBv1",
            platform="windows",
            profiles=("server",),
            severity="high",
            disruption="significant",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=True,
            source_locator="Network / SMBv1",
            mappings={
                "cis_control_ids": ["4.1"],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.cis-windows-server-l1-starter.smb-signing-server-required",
            title="Require SMB signing on servers",
            platform="windows",
            profiles=("server",),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Network / SMB signing",
            mappings={
                "cis_control_ids": ["4.1"],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": ["SHA027"],
            },
        ),
    ],
)

NIST_PACK = pack_spec(
    filename="nist.csf-2.0-starter.json",
    pack_id="pack.nist.csf-2.0-starter",
    source_family="nist",
    source_name="NIST CSF 2.0 Starter",
    source_version="2.0",
    source_url="https://www.nist.gov/cyberframework",
    controls=[
        control_spec(
            control_id="control.nist-csf-2-0-starter.asset-config-baseline",
            title="Maintain baseline configuration inventory",
            platform="windows",
            profiles=("domain_controller", "endpoint", "server"),
            severity="high",
            disruption="minimal",
            rollback_complexity="medium",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="PR.IP-01",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": ["PR.IP-01"],
                "sp80053_ids": ["CM-02"],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.nist-csf-2-0-starter.audit-log-retention",
            title="Retain security audit logs",
            platform="linux",
            profiles=("server",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="DE.AE-03",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": ["DE.AE-03"],
                "sp80053_ids": ["AU-11"],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.nist-csf-2-0-starter.remote-access-review",
            title="Review remote access privileges",
            platform="windows",
            profiles=("domain_controller", "server"),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="PR.AA-01",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": ["PR.AA-01"],
                "sp80053_ids": ["AC-17"],
                "legacy_sha_ids": [],
            },
        ),
    ],
)

DISA_PACK = pack_spec(
    filename="disa.windows-server-stig-starter.json",
    pack_id="pack.disa.windows-server-stig-starter",
    source_family="disa",
    source_name="DISA Windows Server STIG Starter",
    source_version="starter-2026.04",
    source_url="https://public.cyber.mil/stigs/",
    controls=[
        control_spec(
            control_id="control.disa-windows-server-stig-starter.rdp-network-level-authentication",
            title="Require Network Level Authentication for RDP",
            platform="windows",
            profiles=("server",),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="WN22-SO-000315",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.disa-windows-server-stig-starter.smartscreen-reputation-check",
            title="Enable SmartScreen reputation checks",
            platform="windows",
            profiles=("server",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="WN11-CC-000390",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.disa-windows-server-stig-starter.windows-firewall-enabled",
            title="Enable Windows Firewall",
            platform="windows",
            profiles=("server",),
            severity="high",
            disruption="significant",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="WN22-SO-000025",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
    ],
)

CISA_NSA_PACK = pack_spec(
    filename="cisa_nsa.linux-ssh-starter.json",
    pack_id="pack.cisa_nsa.linux-ssh-starter",
    source_family="cisa_nsa",
    source_name="CISA NSA Linux SSH Starter",
    source_version="starter-2026.04",
    source_url="https://www.cisa.gov/resources-tools/resources/guidance-securing-remote-access-software-and-services",
    controls=[
        control_spec(
            control_id="control.cisa-nsa-linux-ssh-starter.allowlisted-users",
            title="Restrict SSH access to allowlisted users",
            platform="linux",
            profiles=("server",),
            severity="high",
            disruption="moderate",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="SSH allowlists",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.cisa-nsa-linux-ssh-starter.disable-password-authentication",
            title="Disable SSH password authentication",
            platform="linux",
            profiles=("server",),
            severity="critical",
            disruption="significant",
            rollback_complexity="high",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="SSH password authentication",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
        control_spec(
            control_id="control.cisa-nsa-linux-ssh-starter.disable-root-login",
            title="Disable SSH root login",
            platform="linux",
            profiles=("server",),
            severity="critical",
            disruption="significant",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="SSH root login",
            mappings={
                "cis_control_ids": [],
                "nist_csf_ids": [],
                "sp80053_ids": [],
                "legacy_sha_ids": [],
            },
        ),
    ],
)

CURATED_PACK_SPECS = [
    MICROSOFT_PACK,
    CIS_PACK,
    NIST_PACK,
    DISA_PACK,
    CISA_NSA_PACK,
]
CURATED_PACK_SPECS_BY_FILENAME = {spec["filename"]: spec for spec in CURATED_PACK_SPECS}
CURATED_PACK_FILES = tuple(spec["filename"] for spec in CURATED_PACK_SPECS)
CURATED_PACK_SPECS_BY_PACK_ID = {str(spec["pack_id"]): spec for spec in CURATED_PACK_SPECS}

LEGACY_CSV_FILENAME = "SecurityControls.csv"
LEGACY_PACK_FILENAME = "legacy-sha.snapshot.json"
LEGACY_PACK_ID = "pack.legacy-sha.snapshot"
LEGACY_CONTROL_ID_PREFIX = "control.legacy-sha.snapshot"
LEGACY_SOURCE_NAME = "Legacy SHA Snapshot"
LEGACY_CSV_SHA256 = "9d5fe54d92f045195cef0e8d7ebe2fc11afcd45435febc989b4ac9f4d2bbdf01"
LEGACY_SOURCE_VERSION = f"sha256:{LEGACY_CSV_SHA256}"
LEGACY_SOURCE_URL = "repo://control-packs/legacy/SecurityControls.csv"
LEGACY_CSV_HEADERS = (
    "ID",
    "CISControlID",
    "Category",
    "Name",
    "Method",
    "MethodArgument",
    "RegistryPath",
    "RegistryItem",
    "Namespace",
    "Property",
    "ClassName",
    "DefaultValue",
    "RecommendedValue",
    "Operator",
    "Severity",
    "ControlProfile",
    "AutoRemediate",
    "RequiresReboot",
    "SystemImpact",
    "UserImpact",
    "RollbackComplexity",
    "BusinessJustification",
)


def ordered_subset(values: Sequence[str], order: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return [value for value in order if value in seen]


def pack_payload(spec: dict[str, object]) -> dict[str, object]:
    controls = [control_payload(str(spec["source_name"]), control) for control in spec["controls"]]
    return {
        "pack_id": spec["pack_id"],
        "source_family": spec["source_family"],
        "source_name": spec["source_name"],
        "source_version": spec["source_version"],
        "generated_at": PINNED_GENERATED_AT,
        "source_url": spec["source_url"],
        "platforms": ordered_subset([control["platform"] for control in controls], CANONICAL_PLATFORM_ORDER),
        "profiles": ordered_subset(
            [profile for control in controls for profile in control["profiles"]],
            CANONICAL_PROFILE_ORDER,
        ),
        "summary": f"Curated starter pack for {spec['source_name']}.",
        "controls": controls,
    }


def catalog_payload(packs: Sequence[SourcePack]) -> dict[str, object]:
    ordered_packs = sorted(packs, key=lambda pack: pack.pack_id)
    return {
        "generated_at": PINNED_GENERATED_AT,
        "pack_count": len(ordered_packs),
        "control_count": sum(len(pack.controls) for pack in ordered_packs),
        "packs": [
            {
                "pack_id": pack.pack_id,
                "source_family": pack.source_family,
                "source_name": pack.source_name,
                "source_version": pack.source_version,
                "control_count": len(pack.controls),
            }
            for pack in ordered_packs
        ],
    }


def _trimmed_cell(row: dict[str, str], field_name: str) -> str:
    return row.get(field_name, "").strip()


def _legacy_profiles(profile_name: str) -> list[str]:
    mapping = {
        "All": ["domain_controller", "endpoint", "server"],
        "DomainController": ["domain_controller"],
        "Endpoint": ["endpoint"],
        "Server": ["server"],
    }
    try:
        return mapping[profile_name]
    except KeyError as exc:
        raise ValueError(f"legacy CSV contains unsupported ControlProfile value: {profile_name}") from exc


def _legacy_severity(severity_name: str) -> str:
    mapping = {
        "Low": "low",
        "Medium": "medium",
        "High": "high",
    }
    try:
        return mapping[severity_name]
    except KeyError as exc:
        raise ValueError(f"legacy CSV contains unsupported Severity value: {severity_name}") from exc


def _legacy_disruption(system_impact: str, user_impact: str) -> str:
    impact = max(int(system_impact), int(user_impact))
    if impact <= 1:
        return "transparent"
    if impact <= 2:
        return "minimal"
    if impact <= 3:
        return "moderate"
    if impact <= 5:
        return "significant"
    return "disruptive"


def _legacy_rollback_complexity(raw_value: str) -> str:
    mapping = {
        "1": "low",
        "2": "low",
        "3": "medium",
        "4": "high",
    }
    try:
        return mapping[raw_value]
    except KeyError as exc:
        raise ValueError(f"legacy CSV contains unsupported RollbackComplexity value: {raw_value}") from exc


def _legacy_boolean(raw_value: str, *, field_name: str) -> bool:
    mapping = {"Yes": True, "No": False}
    try:
        return mapping[raw_value]
    except KeyError as exc:
        raise ValueError(f"legacy CSV contains unsupported {field_name} value: {raw_value}") from exc


def _legacy_control_payload(row: dict[str, str]) -> dict[str, object]:
    legacy_id = _trimmed_cell(row, "ID")
    title = _trimmed_cell(row, "Name")
    cis_control_id = _trimmed_cell(row, "CISControlID")
    return {
        "control_id": f"{LEGACY_CONTROL_ID_PREFIX}.{legacy_id.lower()}",
        "title": title,
        "platform": "windows",
        "profiles": _legacy_profiles(_trimmed_cell(row, "ControlProfile")),
        "severity": _legacy_severity(_trimmed_cell(row, "Severity")),
        "disruption": _legacy_disruption(_trimmed_cell(row, "SystemImpact"), _trimmed_cell(row, "UserImpact")),
        "rollback_complexity": _legacy_rollback_complexity(_trimmed_cell(row, "RollbackComplexity")),
        "auto_remediation_candidate": _legacy_boolean(_trimmed_cell(row, "AutoRemediate"), field_name="AutoRemediate"),
        "reboot_required": _legacy_boolean(_trimmed_cell(row, "RequiresReboot"), field_name="RequiresReboot"),
        "guidance_summary": f"Starter guidance for {title}.",
        "detection_summary": f"Check state for {title}.",
        "remediation_summary": f"Apply desired state for {title}.",
        "rollback_summary": f"Rollback desired state for {title}.",
        "provenance": {
            "source_locator": f"{LEGACY_CSV_FILENAME}#{legacy_id}",
            "notes": f"Starter control selected for {LEGACY_SOURCE_NAME}.",
        },
        "mappings": {
            "cis_control_ids": [cis_control_id] if cis_control_id else [],
            "nist_csf_ids": [],
            "sp80053_ids": [],
            "legacy_sha_ids": [legacy_id],
        },
    }


def _legacy_pack_payload(rows: Sequence[dict[str, str]]) -> dict[str, object]:
    controls = sorted((_legacy_control_payload(row) for row in rows), key=lambda control: str(control["control_id"]))
    return {
        "pack_id": LEGACY_PACK_ID,
        "source_family": "legacy_sha",
        "source_name": LEGACY_SOURCE_NAME,
        "source_version": LEGACY_SOURCE_VERSION,
        "generated_at": PINNED_GENERATED_AT,
        "source_url": LEGACY_SOURCE_URL,
        "platforms": ordered_subset([str(control["platform"]) for control in controls], CANONICAL_PLATFORM_ORDER),
        "profiles": ordered_subset(
            [profile for control in controls for profile in list(control["profiles"])],
            CANONICAL_PROFILE_ORDER,
        ),
        "summary": f"Curated starter pack for {LEGACY_SOURCE_NAME}.",
        "controls": controls,
    }


def _repo_root(repo_root: Path | None) -> Path:
    if repo_root is None:
        return Path(__file__).resolve().parents[3]
    return Path(repo_root).resolve()


def _packs_dir(repo_root: Path) -> Path:
    return repo_root / "control-packs" / "packs"


def _catalog_path(repo_root: Path) -> Path:
    return repo_root / "control-packs" / "catalog.json"


def _legacy_csv_path(repo_root: Path) -> Path:
    return repo_root / "control-packs" / "legacy" / LEGACY_CSV_FILENAME


def _generated_dir(repo_root: Path) -> Path:
    return repo_root / "control-packs" / "generated"


def _legacy_generated_pack_path(repo_root: Path) -> Path:
    return _generated_dir(repo_root) / LEGACY_PACK_FILENAME


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is malformed JSON") from exc


def _validate_pack_against_spec(pack: SourcePack, spec: dict[str, object]) -> None:
    actual = pack.model_dump(mode="json")
    expected = pack_payload(spec)
    if actual != expected:
        raise ValueError(f"{spec['filename']} does not match the pinned curated starter inventory")


def _load_curated_packs(repo_root: Path) -> list[SourcePack]:
    packs_dir = _packs_dir(repo_root)
    if not packs_dir.is_dir():
        raise ValueError(f"missing curated packs directory: {packs_dir}")

    actual_json_files = sorted(
        (path for path in packs_dir.rglob("*") if path.is_file() and path.suffix.lower() == ".json"),
        key=lambda path: path.as_posix(),
    )
    unexpected: list[str] = []
    for path in actual_json_files:
        relative = path.relative_to(packs_dir).as_posix()
        if "/" in relative or path.name not in CURATED_PACK_SPECS_BY_FILENAME:
            unexpected.append(relative)
    if unexpected:
        raise ValueError(f"unexpected curated JSON file(s): {', '.join(unexpected)}")

    missing = [filename for filename in CURATED_PACK_FILES if not (packs_dir / filename).is_file()]
    if missing:
        raise ValueError(f"missing curated JSON file(s): {', '.join(missing)}")

    packs: list[SourcePack] = []
    for spec in CURATED_PACK_SPECS:
        path = packs_dir / str(spec["filename"])
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"curated pack must be a regular file: {path.name}")
        payload = _load_json(path)
        try:
            pack = SourcePack.model_validate(payload)
        except ValidationError as exc:
            raise ValueError(f"{path.name} failed validation") from exc
        _validate_pack_against_spec(pack, spec)
        packs.append(pack)

    pack_ids = [pack.pack_id for pack in packs]
    control_ids = [control.control_id for pack in packs for control in pack.controls]
    if len(pack_ids) != len(set(pack_ids)):
        raise ValueError("duplicate pack_id values are not allowed")
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("duplicate control_id values are not allowed")
    return packs


def _load_legacy_csv_rows(repo_root: Path) -> list[dict[str, str]]:
    csv_path = _legacy_csv_path(repo_root)
    if csv_path.is_symlink() or not csv_path.is_file():
        raise ValueError(f"legacy CSV snapshot must be a regular file: {csv_path}")

    csv_bytes = csv_path.read_bytes()
    digest = hashlib.sha256(csv_bytes).hexdigest()
    if digest != LEGACY_CSV_SHA256:
        raise ValueError(
            f"legacy CSV snapshot hash mismatch for {csv_path.name}: expected {LEGACY_CSV_SHA256}, got {digest}"
        )

    text = csv_bytes.decode("utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    if tuple(reader.fieldnames or ()) != LEGACY_CSV_HEADERS:
        raise ValueError(f"legacy CSV snapshot headers do not match the pinned schema: {csv_path.name}")

    rows = [{key: value for key, value in row.items() if key is not None} for row in reader]
    if not rows:
        raise ValueError(f"legacy CSV snapshot is empty: {csv_path.name}")
    return rows


def _build_legacy_pack(repo_root: Path) -> SourcePack:
    rows = _load_legacy_csv_rows(repo_root)
    try:
        return SourcePack.model_validate(_legacy_pack_payload(rows))
    except ValidationError as exc:
        raise ValueError("generated legacy SHA pack failed validation") from exc


def _render_pack_json(pack: SourcePack) -> str:
    return json.dumps(pack.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def _write_legacy_pack(repo_root: Path, pack: SourcePack) -> Path:
    pack_path = _legacy_generated_pack_path(repo_root)
    pack_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = _render_pack_json(pack)
    tmp_path = pack_path.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(rendered, encoding="utf-8")
        tmp_path.replace(pack_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    return pack_path


def _render_catalog_json(catalog: SourceCatalog) -> str:
    return json.dumps(catalog.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def _write_catalog(repo_root: Path, catalog: SourceCatalog) -> Path:
    catalog_path = _catalog_path(repo_root)
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = _render_catalog_json(catalog)
    tmp_path = catalog_path.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(rendered, encoding="utf-8")
        tmp_path.replace(catalog_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    return catalog_path


def build_source_catalog(repo_root: Path | None = None) -> SourceCatalog:
    resolved_repo_root = _repo_root(repo_root)
    curated_packs = _load_curated_packs(resolved_repo_root)
    legacy_pack = _build_legacy_pack(resolved_repo_root)
    all_packs = [*curated_packs, legacy_pack]

    pack_ids = [pack.pack_id for pack in all_packs]
    control_ids = [control.control_id for pack in all_packs for control in pack.controls]
    if len(pack_ids) != len(set(pack_ids)):
        raise ValueError("duplicate pack_id values are not allowed")
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("duplicate control_id values are not allowed")

    catalog = SourceCatalog.model_validate(catalog_payload(all_packs))
    _write_legacy_pack(resolved_repo_root, legacy_pack)
    _write_catalog(resolved_repo_root, catalog)
    return catalog


def load_source_catalog(repo_root: Path | None = None) -> SourceCatalog:
    resolved_repo_root = _repo_root(repo_root)
    catalog_path = _catalog_path(resolved_repo_root)
    if not catalog_path.is_file():
        raise FileNotFoundError(catalog_path)
    return SourceCatalog.model_validate(_load_json(catalog_path))


def load_source_pack(pack_id: str, repo_root: Path | None = None) -> SourcePack:
    resolved_repo_root = _repo_root(repo_root)
    if pack_id == LEGACY_PACK_ID:
        pack_path = _legacy_generated_pack_path(resolved_repo_root)
    else:
        spec = CURATED_PACK_SPECS_BY_PACK_ID.get(pack_id)
        if spec is None:
            raise FileNotFoundError(pack_id)
        pack_path = _packs_dir(resolved_repo_root) / str(spec["filename"])

    if not pack_path.is_file():
        raise FileNotFoundError(pack_path)
    return SourcePack.model_validate(_load_json(pack_path))


__all__ = [
    "CURATED_PACK_FILES",
    "CURATED_PACK_SPECS",
    "CURATED_PACK_SPECS_BY_FILENAME",
    "LEGACY_CSV_FILENAME",
    "LEGACY_CSV_SHA256",
    "LEGACY_PACK_FILENAME",
    "LEGACY_PACK_ID",
    "LEGACY_SOURCE_NAME",
    "LEGACY_SOURCE_URL",
    "LEGACY_SOURCE_VERSION",
    "build_source_catalog",
    "catalog_payload",
    "control_spec",
    "load_source_catalog",
    "load_source_pack",
    "pack_payload",
    "pack_spec",
]
