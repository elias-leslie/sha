from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Sequence

from pydantic import ValidationError

from app.source_packs.contracts import (
    CANONICAL_PLATFORM_ORDER,
    CANONICAL_PROFILE_ORDER,
    PINNED_GENERATED_AT,
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
) -> dict[str, Any]:
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
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "filename": filename,
        "pack_id": pack_id,
        "source_family": source_family,
        "source_name": source_name,
        "source_version": source_version,
        "source_url": source_url,
        "controls": controls,
    }


def public_mappings(
    *,
    nist_csf_ids: list[str] | None = None,
    sp80053_ids: list[str] | None = None,
    stig_ids: list[str] | None = None,
    cisa_reference_ids: list[str] | None = None,
) -> dict[str, list[str]]:
    return {
        "nist_csf_ids": nist_csf_ids or [],
        "sp80053_ids": sp80053_ids or [],
        "stig_ids": stig_ids or [],
        "cisa_reference_ids": cisa_reference_ids or [],
    }


def control_payload(source_name: str, spec: dict[str, Any]) -> dict[str, Any]:
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


NIST_800_53_PACK = pack_spec(
    filename="nist.800-53-rev5-starter.json",
    pack_id="pack.public.nist-800-53-rev5-starter",
    source_family="nist_800_53",
    source_name="NIST SP 800-53 Rev. 5 Starter",
    source_version="5.2.0",
    source_url="https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
    controls=[
        control_spec(
            control_id="control.public.nist-800-53.ac-17",
            title="Remote Access",
            platform="windows",
            profiles=("domain_controller", "endpoint", "server"),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="NIST SP 800-53 Rev. 5 control AC-17",
            mappings=public_mappings(sp80053_ids=["AC-17"]),
        ),
        control_spec(
            control_id="control.public.nist-800-53.au-11",
            title="Audit Record Retention",
            platform="linux",
            profiles=("server",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="NIST SP 800-53 Rev. 5 control AU-11",
            mappings=public_mappings(sp80053_ids=["AU-11"]),
        ),
        control_spec(
            control_id="control.public.nist-800-53.cm-2",
            title="Baseline Configuration",
            platform="windows",
            profiles=("domain_controller", "endpoint", "server"),
            severity="high",
            disruption="minimal",
            rollback_complexity="medium",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="NIST SP 800-53 Rev. 5 control CM-2",
            mappings=public_mappings(sp80053_ids=["CM-2"]),
        ),
    ],
)

DISA_WINDOWS_SERVER_2022_PACK = pack_spec(
    filename="disa.windows-server-2022-v2r5-starter.json",
    pack_id="pack.public.disa-windows-server-2022-v2r5-starter",
    source_family="disa_stig",
    source_name="DISA Microsoft Windows Server 2022 STIG V2R5 Starter",
    source_version="V2R5",
    source_url="https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R5_STIG.zip",
    controls=[
        control_spec(
            control_id="control.public.disa-windows-server-2022.wn22-00-000010",
            title="Separate administrator and standard user accounts",
            platform="windows",
            profiles=("server",),
            severity="medium",
            disruption="moderate",
            rollback_complexity="medium",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="DISA Windows Server 2022 STIG V2R5 WN22-00-000010 / V-254238",
            mappings=public_mappings(stig_ids=["WN22-00-000010"]),
        ),
        control_spec(
            control_id="control.public.disa-windows-server-2022.wn22-au-000010",
            title="Back up audit records separately",
            platform="windows",
            profiles=("server",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="medium",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="DISA Windows Server 2022 STIG V2R5 WN22-AU-000010 / V-254294",
            mappings=public_mappings(stig_ids=["WN22-AU-000010"]),
        ),
        control_spec(
            control_id="control.public.disa-windows-server-2022.wn22-cc-000020",
            title="Disable WDigest authentication",
            platform="windows",
            profiles=("server",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="DISA Windows Server 2022 STIG V2R5 WN22-CC-000020 / V-254334",
            mappings=public_mappings(stig_ids=["WN22-CC-000020"]),
        ),
    ],
)

CISA_NSA_HARDENING_PACK = pack_spec(
    filename="cisa_nsa.communications-hardening-starter.json",
    pack_id="pack.public.cisa-nsa-communications-hardening-starter",
    source_family="cisa_nsa",
    source_name="CISA NSA Communications Hardening Starter",
    source_version="2025-06",
    source_url="https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure",
    controls=[
        control_spec(
            control_id="control.public.cisa-nsa.accounts.review-least-privilege",
            title="Review accounts for least privilege",
            platform="linux",
            profiles=("server",),
            severity="high",
            disruption="minimal",
            rollback_complexity="medium",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="Enhanced Visibility and Hardening Guidance / Remove unnecessary accounts and review privileges",
            mappings=public_mappings(cisa_reference_ids=["enhanced-visibility-account-review"]),
        ),
        control_spec(
            control_id="control.public.cisa-nsa.remote-management.trusted-networks",
            title="Limit management access to trusted networks",
            platform="linux",
            profiles=("server",),
            severity="high",
            disruption="moderate",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Enhanced Visibility and Hardening Guidance / Device management from trusted networks",
            mappings=public_mappings(cisa_reference_ids=["enhanced-visibility-trusted-management"]),
        ),
        control_spec(
            control_id="control.public.cisa-nsa.ssh.disable-version-1",
            title="Disable SSH version 1",
            platform="linux",
            profiles=("server",),
            severity="critical",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="Enhanced Visibility and Hardening Guidance / Disable Secure Shell version 1",
            mappings=public_mappings(cisa_reference_ids=["enhanced-visibility-disable-ssh-v1"]),
        ),
    ],
)

SHA_IMPLEMENTED_ENDPOINT_RESPONSE_PACK = pack_spec(
    filename="sha.implemented-endpoint-response-starter.json",
    pack_id="pack.sha.implemented-endpoint-response-starter",
    source_family="sha_builtin",
    source_name="SHA Implemented Endpoint Response Starter",
    source_version="2026.06",
    source_url="https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf",
    controls=[
        control_spec(
            control_id="control.windows.defender-real-time-protection",
            title="Windows Defender real-time protection",
            platform="windows",
            profiles=("endpoint", "server"),
            severity="critical",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="SHA Windows bootstrap / Microsoft Defender Antivirus always-on protection",
            mappings=public_mappings(sp80053_ids=["SI-3", "SI-4"]),
        ),
        control_spec(
            control_id="control.windows.firewall-all-profiles",
            title="Windows firewall all profiles",
            platform="windows",
            profiles=("endpoint", "server"),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="SHA Windows bootstrap / Windows Firewall profile containment",
            mappings=public_mappings(sp80053_ids=["CM-7", "SC-7"]),
        ),
        control_spec(
            control_id="control.windows.firewall-endpoint-isolated",
            title="Windows endpoint network isolation",
            platform="windows",
            profiles=("endpoint", "server"),
            severity="critical",
            disruption="disruptive",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="CISA Incident Response Playbook containment step 7d / SHA Windows firewall isolation",
            mappings=public_mappings(sp80053_ids=["IR-4", "IR-5", "SC-7"], cisa_reference_ids=["incident-playbook-containment-7d"]),
        ),
        control_spec(
            control_id="linux.network.endpoint-isolated",
            title="Linux endpoint network isolation",
            platform="linux",
            profiles=("server",),
            severity="critical",
            disruption="disruptive",
            rollback_complexity="medium",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="CISA Incident Response Playbook containment step 7d / SHA Linux iptables isolation",
            mappings=public_mappings(sp80053_ids=["IR-4", "IR-5", "SC-7"], cisa_reference_ids=["incident-playbook-containment-7d"]),
        ),
        control_spec(
            control_id="linux.ssh.password-authentication-disabled",
            title="Linux SSH password authentication disabled",
            platform="linux",
            profiles=("server",),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=True,
            reboot_required=False,
            source_locator="SHA Linux bootstrap / SSH PasswordAuthentication hardening",
            mappings=public_mappings(sp80053_ids=["AC-17", "IA-2"]),
        ),
        control_spec(
            control_id="macos.disk.filevault-enabled",
            title="macOS FileVault enabled",
            platform="macos",
            profiles=("endpoint",),
            severity="high",
            disruption="moderate",
            rollback_complexity="medium",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="SHA macOS bootstrap / FileVault observe-only posture check",
            mappings=public_mappings(sp80053_ids=["SC-28"]),
        ),
        control_spec(
            control_id="macos.firewall.application-firewall-enabled",
            title="macOS Application Firewall enabled",
            platform="macos",
            profiles=("endpoint",),
            severity="medium",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="SHA macOS bootstrap / Application Firewall observe-only posture check",
            mappings=public_mappings(sp80053_ids=["CM-7", "SC-7"]),
        ),
        control_spec(
            control_id="macos.gatekeeper.assessments-enabled",
            title="macOS Gatekeeper assessments enabled",
            platform="macos",
            profiles=("endpoint",),
            severity="high",
            disruption="minimal",
            rollback_complexity="low",
            auto_remediation_candidate=False,
            reboot_required=False,
            source_locator="SHA macOS bootstrap / Gatekeeper observe-only posture check",
            mappings=public_mappings(sp80053_ids=["CM-7", "SI-3"]),
        ),
    ],
)

CURATED_PACK_SPECS = [
    CISA_NSA_HARDENING_PACK,
    DISA_WINDOWS_SERVER_2022_PACK,
    NIST_800_53_PACK,
    SHA_IMPLEMENTED_ENDPOINT_RESPONSE_PACK,
]
CURATED_PACK_SPECS_BY_FILENAME = {str(spec["filename"]): spec for spec in CURATED_PACK_SPECS}
CURATED_PACK_FILES = tuple(str(spec["filename"]) for spec in CURATED_PACK_SPECS)
CURATED_PACK_SPECS_BY_PACK_ID = {str(spec["pack_id"]): spec for spec in CURATED_PACK_SPECS}


def ordered_subset(values: Sequence[str], order: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return [value for value in order if value in seen]


def pack_payload(spec: dict[str, Any]) -> dict[str, Any]:
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


def catalog_payload(packs: Sequence[SourcePack]) -> dict[str, Any]:
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


def _repo_root(repo_root: Path | None) -> Path:
    if repo_root is None:
        return Path(__file__).resolve().parents[3]
    return Path(repo_root).resolve()


def _packs_dir(repo_root: Path) -> Path:
    return repo_root / "control-packs" / "packs"


def _catalog_path(repo_root: Path) -> Path:
    return repo_root / "control-packs" / "catalog.json"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is malformed JSON") from exc


def _validate_pack_against_spec(pack: SourcePack, spec: dict[str, Any]) -> None:
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
    packs = _load_curated_packs(resolved_repo_root)

    pack_ids = [pack.pack_id for pack in packs]
    control_ids = [control.control_id for pack in packs for control in pack.controls]
    if len(pack_ids) != len(set(pack_ids)):
        raise ValueError("duplicate pack_id values are not allowed")
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("duplicate control_id values are not allowed")

    catalog = SourceCatalog.model_validate(catalog_payload(packs))
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
    "build_source_catalog",
    "load_source_catalog",
    "load_source_pack",
    "pack_payload",
]
