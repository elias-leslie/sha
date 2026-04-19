from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from app.source_packs.catalog import build_source_catalog
from app.source_packs.contracts import SourceCatalog, SourcePack

PINNED_GENERATED_AT = "2026-04-18T00:00:00Z"
CANONICAL_PLATFORM_ORDER = ("windows", "linux")
CANONICAL_PROFILE_ORDER = ("domain_controller", "endpoint", "server")
LEGACY_CSV_SHA256 = "9d5fe54d92f045195cef0e8d7ebe2fc11afcd45435febc989b4ac9f4d2bbdf01"
LEGACY_SOURCE_FILENAME = "SecurityControls.csv"
LEGACY_PACK_FILENAME = "legacy-sha.snapshot.json"
LEGACY_PACK_ID = "pack.legacy-sha.snapshot"
LEGACY_SOURCE_NAME = "Legacy SHA Snapshot"
LEGACY_SOURCE_VERSION = f"sha256:{LEGACY_CSV_SHA256}"
LEGACY_SOURCE_URL = "repo://control-packs/legacy/SecurityControls.csv"
LEGACY_CONTROL_COUNT = 521


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
        "mappings": deepcopy(mappings),
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
        "controls": deepcopy(controls),
    }


def ordered_subset(values: list[str], order: tuple[str, ...]) -> list[str]:
    unique_values: list[str] = []
    for value in values:
        if value not in unique_values:
            unique_values.append(value)
    return [value for value in order if value in unique_values]


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

PACK_SPECS = [
    MICROSOFT_PACK,
    CIS_PACK,
    NIST_PACK,
    DISA_PACK,
    CISA_NSA_PACK,
]
PACK_SPEC_BY_FILENAME = {spec["filename"]: spec for spec in PACK_SPECS}
PACK_SPEC_BY_PACK_ID = {spec["pack_id"]: spec for spec in PACK_SPECS}


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


def pack_payload(spec: dict[str, object]) -> dict[str, object]:
    controls = [control_payload(spec["source_name"], control) for control in spec["controls"]]
    platform_values = [control["platform"] for control in controls]
    profile_values = [profile for control in controls for profile in control["profiles"]]
    return {
        "pack_id": spec["pack_id"],
        "source_family": spec["source_family"],
        "source_name": spec["source_name"],
        "source_version": spec["source_version"],
        "generated_at": PINNED_GENERATED_AT,
        "source_url": spec["source_url"],
        "platforms": ordered_subset(platform_values, CANONICAL_PLATFORM_ORDER),
        "profiles": ordered_subset(profile_values, CANONICAL_PROFILE_ORDER),
        "summary": f"Curated starter pack for {spec['source_name'] }.",
        "controls": controls,
    }


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repo_legacy_csv_bytes() -> bytes:
    return (repo_root() / "control-packs" / "legacy" / LEGACY_SOURCE_FILENAME).read_bytes()


def expected_catalog_dict() -> dict[str, object]:
    packs = sorted(PACK_SPECS, key=lambda spec: spec["pack_id"])
    pack_summaries = [
        {
            "pack_id": spec["pack_id"],
            "source_family": spec["source_family"],
            "source_name": spec["source_name"],
            "source_version": spec["source_version"],
            "control_count": len(spec["controls"]),
        }
        for spec in packs
    ]
    pack_summaries.append(
        {
            "pack_id": LEGACY_PACK_ID,
            "source_family": "legacy_sha",
            "source_name": LEGACY_SOURCE_NAME,
            "source_version": LEGACY_SOURCE_VERSION,
            "control_count": LEGACY_CONTROL_COUNT,
        }
    )
    pack_summaries = sorted(pack_summaries, key=lambda pack: pack["pack_id"])
    return {
        "generated_at": PINNED_GENERATED_AT,
        "pack_count": len(pack_summaries),
        "control_count": sum(len(spec["controls"]) for spec in packs) + LEGACY_CONTROL_COUNT,
        "packs": pack_summaries,
    }


def expected_catalog_text() -> str:
    return json.dumps(expected_catalog_dict(), indent=2, ensure_ascii=False) + "\n"


def write_pack_file(root: Path, spec: dict[str, object]) -> None:
    path = root / "control-packs" / "packs" / str(spec["filename"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pack_payload(spec), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_legacy_snapshot(root: Path, *, content: bytes | None = None) -> None:
    path = root / "control-packs" / "legacy" / LEGACY_SOURCE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(repo_legacy_csv_bytes() if content is None else content)


def write_workspace(
    root: Path,
    *,
    omit: set[str] | None = None,
    extra_files: dict[str, str] | None = None,
) -> None:
    omitted = omit or set()
    for spec in PACK_SPECS:
        if spec["filename"] in omitted:
            continue
        write_pack_file(root, spec)
    write_legacy_snapshot(root)
    if extra_files:
        for relative_path, content in extra_files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")


def rewrite_pack_file(root: Path, filename: str, mutator) -> None:
    path = root / "control-packs" / "packs" / filename
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutator(payload)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def test_builder_generates_expected_catalog_and_ignores_non_json_files(tmp_path: Path) -> None:
    write_workspace(
        tmp_path,
        extra_files={
            "control-packs/packs/README.txt": "ignore this non-json file\n",
            "control-packs/packs/.keep": "\n",
        },
    )

    catalog = build_source_catalog(tmp_path)
    catalog_path = tmp_path / "control-packs" / "catalog.json"
    generated_pack_path = tmp_path / "control-packs" / "generated" / LEGACY_PACK_FILENAME
    expected_text = expected_catalog_text()

    assert catalog.pack_count == 6
    assert catalog.control_count == 536
    assert catalog_path.exists()
    assert generated_pack_path.exists()
    assert catalog_path.read_text(encoding="utf-8") == expected_text
    assert catalog_path.read_bytes() == expected_text.encode("utf-8")

    parsed = SourceCatalog.model_validate_json(expected_text)
    assert parsed.generated_at == PINNED_GENERATED_AT
    assert [pack.pack_id for pack in parsed.packs] == [
        "pack.cis.windows-server-l1-starter",
        "pack.cisa_nsa.linux-ssh-starter",
        "pack.disa.windows-server-stig-starter",
        LEGACY_PACK_ID,
        "pack.microsoft.windows-security-baseline-starter",
        "pack.nist.csf-2.0-starter",
    ]

    legacy_pack = SourcePack.model_validate_json(generated_pack_path.read_text(encoding="utf-8"))
    assert legacy_pack.pack_id == LEGACY_PACK_ID
    assert legacy_pack.source_family.value == "legacy_sha"
    assert legacy_pack.source_name == LEGACY_SOURCE_NAME
    assert legacy_pack.source_version == LEGACY_SOURCE_VERSION
    assert legacy_pack.source_url == LEGACY_SOURCE_URL
    assert legacy_pack.platforms == ["windows"]
    assert legacy_pack.profiles == ["domain_controller", "endpoint", "server"]
    assert len(legacy_pack.controls) == LEGACY_CONTROL_COUNT
    assert legacy_pack.controls[0].control_id == "control.legacy-sha.snapshot.sha001"
    assert legacy_pack.controls[0].title == "Length of password history maintained"
    assert legacy_pack.controls[0].profiles == ["domain_controller", "endpoint", "server"]
    assert legacy_pack.controls[0].disruption.value == "transparent"
    assert legacy_pack.controls[0].mappings.cis_control_ids == ["4.1"]
    assert legacy_pack.controls[0].mappings.legacy_sha_ids == ["SHA001"]
    assert legacy_pack.controls[0].provenance.source_locator == "SecurityControls.csv#SHA001"
    assert legacy_pack.controls[6].control_id == "control.legacy-sha.snapshot.sha007"
    assert legacy_pack.controls[6].disruption.value == "disruptive"
    assert next(control for control in legacy_pack.controls if control.control_id == "control.legacy-sha.snapshot.sha053").profiles == [
        "domain_controller"
    ]
    assert next(control for control in legacy_pack.controls if control.control_id == "control.legacy-sha.snapshot.sha105").profiles == [
        "endpoint"
    ]

    generated_before = generated_pack_path.read_bytes()
    second_catalog = build_source_catalog(tmp_path)
    assert catalog_path.read_bytes() == expected_text.encode("utf-8")
    assert second_catalog.pack_count == catalog.pack_count
    assert second_catalog.control_count == catalog.control_count
    assert generated_pack_path.read_bytes() == generated_before


def test_builder_rejects_missing_expected_file(tmp_path: Path) -> None:
    write_workspace(tmp_path, omit={"disa.windows-server-stig-starter.json"})

    catalog_path = tmp_path / "control-packs" / "catalog.json"
    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    assert not catalog_path.exists()


def test_builder_rejects_hash_drifted_legacy_snapshot_and_preserves_existing_outputs(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    build_source_catalog(tmp_path)

    catalog_path = tmp_path / "control-packs" / "catalog.json"
    generated_pack_path = tmp_path / "control-packs" / "generated" / LEGACY_PACK_FILENAME
    legacy_csv_path = tmp_path / "control-packs" / "legacy" / LEGACY_SOURCE_FILENAME
    catalog_before = catalog_path.read_bytes()
    generated_before = generated_pack_path.read_bytes()
    legacy_bytes = bytearray(legacy_csv_path.read_bytes())
    legacy_bytes[0] = (legacy_bytes[0] + 1) % 255
    legacy_csv_path.write_bytes(bytes(legacy_bytes))

    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    assert catalog_path.read_bytes() == catalog_before
    assert generated_pack_path.read_bytes() == generated_before


def test_builder_rejects_extra_json_files(tmp_path: Path) -> None:
    write_workspace(
        tmp_path,
        extra_files={
            "control-packs/packs/extra.curated.json": "{}\n",
            "control-packs/packs/EXTRA.JSON": "{}\n",
            "control-packs/packs/nested/evil.json": "{}\n",
        },
    )

    catalog_path = tmp_path / "control-packs" / "catalog.json"
    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    assert not catalog_path.exists()


def test_builder_rejects_malformed_json_and_preserves_existing_catalog_bytes(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    build_source_catalog(tmp_path)
    catalog_path = tmp_path / "control-packs" / "catalog.json"
    before = catalog_path.read_bytes()

    malformed_path = tmp_path / "control-packs" / "packs" / "nist.csf-2.0-starter.json"
    malformed_path.write_text("{\n  \"broken\": true,,\n}\n", encoding="utf-8")

    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    assert catalog_path.read_bytes() == before


@pytest.mark.parametrize(
    ("filename", "mutator"),
    [
        (
            "microsoft.windows-security-baseline-starter.json",
            lambda payload: payload["controls"].__setitem__(0, {**payload["controls"][0], "title": "Wrong title"}),
        ),
        (
            "cis.windows-server-l1-starter.json",
            lambda payload: payload["controls"].__setitem__(
                2,
                {
                    **payload["controls"][2],
                    "control_id": "control.microsoft-windows-security-baseline-starter.password-history",
                },
            ),
        ),
        (
            "microsoft.windows-security-baseline-starter.json",
            lambda payload: payload["controls"].__setitem__(
                1,
                {
                    **payload["controls"][1],
                    "control_id": payload["controls"][0]["control_id"],
                },
            ),
        ),
        (
            "nist.csf-2.0-starter.json",
            lambda payload: payload.__setitem__("profiles", ["domain_controller", "server"]),
        ),
        (
            "disa.windows-server-stig-starter.json",
            lambda payload: payload.__setitem__("controls", list(reversed(payload["controls"]))),
        ),
    ],
)
def test_builder_rejects_inventory_and_shape_drift(
    tmp_path: Path,
    filename: str,
    mutator,
) -> None:
    write_workspace(tmp_path)
    rewrite_pack_file(tmp_path, filename, mutator)

    catalog_path = tmp_path / "control-packs" / "catalog.json"
    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    assert not catalog_path.exists()


def test_builder_rejects_duplicate_pack_ids_and_duplicate_control_ids_across_and_within_packs(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    rewrite_pack_file(
        tmp_path,
        "cis.windows-server-l1-starter.json",
        lambda payload: payload.__setitem__("pack_id", "pack.microsoft.windows-security-baseline-starter"),
    )
    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    write_workspace(tmp_path)
    rewrite_pack_file(
        tmp_path,
        "cis.windows-server-l1-starter.json",
        lambda payload: payload["controls"].__setitem__(
            2,
            {
                **payload["controls"][2],
                "control_id": "control.microsoft-windows-security-baseline-starter.password-history",
            },
        ),
    )
    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)

    write_workspace(tmp_path)
    rewrite_pack_file(
        tmp_path,
        "microsoft.windows-security-baseline-starter.json",
        lambda payload: payload["controls"].__setitem__(
            1,
            {
                **payload["controls"][1],
                "control_id": payload["controls"][0]["control_id"],
            },
        ),
    )
    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)


def test_builder_rejects_symlinked_curated_pack_files(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    target = tmp_path / "control-packs" / "packs" / "microsoft.windows-security-baseline-starter.json"
    replacement = tmp_path / "outside.json"
    replacement.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
    target.unlink()
    target.symlink_to(replacement)

    with pytest.raises(ValueError):
        build_source_catalog(tmp_path)
