from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from app.source_packs import catalog as catalog_module
from app.source_packs.catalog import CURATED_PACK_SPECS, build_source_catalog, catalog_payload, pack_payload
from app.source_packs.contracts import SourceCatalog, SourcePack


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def write_pack_files(root: Path, specs: list[dict[str, Any]] | None = None) -> None:
    packs_dir = root / "control-packs" / "packs"
    packs_dir.mkdir(parents=True, exist_ok=True)
    for spec in specs or CURATED_PACK_SPECS:
        payload = pack_payload(spec)
        path = packs_dir / str(spec["filename"])
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def copy_workspace(tmp_path: Path) -> Path:
    root = tmp_path
    write_pack_files(root)
    catalog_source = repo_root() / "control-packs" / "catalog.json"
    catalog_dest = root / "control-packs" / "catalog.json"
    catalog_dest.write_text(catalog_source.read_text(encoding="utf-8"), encoding="utf-8")
    return root


def expected_catalog() -> SourceCatalog:
    packs = [SourcePack.model_validate(pack_payload(spec)) for spec in CURATED_PACK_SPECS]
    return SourceCatalog.model_validate(catalog_payload(packs))


def test_builder_generates_expected_catalog_and_ignores_non_json_files(tmp_path: Path) -> None:
    root = copy_workspace(tmp_path)
    (root / "control-packs" / "packs" / "README.txt").write_text("ignored\n", encoding="utf-8")

    catalog = build_source_catalog(root)

    assert catalog == expected_catalog()
    assert catalog.pack_count == 4
    assert catalog.control_count == 17
    assert not (root / "control-packs" / "generated").exists()
    assert (root / "control-packs" / "catalog.json").read_text(encoding="utf-8") == (
        json.dumps(catalog.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
    )


def test_builder_rejects_missing_expected_file(tmp_path: Path) -> None:
    root = copy_workspace(tmp_path)
    (root / "control-packs" / "packs" / str(CURATED_PACK_SPECS[0]["filename"])).unlink()

    with pytest.raises(ValueError, match="missing curated JSON"):
        build_source_catalog(root)


def test_builder_rejects_extra_json_files(tmp_path: Path) -> None:
    root = copy_workspace(tmp_path)
    (root / "control-packs" / "packs" / "extra.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected curated JSON"):
        build_source_catalog(root)


def test_builder_rejects_malformed_json_and_preserves_existing_catalog_bytes(tmp_path: Path) -> None:
    root = copy_workspace(tmp_path)
    catalog_path = root / "control-packs" / "catalog.json"
    original_bytes = b"existing catalog bytes\n"
    catalog_path.write_bytes(original_bytes)
    (root / "control-packs" / "packs" / str(CURATED_PACK_SPECS[0]["filename"])).write_text("{\n", encoding="utf-8")

    with pytest.raises(ValueError, match="malformed JSON"):
        build_source_catalog(root)

    assert catalog_path.read_bytes() == original_bytes


def test_builder_rejects_inventory_drift_and_preserves_existing_catalog_bytes(tmp_path: Path) -> None:
    root = copy_workspace(tmp_path)
    catalog_path = root / "control-packs" / "catalog.json"
    original_bytes = catalog_path.read_bytes()
    path = root / "control-packs" / "packs" / str(CURATED_PACK_SPECS[0]["filename"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["controls"][0]["title"] = "Changed title"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="pinned curated starter inventory|failed validation"):
        build_source_catalog(root)

    assert catalog_path.read_bytes() == original_bytes


def patch_catalog_specs(monkeypatch: pytest.MonkeyPatch, specs: list[dict[str, Any]]) -> None:
    monkeypatch.setattr(catalog_module, "CURATED_PACK_SPECS", specs)
    monkeypatch.setattr(catalog_module, "CURATED_PACK_FILES", tuple(spec["filename"] for spec in specs))
    monkeypatch.setattr(catalog_module, "CURATED_PACK_SPECS_BY_FILENAME", {spec["filename"]: spec for spec in specs})
    monkeypatch.setattr(catalog_module, "CURATED_PACK_SPECS_BY_PACK_ID", {str(spec["pack_id"]): spec for spec in specs})


def test_builder_rejects_duplicate_pack_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    specs = deepcopy(CURATED_PACK_SPECS)
    specs[1]["pack_id"] = specs[0]["pack_id"]
    patch_catalog_specs(monkeypatch, specs)
    write_pack_files(tmp_path, specs)

    with pytest.raises(ValueError, match="duplicate pack_id"):
        build_source_catalog(tmp_path)


def test_builder_rejects_duplicate_control_ids_across_packs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    specs = deepcopy(CURATED_PACK_SPECS)
    specs[1]["controls"][0]["control_id"] = specs[0]["controls"][0]["control_id"]
    patch_catalog_specs(monkeypatch, specs)
    write_pack_files(tmp_path, specs)

    with pytest.raises(ValueError, match="duplicate control_id"):
        build_source_catalog(tmp_path)


def test_builder_rejects_symlinked_curated_pack_files(tmp_path: Path) -> None:
    root = copy_workspace(tmp_path)
    path = root / "control-packs" / "packs" / str(CURATED_PACK_SPECS[0]["filename"])
    target = root / "control-packs" / "symlink-target.json"
    target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    path.unlink()
    path.symlink_to(target)

    with pytest.raises(ValueError, match="curated pack must be a regular file"):
        build_source_catalog(root)
