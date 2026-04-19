from __future__ import annotations


def test_source_pack_catalog_endpoint_returns_generated_catalog(db_path, make_client) -> None:
    client = make_client(db_path)

    response = client.get("/api/source-packs")

    assert response.status_code == 200
    payload = response.json()
    assert payload["generated_at"] == "2026-04-18T00:00:00Z"
    assert payload["pack_count"] == 6
    assert payload["control_count"] == 536
    assert payload["packs"][3] == {
        "pack_id": "pack.legacy-sha.snapshot",
        "source_family": "legacy_sha",
        "source_name": "Legacy SHA Snapshot",
        "source_version": "sha256:9d5fe54d92f045195cef0e8d7ebe2fc11afcd45435febc989b4ac9f4d2bbdf01",
        "control_count": 521,
    }



def test_source_pack_detail_endpoint_returns_generated_legacy_pack(db_path, make_client) -> None:
    client = make_client(db_path)

    response = client.get("/api/source-packs/pack.legacy-sha.snapshot")

    assert response.status_code == 200
    payload = response.json()
    assert payload["pack_id"] == "pack.legacy-sha.snapshot"
    assert payload["source_family"] == "legacy_sha"
    assert payload["source_name"] == "Legacy SHA Snapshot"
    assert payload["source_version"] == "sha256:9d5fe54d92f045195cef0e8d7ebe2fc11afcd45435febc989b4ac9f4d2bbdf01"
    assert payload["source_url"] == "repo://control-packs/legacy/SecurityControls.csv"
    assert payload["platforms"] == ["windows"]
    assert payload["profiles"] == ["domain_controller", "endpoint", "server"]
    assert len(payload["controls"]) == 521
    assert payload["controls"][0]["control_id"] == "control.legacy-sha.snapshot.sha001"
    assert payload["controls"][0]["title"] == "Length of password history maintained"
    assert payload["controls"][0]["provenance"]["source_locator"] == "SecurityControls.csv#SHA001"
    assert payload["controls"][0]["mappings"]["legacy_sha_ids"] == ["SHA001"]
