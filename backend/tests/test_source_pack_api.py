from __future__ import annotations


def test_source_pack_catalog_endpoint_returns_generated_catalog(db_path, make_client) -> None:
    client = make_client(db_path)

    response = client.get("/api/source-packs")

    assert response.status_code == 200
    payload = response.json()
    assert payload["generated_at"] == "2026-04-18T00:00:00Z"
    assert payload["pack_count"] == 3
    assert payload["control_count"] == 9
    assert [pack["pack_id"] for pack in payload["packs"]] == [
        "pack.public.cisa-nsa-communications-hardening-starter",
        "pack.public.disa-windows-server-2022-v2r5-starter",
        "pack.public.nist-800-53-rev5-starter",
    ]


def test_source_pack_detail_endpoint_returns_clean_public_pack(db_path, make_client) -> None:
    client = make_client(db_path)

    response = client.get("/api/source-packs/pack.public.nist-800-53-rev5-starter")

    assert response.status_code == 200
    payload = response.json()
    assert payload["pack_id"] == "pack.public.nist-800-53-rev5-starter"
    assert payload["source_family"] == "nist_800_53"
    assert payload["source_name"] == "NIST SP 800-53 Rev. 5 Starter"
    assert payload["source_version"] == "5.2.0"
    assert payload["source_url"].startswith("https://raw.githubusercontent.com/usnistgov/oscal-content/")
    assert payload["platforms"] == ["windows", "linux"]
    assert payload["profiles"] == ["domain_controller", "endpoint", "server"]
    assert len(payload["controls"]) == 3
    assert payload["controls"][0]["control_id"] == "control.public.nist-800-53.ac-17"
    assert payload["controls"][0]["title"] == "Remote Access"
    assert payload["controls"][0]["provenance"]["source_locator"] == "NIST SP 800-53 Rev. 5 control AC-17"
    assert payload["controls"][0]["mappings"]["sp80053_ids"] == ["AC-17"]
