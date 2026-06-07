# Curated starter source packs

This directory is the local, file-backed source-pack workspace for the SHA starter catalog slice.

What lives here:
- `packs/` contains the three authoritative curated starter JSON inputs.
- `catalog.json` is the generated summary manifest built from those curated inputs.

Public-source inputs represented in this slice:
- NIST SP 800-53 Rev. 5 OSCAL catalog.
- DISA Microsoft Windows Server 2022 STIG V2R5.
- CISA/NSA Enhanced Visibility and Hardening Guidance for Communications Infrastructure.

Rules for this slice:
- Curated pack files are authoritative inputs and are validated in place.
- The builder never rewrites curated pack JSON files.
- Non-JSON files under `packs/` are ignored.
- Unexpected extra JSON files under `packs/` fail validation.
- The slice is deterministic and local only: no live scraping and no out-of-repo dependency during normal builder reruns or API reads.
- CIS Benchmark and Microsoft baseline content are citation-only future references unless licensing allows reproduction.

Regenerate the catalog from the repo root with:
- `uv run --directory backend python scripts/build_source_catalog.py`

Or from `backend/`:
- `uv run python scripts/build_source_catalog.py`
