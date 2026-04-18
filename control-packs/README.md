# Curated starter source packs

This directory is the local, file-backed source-pack workspace for the SHA starter catalog slice.

What lives here:
- `packs/` contains the five authoritative curated starter JSON inputs.
- `catalog.json` is the generated summary manifest built from those inputs.

Rules for this slice:
- Curated pack files are authoritative inputs and are validated in place.
- The builder never rewrites curated pack JSON files.
- Non-JSON files under `packs/` are ignored.
- Unexpected extra JSON files under `packs/` fail validation.
- The slice is deterministic and local only: no live scraping, no legacy CSV import, no service startup.

Regenerate the catalog from the repo root with:
- `uv run --directory backend python scripts/build_source_catalog.py`

Or from `backend/`:
- `uv run python scripts/build_source_catalog.py`
