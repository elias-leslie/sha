# Curated starter source packs

This directory is the local, file-backed source-pack workspace for the SHA starter catalog slice.

What lives here:
- `packs/` contains the five authoritative curated starter JSON inputs.
- `legacy/SecurityControls.csv` is the checked-in legacy SHA CSV snapshot pinned to SHA256 `9d5fe54d92f045195cef0e8d7ebe2fc11afcd45435febc989b4ac9f4d2bbdf01`.
- `generated/legacy-sha.snapshot.json` is the deterministic legacy pack generated from that CSV snapshot.
- `catalog.json` is the generated summary manifest built from the curated inputs plus the generated legacy pack.

Rules for this slice:
- Curated pack files are authoritative inputs and are validated in place.
- The builder never rewrites curated pack JSON files.
- The legacy CSV snapshot is repo-local and hash-verified before import.
- The builder regenerates `generated/legacy-sha.snapshot.json` deterministically from the repo-local CSV snapshot.
- Non-JSON files under `packs/` are ignored.
- Unexpected extra JSON files under `packs/` fail validation.
- The slice is deterministic and local only: no live scraping and no out-of-repo dependency during normal builder reruns or API reads.

Regenerate the catalog from the repo root with:
- `uv run --directory backend python scripts/build_source_catalog.py`

Or from `backend/`:
- `uv run python scripts/build_source_catalog.py`
