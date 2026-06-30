# SHA shared schemas

Shared contracts between the SHA control plane, the endpoint agent boundary, and optional operator-automation layers.

Machine-readable JSON Schema exports live under `schemas/generated/`.
These files are derived from the FastAPI/Pydantic contract models in `backend/app/schemas/contracts.py` and give future agent implementations a stable, repo-local source of truth for request/response shapes.

Regenerate them with:

```bash
cd backend
uv run python scripts/export_contract_schemas.py
```

The generated set covers endpoint enrollment, heartbeat, inventory/detail, posture snapshots, installer profiles, approval requests/grants, and response actions. `schemas/generated/manifest.json` records exported filenames and source model names.
