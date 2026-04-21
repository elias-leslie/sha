# SHA shared schemas

Shared contracts between the SHA control plane, the SHA agent, and SHAna orchestration layers.

## Generated contract exports

Machine-readable JSON Schema exports live under `schemas/generated/`.
These files are derived from the FastAPI/Pydantic contract models in `backend/app/schemas/contracts.py` and give future agent implementations a stable, repo-local source of truth for request/response shapes.

Regenerate them with:

- `cd backend && uv run python scripts/export_contract_schemas.py`

The generated set currently covers:

- endpoint enroll request/response
- endpoint heartbeat request/ack
- endpoint inventory/detail responses
- posture snapshot request/ack
- installer profile create/list/response contracts
- approval request create/decision/list/response contracts
- approval grant create/list/response contracts

`schemas/generated/manifest.json` records the exported filenames and source model names so downstream tooling can discover the bundle deterministically.
