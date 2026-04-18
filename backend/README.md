# SHA backend

FastAPI control-plane foundation for endpoint enrollment, posture snapshot uploads, installer profiles, and approval grants.

Local development:
- uv sync
- uv run uvicorn app.main:app --reload --port 8010

SQLite defaults to `data/sha.sqlite3` when running inside `backend/` (repo path `backend/data/sha.sqlite3`) and is created automatically on startup.
This slice does not include any /api/endpoints list or detail routes.
