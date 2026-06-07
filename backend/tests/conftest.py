from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "sha.sqlite3"


@pytest.fixture
def make_client():
    contexts: list[TestClient] = []

    def _make(db_path: Path) -> TestClient:
        context = TestClient(create_app(database_url=f"sqlite:///{db_path}"))
        contexts.append(context)
        return context.__enter__()

    yield _make

    while contexts:
        context = contexts.pop()
        context.__exit__(None, None, None)
