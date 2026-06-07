from __future__ import annotations

import sqlite3

EXPECTED_HEALTH = {
    "status": "ok",
    "service": "sha-backend",
    "version": "0.1.0",
}

EXPECTED_TABLES = {
    "approval_grants",
    "endpoints",
    "installer_profiles",
    "posture_results",
    "posture_snapshots",
}


def test_health_endpoint_returns_exact_contract(db_path, make_client):
    client = make_client(db_path)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == EXPECTED_HEALTH


def test_startup_creates_database_and_required_tables(db_path, make_client):
    assert not db_path.exists()

    client = make_client(db_path)
    client.get("/health")

    assert db_path.exists()
    with sqlite3.connect(db_path) as connection:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert EXPECTED_TABLES.issubset(table_names)
