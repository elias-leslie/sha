from __future__ import annotations

import subprocess

from app import utils as utils_module


def _enroll_endpoint(client) -> str:
    response = client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": "linux-terminal-agent",
            "hostname": "linux-term-01",
            "platform": "linux",
            "platform_version": "Ubuntu 24.04",
            "agent_version": "agent-test",
        },
    )
    assert response.status_code == 201
    return response.json()["endpoint_id"]


def _capture_runs(monkeypatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _execute(client, endpoint_id: str, command: str) -> dict[str, object]:
    response = client.post(f"/api/endpoints/{endpoint_id}/terminal/execute", json={"command": command})
    assert response.status_code == 200
    return response.json()


def test_allowlisted_command_runs_server_defined_argv(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = _enroll_endpoint(client)
    calls = _capture_runs(monkeypatch)

    body = _execute(client, endpoint_id, "  uname   -a ")

    assert calls == [["uname", "-a"]]
    assert body["stdout"] == "ok\n"
    assert body["exit_code"] == 0


def test_allowlisted_prefix_with_extra_arguments_never_reaches_subprocess(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = _enroll_endpoint(client)
    calls = _capture_runs(monkeypatch)

    for command in ("cat /etc/os-release /etc/shadow", "date -s 2000-01-01", "ip link set eth0 down"):
        body = _execute(client, endpoint_id, command)
        assert "sent over SHA agent tunnel" in str(body["stdout"])

    assert calls == []


def test_echo_is_answered_without_subprocess(db_path, make_client, monkeypatch):
    client = make_client(db_path)
    endpoint_id = _enroll_endpoint(client)
    calls = _capture_runs(monkeypatch)

    body = _execute(client, endpoint_id, "echo hello world")

    assert calls == []
    assert body["stdout"] == "hello world\n"
    assert body["exit_code"] == 0


def test_execution_errors_do_not_expose_exception_details(monkeypatch):
    def failing_run(cmd, **kwargs):
        raise OSError("secret internal path /srv/private/thing")

    monkeypatch.setattr(subprocess, "run", failing_run)

    stdout, stderr, exit_code = utils_module.safe_subprocess(["uname"])

    assert stdout == ""
    assert exit_code == 1
    assert "/srv/private" not in stderr
    assert stderr == "Execution error: command could not be run"
