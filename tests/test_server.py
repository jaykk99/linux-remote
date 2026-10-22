"""Tests for linux-remote server.py.

Run:  python3 -m pytest tests/ -q
"""

import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402

TEST_KEY = "test-key-12345"


@pytest.fixture()
def tmp_home(tmp_path, monkeypatch):
    """Isolate key/log/workdir state per test."""
    data = tmp_path / "data"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(server, "DATA_DIR", data)
    monkeypatch.setattr(server, "KEY_FILE", data / "key")
    monkeypatch.setattr(server, "LOG_FILE", data / "commands.log")
    monkeypatch.setattr(server, "BASE_DIR", work)
    monkeypatch.setattr(server, "API_KEY", TEST_KEY)
    server.reset_rate_limiter()
    return tmp_path


@pytest.fixture()
def client(tmp_home):
    return TestClient(server.app)


def auth(key=TEST_KEY):
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def test_health_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["service"] == "linux-remote"
    assert "version" in body and "host" in body and "uptime_s" in body


# ---------------------------------------------------------------------------
# auth + rate limiting
# ---------------------------------------------------------------------------

def test_exec_rejects_missing_key(client):
    r = client.post("/exec", json={"command": "echo hi"})
    assert r.status_code == 401


def test_exec_rejects_wrong_key(client):
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth("nope"))
    assert r.status_code == 401


def test_rate_limit_kicks_in(client, monkeypatch):
    monkeypatch.setattr(server, "RATE_LIMIT", 3)
    monkeypatch.setattr(server, "RATE_WINDOW", 60)
    for _ in range(3):
        r = client.post("/exec", json={"command": "echo hi"}, headers=auth("nope"))
        assert r.status_code == 401
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth("nope"))
    assert r.status_code == 429
    # Even the right key is blocked while the IP is rate limited.
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth())
    assert r.status_code == 429


def test_successful_auth_clears_failures(client, monkeypatch):
    monkeypatch.setattr(server, "RATE_LIMIT", 3)
    monkeypatch.setattr(server, "RATE_WINDOW", 60)
    for _ in range(2):
        client.post("/exec", json={"command": "echo hi"}, headers=auth("nope"))
    r = client.post("/exec", json={"command": "echo ok"}, headers=auth())
    assert r.status_code == 200
    # Counter was cleared: two more failures do not trip the limit.
    for _ in range(2):
        r = client.post("/exec", json={"command": "echo hi"}, headers=auth("nope"))
        assert r.status_code == 401


def test_body_size_limit(client, monkeypatch):
    monkeypatch.setattr(server, "MAX_BODY_BYTES", 100)
    big = "x" * 10_000
    r = client.post("/exec", json={"command": big}, headers=auth())
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# exec basics
# ---------------------------------------------------------------------------

def test_exec_echo(client):
    r = client.post("/exec", json={"command": "echo hello"}, headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["stdout"].strip() == "hello"
    assert body["exit_code"] == 0
    assert body["truncated"] is False
    assert body["duration_ms"] >= 0


def test_exec_exit_code_and_stderr(client):
    r = client.post(
        "/exec",
        json={"command": "echo oops >&2; exit 3"},
        headers=auth(),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["exit_code"] == 3
    assert "oops" in body["stderr"]


def test_exec_empty_command(client):
    r = client.post("/exec", json={"command": "   "}, headers=auth())
    assert r.status_code == 400


def test_exec_timeout(client, monkeypatch):
    monkeypatch.setattr(server, "COMMAND_TIMEOUT", 2)
    r = client.post("/exec", json={"command": "sleep 30"}, headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["exit_code"] == 124
    assert "timed out" in body["stderr"]


def test_exec_output_truncation(client, monkeypatch):
    monkeypatch.setattr(server, "MAX_OUTPUT_BYTES", 200)
    r = client.post(
        "/exec",
        json={"command": "python3 -c \"print('x' * 100000)\""},
        headers=auth(),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["truncated"] is True
    assert len(body["stdout"].encode()) <= 200 + 200  # cap + notice
    assert "truncated" in body["stdout"]


def test_exec_timeout_override_shorter(client):
    r = client.post(
        "/exec", json={"command": "sleep 30", "timeout_s": 1}, headers=auth()
    )
    assert r.status_code == 200
    body = r.json()
    assert body["exit_code"] == 124
    assert "timed out" in body["stderr"]


def test_exec_timeout_override_cannot_exceed_server_max(client, monkeypatch):
    monkeypatch.setattr(server, "COMMAND_TIMEOUT", 2)
    started = time.time()
    r = client.post(
        "/exec", json={"command": "sleep 30", "timeout_s": 9999}, headers=auth()
    )
    elapsed = time.time() - started
    assert r.status_code == 200
    assert r.json()["exit_code"] == 124
    assert elapsed < 15  # clamped to the 2s server ceiling, not 9999s


def test_exec_timeout_override_rejects_zero(client):
    r = client.post(
        "/exec", json={"command": "echo hi", "timeout_s": 0}, headers=auth()
    )
    assert r.status_code == 422


def test_exec_concurrent_streams_no_deadlock(client, monkeypatch):
    """A chatty stderr must not deadlock a chatty stdout."""
    monkeypatch.setattr(server, "MAX_OUTPUT_BYTES", 10_000_000)
    cmd = (
        "python3 -c \""
        "import sys; "
        "[print('o' * 1000) or print('e' * 1000, file=sys.stderr) for _ in range(2000)]"
        "\""
    )
    r = client.post("/exec", json={"command": cmd}, headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["exit_code"] == 0
    assert body["stdout"].count("o" * 1000) == 2000
    assert body["stderr"].count("e" * 1000) == 2000


# ---------------------------------------------------------------------------
# cwd handling
# ---------------------------------------------------------------------------

def test_exec_cwd_subdir(client, tmp_home):
    sub = tmp_home / "work" / "proj"
    sub.mkdir()
    r = client.post("/exec", json={"command": "pwd", "cwd": "proj"}, headers=auth())
    assert r.status_code == 200
    assert r.json()["stdout"].strip().endswith("proj")


def test_exec_cwd_escape_blocked(client):
    r = client.post("/exec", json={"command": "pwd", "cwd": "../../.."}, headers=auth())
    assert r.status_code == 400


def test_exec_cwd_absolute_outside_base_blocked(client, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    r = client.post(
        "/exec", json={"command": "pwd", "cwd": str(outside)}, headers=auth()
    )
    assert r.status_code == 400


def test_exec_cwd_not_a_dir(client):
    r = client.post(
        "/exec", json={"command": "pwd", "cwd": "no-such-dir"}, headers=auth()
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# destructive-command denylist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -rf / ",
        "sudo rm -rf /tmp/..;/bin/rm -rf /",
        "rm -rf ~",
        "rm -rf ~/",
        "rm -rf $HOME",
        "rm -rf $HOME/",
        'rm -rf "$HOME"',
        "rm -rf ${HOME}",
        "rm -rf ${HOME}/",
        "sudo rm -rf $HOME",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "mkfs.ext4 /dev/sda1",
        ":(){ :|:& };:",
        "sudo reboot",
        "shutdown -h now",
        "echo hi > /dev/sda",
        "shred -u /dev/sdb",
    ],
)
def test_dangerous_blocked(client, command):
    assert server.check_dangerous(command) is not None
    r = client.post("/exec", json={"command": command}, headers=auth())
    assert r.status_code == 403


@pytest.mark.parametrize(
    "command",
    [
        "echo hello",
        "ls -la /tmp",
        "rm -rf /tmp/my-scratch-dir",
        "rm -rf $HOME/cache",
        "rm -rf ~/projects/scratch",
        "echo $HOME",
        "rm /tmp/some-file",
        "df -h",
        "dd if=/dev/zero of=/tmp/test.img bs=1M count=1",
        "grep -r reboot /tmp",
        "echo shutdown",
    ],
)
def test_benign_allowed(client, command):
    assert server.check_dangerous(command) is None


def test_dangerous_override_env(monkeypatch):
    monkeypatch.setattr(server, "ALLOW_DANGEROUS", True)
    assert server.check_dangerous("rm -rf /") is None


# ---------------------------------------------------------------------------
# key rotation
# ---------------------------------------------------------------------------

def test_rotate_key(client, tmp_home):
    r = client.post("/rotate-key", headers=auth())
    assert r.status_code == 200
    new_key = r.json()["api_key"]
    assert new_key and new_key != TEST_KEY
    # Old key dead, new key works.
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth())
    assert r.status_code == 401
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth(new_key))
    assert r.status_code == 200
    # Key file updated with 0600 perms.
    saved = (tmp_home / "data" / "key").read_text().strip()
    assert saved == new_key
    assert oct((tmp_home / "data" / "key").stat().st_mode & 0o777) == "0o600"


def test_rotate_key_requires_auth(client):
    r = client.post("/rotate-key", headers=auth("wrong"))
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------

def test_commands_are_logged(client, tmp_home):
    client.post("/exec", json={"command": "echo one"}, headers=auth())
    client.post("/exec", json={"command": "exit 7"}, headers=auth())
    log = (tmp_home / "data" / "commands.log").read_text()
    assert "cmd=echo one" in log
    assert "exit=0" in log
    assert "exit=7" in log
    assert "ip=" in log and "dur_ms=" in log


def test_log_escapes_newlines(client, tmp_home):
    client.post("/exec", json={"command": "echo a\necho b"}, headers=auth())
    lines = (tmp_home / "data" / "commands.log").read_text().strip().split("\n")
    # One command -> one log line, newlines escaped.
    assert len(lines) == 1
    assert "\\n" in lines[0]


def test_log_rotation(client, tmp_home, monkeypatch):
    monkeypatch.setattr(server, "LOG_MAX_BYTES", 50)
    (tmp_home / "data").mkdir(parents=True, exist_ok=True)
    (tmp_home / "data" / "commands.log").write_text("x" * 100 + "\n")
    client.post("/exec", json={"command": "echo hi"}, headers=auth())
    assert (tmp_home / "data" / "commands.log.1").exists()
    assert "cmd=echo hi" in (tmp_home / "data" / "commands.log").read_text()


def test_recent_endpoint(client):
    client.post("/exec", json={"command": "echo first"}, headers=auth())
    client.post("/exec", json={"command": "echo second"}, headers=auth())
    r = client.get("/recent?n=10", headers=auth())
    assert r.status_code == 200
    lines = r.json()["lines"]
    assert len(lines) == 2
    assert "second" in lines[0]  # newest first
    assert "first" in lines[1]


def test_recent_requires_auth(client):
    r = client.get("/recent", headers=auth("wrong"))
    assert r.status_code == 401


def test_recent_empty_log(client):
    r = client.get("/recent", headers=auth())
    assert r.status_code == 200
    assert r.json()["lines"] == []


# ---------------------------------------------------------------------------
# key file handling
# ---------------------------------------------------------------------------

def test_get_or_create_key_roundtrip(tmp_path, monkeypatch):
    data = tmp_path / "kd"
    monkeypatch.setattr(server, "DATA_DIR", data)
    monkeypatch.setattr(server, "KEY_FILE", data / "key")
    key1, is_new1 = server.get_or_create_key()
    assert is_new1 is True and len(key1) > 20
    key2, is_new2 = server.get_or_create_key()
    assert is_new2 is False and key2 == key1
    assert oct((data / "key").stat().st_mode & 0o777) == "0o600"
    assert oct(data.stat().st_mode & 0o777) == "0o700"
