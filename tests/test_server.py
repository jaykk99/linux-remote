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

@pytest.mark.parametrize(
    "command",
    [
        "rm -rf / --no-preserve-root",
        "rm -rf /*",
        "rm -rf / *",
        "sudo rm -rf /",
        "sudo rm -rf /* --no-preserve-root",
        "sudo rm -rf /tmp/..; rm -rf /",
        "rm -rf $HOME/*",
        "rm -rf ~/*",
        'rm -rf "$HOME"/*',
        "rm -rf '$HOME'/*",
        "rm -rf $HOME/..",
        "rm -rf ~/../",
        'rm -rf "$HOME"/..',
        "rm -rf ${HOME}/..",
        "sudo rm -rf $HOME/*",
    ],
)
def test_dangerous_blocked_v13(client, command):
    assert server.check_dangerous(command) is not None
    r = client.post("/exec", json={"command": command}, headers=auth())
    assert r.status_code == 403


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /tmp/my-scratch-dir",
        "rm -rf $HOME/cache",
        "rm -rf ~/.cache/*",
        "rm -rf ~/projects/scratch",
        "rm -rf $HOME/.cache",
        "ls /",
        "df -h /",
        "echo /",
        "grep -r / /tmp/x",
    ],
)
def test_benign_still_allowed_v13(client, command):
    assert server.check_dangerous(command) is None


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

def test_stats_empty_log(client):
    r = client.get("/stats", headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["total_commands"] == 0
    assert body["successful"] == 0
    assert body["failed"] == 0
    assert body["blocked"] == 0
    assert body["success_rate"] is None
    assert body["avg_duration_ms"] is None
    assert body["top_commands"] == []
    assert body["per_day"] == {}


def test_stats_counts(client):
    client.post("/exec", json={"command": "echo one"}, headers=auth())
    client.post("/exec", json={"command": "echo two"}, headers=auth())
    client.post("/exec", json={"command": "exit 7"}, headers=auth())
    client.post("/exec", json={"command": "rm -rf /"}, headers=auth())  # 403
    r = client.get("/stats", headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["total_commands"] == 4
    assert body["successful"] == 2
    assert body["failed"] == 1
    assert body["blocked"] == 1
    assert body["success_rate"] == 0.5
    assert body["avg_duration_ms"] is not None and body["avg_duration_ms"] >= 0
    tops = {t["command"]: t["count"] for t in body["top_commands"]}
    assert tops.get("echo") == 2
    assert tops.get("exit") == 1
    assert tops.get("rm") == 1
    today = __import__("datetime").date.today().isoformat()
    assert body["per_day"].get(today) == 4


def test_stats_sudo_collapses_to_base_command():
    lines = [
        "[2026-10-23T07:00:00] ip=1.2.3.4 cwd=/x dur_ms=10 exit=0 cmd=sudo apt update",
        "[2026-10-23T07:00:01] ip=1.2.3.4 cwd=/x dur_ms=10 exit=0 cmd=BLOCKED(recursive delete rooted at /): sudo rm -rf /",
        "[2026-10-23T07:00:02] ip=1.2.3.4 cwd=/x dur_ms=10 exit=1 cmd=not-a-real-cmd",
        "this line is garbage and must be skipped",
    ]
    s = server.compute_stats(lines)
    assert s["total_commands"] == 3
    assert s["successful"] == 1
    assert s["failed"] == 1
    assert s["blocked"] == 1
    tops = {t["command"]: t["count"] for t in s["top_commands"]}
    assert tops == {"apt": 1, "rm": 1, "not-a-real-cmd": 1}
    assert s["avg_duration_ms"] == 10.0  # blocked line excluded from average


def test_stats_requires_auth(client):
    r = client.get("/stats", headers=auth("wrong"))
    assert r.status_code == 401


def test_stats_limit_clamped(client):
    for _ in range(3):
        client.post("/exec", json={"command": "echo hi"}, headers=auth())
    r = client.get("/stats?n=5000", headers=auth())  # clamped to 2000
    assert r.status_code == 200
    assert r.json()["total_commands"] == 3


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


# ---------------------------------------------------------------------------
# v1.4.0: parent-traversal deletes, find -delete, recursive perms,
# workdir-root wipes, and the /exec concurrency cap
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "command",
    [
        # Parent-dir deletes (v1.3.0 let all of these through).
        "rm -rf ..",
        "rm -rf ../",
        "rm -rf ../*",
        "rm -rf /tmp/..",
        "rm -rf foo/../..",
        "sudo rm -rf ..",
        'rm -rf ".."',
        # find -delete on a root-ish path.
        "find / -delete",
        "find / -type f -delete",
        "find ~ -delete",
        "find $HOME -delete",
        "find ${HOME} -delete",
        "find .. -delete",
        "find / -exec rm {} +",
        "sudo find / -delete",
        # Recursive permission wipes on a root path.
        "chmod -R 000 /",
        "chmod --recursive 000 /",
        "chown -R root /",
        "sudo chmod -R 755 ~",
        "chmod -R 000 $HOME",
        "chmod -R 000 /*",
    ],
)
def test_dangerous_blocked_v14(client, command):
    assert server.check_dangerous(command) is not None
    r = client.post("/exec", json={"command": command}, headers=auth())
    assert r.status_code == 403


@pytest.mark.parametrize(
    "command",
    [
        # Named targets stay allowed, even one step up or under a root path.
        "rm -rf ../build",
        "rm -rf /tmp/my-scratch-dir",
        "rm -rf $HOME/cache",
        "find /tmp -delete",
        "find ../build -delete",
        # Non-recursive perms, or recursive perms on a subdir, stay allowed.
        "chmod 755 /tmp/file",
        "chmod -R 755 /tmp/mydir",
        "chown -R user:group /tmp/mydir",
        # rm without both -r and -f is not a wipe.
        "rm ..",
        "rm -f /tmp/file",
    ],
)
def test_benign_still_allowed_v14(client, command):
    assert server.check_dangerous(command) is None


def test_workdir_root_wipe_blocked_at_base(client, tmp_home):
    # Default cwd IS the workdir base: `rm -rf *` there would wipe home.
    assert server.check_dangerous("rm -rf *", cwd=tmp_home / "work") is not None
    assert server.check_dangerous("find . -delete", cwd=tmp_home / "work") is not None
    r = client.post("/exec", json={"command": "rm -rf *"}, headers=auth())
    assert r.status_code == 403
    # And the base dir itself survived the blocked attempt.
    assert (tmp_home / "work").is_dir()


def test_workdir_root_wipe_allowed_in_subdir(client, tmp_home):
    sub = tmp_home / "work" / "scratch"
    sub.mkdir()
    (sub / "junk.txt").write_text("junk")
    # In a subdirectory, `rm -rf *` clears just that directory.
    assert server.check_dangerous("rm -rf *", cwd=sub) is None
    r = client.post(
        "/exec", json={"command": "rm -rf *", "cwd": "scratch"}, headers=auth()
    )
    assert r.status_code == 200
    assert not (sub / "junk.txt").exists()


def test_exec_concurrency_cap(client, monkeypatch):
    import threading

    monkeypatch.setattr(server, "_exec_sem", threading.Semaphore(0))
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth())
    assert r.status_code == 503
    # Freeing a slot lets commands through again.
    monkeypatch.setattr(server, "_exec_sem", threading.Semaphore(1))
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth())
    assert r.status_code == 200


def test_exec_busy_slot_released_after_command(client, monkeypatch):
    import threading

    sem = threading.Semaphore(1)
    monkeypatch.setattr(server, "_exec_sem", sem)
    r = client.post("/exec", json={"command": "echo hi"}, headers=auth())
    assert r.status_code == 200
    # The slot was released: a second command still fits.
    r = client.post("/exec", json={"command": "echo again"}, headers=auth())
    assert r.status_code == 200


def test_health_reports_max_concurrent(client, monkeypatch):
    monkeypatch.setattr(server, "MAX_CONCURRENT", 4)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["max_concurrent"] == 4
    assert r.json()["version"] == "1.7.0"


# ---------------------------------------------------------------------------
# v1.5.0: absolute-path spellings of the workdir base (and its parent)
# ---------------------------------------------------------------------------
# v1.4.0 blocked `rm -rf ~` / `rm -rf $HOME` but let the identical wipe
# through as the absolute path: `rm -rf /home/jay`, `chmod -R 000
# /home/jay`, `find /home/jay -delete`, and the parent dir /home itself.

def test_absolute_base_path_wipes_blocked(client, tmp_home):
    work = str(tmp_home / "work")
    parent = str(tmp_home)
    for command in [
        f"rm -rf {work}",
        f"rm -rf {work}/",
        f"rm -rf {work}/*",
        f"sudo rm -rf {work}",
        f"rm -rf {parent}",
        f"rm -rf {parent}/*",
        f"find {work} -delete",
        f"find {parent} -delete",
        f"chmod -R 000 {work}",
        f"chown -R root {parent}",
        "rm -rf ~root",
        "rm -rf ~otheruser",
    ]:
        assert server.check_dangerous(command) is not None, command
        r = client.post("/exec", json={"command": command}, headers=auth())
        assert r.status_code == 403, command
    # Nothing above executed: the base dir and its parent survived.
    assert (tmp_home / "work").is_dir()
    assert tmp_home.is_dir()


def test_absolute_subdir_still_allowed(client, tmp_home):
    work = str(tmp_home / "work")
    for command in [
        f"rm -rf {work}/cache",
        f"rm -rf {work}/projects/scratch",
        f"find {work}/tmp -delete",
        f"chmod -R 755 {work}/mydir",
        f"chown -R user:group {work}/mydir",
    ]:
        assert server.check_dangerous(command) is None, command


# ---------------------------------------------------------------------------
# v1.6.0: filesystem-root spellings of the wipe root
# ---------------------------------------------------------------------------
# v1.5.0 compared targets only against the workdir base and its parent,
# so root spelled as `/.`, `//`, `/./`, or a root contents glob slipped
# through every helper (rm, find -delete, and recursive chmod/chown —
# and find/chmod have no rm-style root guard of their own).

@pytest.mark.parametrize(
    "command",
    [
        # rm spellings of root.
        "rm -rf /.",
        "rm -rf //",
        "rm -rf ///",
        "rm -rf /./",
        "rm -rf /./*",
        "rm -rf //*",
        "sudo rm -rf /.",
        # find -delete spellings of root.
        "find /. -delete",
        "find // -delete",
        "find /./ -delete",
        "find /* -delete",
        "sudo find /. -delete",
        # Recursive perms spellings of root.
        "chmod -R 000 /.",
        "chmod -R 000 /..",
        "chmod -R 000 /./",
        "chown -R root /.",
        "sudo chmod -R 000 /.",
    ],
)
def test_dangerous_blocked_v16(client, command):
    assert server.check_dangerous(command) is not None, command
    r = client.post("/exec", json={"command": command}, headers=auth())
    assert r.status_code == 403, command


@pytest.mark.parametrize(
    "command",
    [
        # Named targets under root stay allowed, as before.
        "rm -rf /tmp/my-scratch-dir",
        "find /tmp -delete",
        "chmod -R 755 /tmp/mydir",
        "chown -R user:group /tmp/mydir",
        "ls /",
        "df -h /",
    ],
)
def test_benign_still_allowed_v16(client, command):
    assert server.check_dangerous(command) is None, command


# ---------------------------------------------------------------------------
# v1.7.0: shell-word spellings of the wipe root
# ---------------------------------------------------------------------------
# v1.6.0 tokenized $'/' into "$" + "/" and /$'' into "/" + "$''", so
# a wipe root spelled with ANSI-C hex/octal escapes, a backslash, or
# a concatenated empty fragment slipped past: rm caught some forms
# only because it scans every fragment, while find (first path token
# only) and chmod missed them outright. The shell-word tokenizer
# decodes $'\x2f' / $'\057' / \/ / /$'' / $HOME$'' back to the "/"
# / "$HOME" the shell would actually pass, so all three commands
# block them. Long flags (--recursive --force) are covered too: the
# old helper only read short-flag letters.

@pytest.mark.parametrize(
    "command",
    [
        # ANSI-C quoting: plain, hex, octal, doubled, dotted, glob.
        "rm -rf $'/'",
        "rm -rf $'\\x2f'",
        "rm -rf $'\\057'",
        "rm -rf $'\\x2f\\x2f'",
        "rm -rf $'\\x2f.'",
        "rm -rf $'\\x2f'*",
        # Backslash-escaped spellings.
        "rm -rf \\/",
        "rm -rf \\/\\/",
        "rm -rf \\/.",
        # Concatenated spellings (empty fragments).
        "rm -rf /$''",
        "rm -rf /$''*",
        "rm -rf $HOME$''",
        "rm -rf ''$HOME",
        # ANSI-C / escaped parent-dir spellings.
        "rm -rf $'\\x2e\\x2e'",
        "rm -rf \\.\\.",
        "rm -rf /tmp/$'..'",
        # Long-flag spellings of rm -rf.
        "rm --recursive --force /",
        "rm --recursive --force $'\\x2f'",
        "rm -r --force /",
        # find -delete on a shell-word root.
        "find $'/' -delete",
        "find $'\\x2f' -delete",
        "find \\/ -delete",
        "find /$'' -delete",
        "find $HOME$'' -delete",
        # Recursive perms on a shell-word root.
        "chmod -R 000 \\/",
        "chmod -R 000 $'\\x2f'",
        "chmod -R 000 $'\\x2f.'",
        "chmod -R 000 $HOME$''",
        "chown -R root $'\\x2f'",
    ],
)
def test_dangerous_blocked_v17(client, command):
    assert server.check_dangerous(command) is not None, command
    r = client.post("/exec", json={"command": command}, headers=auth())
    assert r.status_code == 403, command


def test_workdir_root_wipe_quoted_glob_blocked_at_base(client, tmp_home):
    # $'*' and $'\x2a' both expand to "*" in the shell, so at the
    # workdir base they wipe home just like a bare `rm -rf *`.
    assert server.check_dangerous("rm -rf $'*'", cwd=tmp_home / "work") is not None
    assert server.check_dangerous("rm -rf $'\\x2a'", cwd=tmp_home / "work") is not None
    r = client.post("/exec", json={"command": "rm -rf $'*'"}, headers=auth())
    assert r.status_code == 403
    assert (tmp_home / "work").is_dir()


@pytest.mark.parametrize(
    "command",
    [
        # Named targets stay allowed, however they are quoted.
        "rm -rf /tmp/my-scratch-dir",
        "rm -rf $HOME/ca''che",
        "rm -rf /tmp/$'cache'",
        "rm -rf $'../build'",
        "rm --recursive --force /tmp/mydir",
        "find $HOME/cache -delete",
        "find /tmp -delete",
        # A concatenated empty fragment in a named target is not a
        # wipe: previously chmod blocked this as a false positive
        # (the empty fragment token normalized to "/").
        "chmod -R 755 $HOME/ca''che",
        "chmod -R 755 /tmp/mydir",
    ],
)
def test_benign_still_allowed_v17(client, command):
    assert server.check_dangerous(command) is None, command
