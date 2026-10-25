"""linux-remote server.

Remote shell access from your phone. Whoever holds the API key gets
full shell access on this machine, so keep the key secret and never
expose this port to the public internet. Use Tailscale.

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000
    ./start.sh [port]

Env:
    PORT                    port to listen on (default 8000)
    LR_MAX_COMMAND_LEN      max command string length, chars (default 32768)
    LR_TIMEOUT              per-command timeout, seconds (default 300)
    LR_MAX_OUTPUT_BYTES     cap on captured stdout+stderr each (default 1048576)
    LR_MAX_BODY_BYTES       max request body size (default 65536)
    LR_RATE_LIMIT           failed-auth attempts per window before temp ban
                            (default 10)
    LR_RATE_WINDOW          rate-limit window, seconds (default 300)
    LR_ALLOW_DANGEROUS      set to "1" to skip the destructive-command
                            denylist (default off)
    LR_LOG_MAX_BYTES        rotate commands.log past this size (default 5MB)
    LR_WORKDIR              base dir commands may run in (default: $HOME)
    LR_MAX_CONCURRENT       max simultaneous /exec commands (default 8);
                            further commands get 503 while all slots are busy
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import re
import secrets
import select
import shutil
import socket
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

VERSION = "1.5.0"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


PORT = _env_int("PORT", 8000)
MAX_COMMAND_LEN = _env_int("LR_MAX_COMMAND_LEN", 32_768)
COMMAND_TIMEOUT = _env_int("LR_TIMEOUT", 300)
MAX_OUTPUT_BYTES = _env_int("LR_MAX_OUTPUT_BYTES", 1_048_576)
MAX_BODY_BYTES = _env_int("LR_MAX_BODY_BYTES", 65_536)
RATE_LIMIT = _env_int("LR_RATE_LIMIT", 10)
RATE_WINDOW = _env_int("LR_RATE_WINDOW", 300)
ALLOW_DANGEROUS = os.environ.get("LR_ALLOW_DANGEROUS", "") == "1"
LOG_MAX_BYTES = _env_int("LR_LOG_MAX_BYTES", 5 * 1_048_576)
MAX_CONCURRENT = _env_int("LR_MAX_CONCURRENT", 8)
# One slot per in-flight /exec. Tests may replace this semaphore to force
# the busy path; the endpoint only ever uses the module-level object.
_exec_sem = threading.Semaphore(max(1, MAX_CONCURRENT))
BASE_DIR = Path(os.environ.get("LR_WORKDIR", str(Path.home()))).expanduser()

DATA_DIR = Path.home() / ".linux-remote"
KEY_FILE = DATA_DIR / "key"
LOG_FILE = DATA_DIR / "commands.log"


# ---------------------------------------------------------------------------
# API key management (single source of truth)
# ---------------------------------------------------------------------------

def get_or_create_key() -> tuple[str, bool]:
    """Return (key, is_new). Key file is 0600, dir is 0700."""
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip(), False
    key = secrets.token_urlsafe(32)
    KEY_FILE.write_text(key + "\n")
    KEY_FILE.chmod(0o600)
    return key, True


API_KEY, KEY_IS_NEW = get_or_create_key()

STARTED_AT = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("linux-remote server starting")
    if KEY_IS_NEW:
        # Printed only on first run, as the README promises.
        print(f"API key: {API_KEY}")
        print("Save that key in the phone app. It is only printed here once.")
    else:
        print(f"API key: loaded from {KEY_FILE} (not shown)")
    print(f"Key file: {KEY_FILE}")
    print("=" * 60)
    yield


app = FastAPI(title="linux-remote", version=VERSION, lifespan=lifespan)

# CORS: the phone app is hosted on Render (or another origin) and calls this
# server directly. This is a personal server reached over Tailscale, so allow
# all origins. Never expose this port to the public internet.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    """Reject oversized request bodies before they are buffered."""
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413, content={"detail": "request body too large"}
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Rate limiting (brute-force protection on the API key)
# ---------------------------------------------------------------------------

# ip -> list of failed-auth timestamps (monotonic seconds)
_failed_auths: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Trust X-Forwarded-For only from loopback."""
    fwd = request.headers.get("x-forwarded-for", "")
    remote = request.client.host if request.client else "unknown"
    try:
        if fwd and ipaddress.ip_address(remote).is_loopback:
            return fwd.split(",")[0].strip() or remote
    except ValueError:
        pass
    return remote


def _prune(now: float, ip: str) -> list[float]:
    stamps = _failed_auths.get(ip, [])
    fresh = [t for t in stamps if now - t < RATE_WINDOW]
    if fresh:
        _failed_auths[ip] = fresh
    else:
        _failed_auths.pop(ip, None)
    return fresh


def record_failed_auth(ip: str) -> None:
    with _rate_lock:
        now = time.monotonic()
        stamps = _prune(now, ip)
        stamps.append(now)
        _failed_auths[ip] = stamps


def clear_failed_auths(ip: str) -> None:
    with _rate_lock:
        _failed_auths.pop(ip, None)


def is_rate_limited(ip: str) -> bool:
    with _rate_lock:
        return len(_prune(time.monotonic(), ip)) >= RATE_LIMIT


def reset_rate_limiter() -> None:
    """Test hook: clear all rate-limit state."""
    with _rate_lock:
        _failed_auths.clear()


def require_key(request: Request, x_api_key: str = "") -> None:
    """Raise 401/429 unless the request carries the API key."""
    ip = _client_ip(request)
    if is_rate_limited(ip):
        raise HTTPException(
            status_code=429,
            detail="too many failed attempts; try again later",
        )
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        record_failed_auth(ip)
        raise HTTPException(status_code=401, detail="bad or missing API key")
    clear_failed_auths(ip)


# ---------------------------------------------------------------------------
# Destructive-command denylist
# ---------------------------------------------------------------------------
# This box is Jay's own machine, but a typo on a phone keyboard should not
# wipe a disk. Block the obviously catastrophic patterns; the phone app
# surfaces the block reason. Set LR_ALLOW_DANGEROUS=1 to disable.

_DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f\b.*\s+/\s*(;|$|&&|\|\|)", "recursive delete rooted at /"),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|;|$)", "recursive delete of /"),
    # Same guard with extra flags/args after the /, with sudo, and with a
    # trailing glob: `rm -rf / --no-preserve-root`, `rm -rf /*`, `sudo rm -rf /`.
    (
        r"(sudo\s+)?\brm\b[^\n;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b[^\n;|&]*\s+/\*?(?:\s|;|$)",
        "recursive delete rooted at /",
    ),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+~/?(?:\s|;|$)", "recursive delete of home dir"),
    # Same guard for the $HOME / ${HOME} spellings of the home dir
    # (quoted or not). Only the home root itself is blocked; clearing a
    # subdirectory like $HOME/cache stays allowed.
    (r"""\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+["']?\$HOME["']?/?(?:\s|;|$)""", "recursive delete of home dir"),
    (r"""\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+["']?\$\{HOME\}["']?/?(?:\s|;|$)""", "recursive delete of home dir"),
    # Same guard for clearing the whole home tree via glob
    # (`rm -rf $HOME/*`) or escaping to its parent (`rm -rf $HOME/..`).
    (
        r"""\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+["']?(\$HOME|\$\{HOME\}|~)["']?/\*+["']?(?:\s|;|$)""",
        "recursive delete of home contents",
    ),
    (
        r"""\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+["']?(\$HOME|\$\{HOME\}|~)["']?/\.\.(?:/|\s|;|$)""",
        "recursive delete via parent of home dir",
    ),
    (r"\bdd\b.*\bof=/dev/(sd|hd|vd|nvme|mmcblk)", "raw disk write via dd"),
    (r"\bmkfs(\.\w+)?\b", "filesystem format"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    # Power control only when it is the command being run (not an argument
    # like in `grep -r reboot /tmp`), optionally via sudo and after a
    # command separator.
    (
        r"(^|[;&|]\s*)(sudo\s+)?(shutdown|reboot|halt|poweroff)\b",
        "system power control",
    ),
    (r">\s*/dev/(sd|hd|vd|nvme|mmcblk)", "raw disk write via redirect"),
    (r"\bwipefs\b|\bshred\b\s+.*\s+/dev/", "disk wipe utility on device"),
]
_DANGEROUS_RES = [(re.compile(p, re.IGNORECASE), label) for p, label in _DANGEROUS_PATTERNS]


# ---------------------------------------------------------------------------
# Denylist helpers for cases regexes express badly (v1.4.0, extended v1.5.0)
# ---------------------------------------------------------------------------
# These scan per shell segment (split on ; && || |). Over-splitting only
# blocks more, never less: a dangerous command hidden behind a separator
# is still caught in its own segment.

_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|[^\s"\']+')


def _base_dir() -> Path:
    """Resolved workdir base (tests monkeypatch BASE_DIR)."""
    try:
        return Path(BASE_DIR).resolve()
    except OSError:
        return Path(BASE_DIR)


def _expand_home_spelling(target: str) -> str:
    """Expand a leading ~ / $HOME / ${HOME} spelling to an absolute path.

    Relative targets pass through unchanged.
    """
    base = str(_base_dir())
    if target == "~" or target.startswith("~/"):
        return base + target[1:]
    if target == "$HOME" or target.startswith("$HOME/"):
        return base + target[5:]
    if target == "${HOME}" or target.startswith("${HOME}/"):
        return base + target[7:]
    return target


def _is_wipe_root_target(target: str) -> bool:
    """True if target names the workdir base, its parent, or their whole
    contents — by absolute path, not just a ~/$HOME spelling.

    v1.4.0 blocked `rm -rf ~` and `rm -rf $HOME` but let the exact same
    wipe through as `rm -rf /home/jay` (the absolute path of the base),
    `rm -rf /home` (its parent), or either with a `/*` contents glob.
    A named subdirectory (`/home/jay/cache`) still stays allowed: it
    names exactly what goes, same as the existing named-target policy.
    A bare `~name` spelling (another user's whole home) is also a wipe.
    """
    if target.startswith("~") and target != "~" and not target.startswith("~/"):
        # ~name with no slash: another user's whole home dir. A subdir
        # under it (~name/projects) is a named target and stays allowed.
        if "/" not in target[1:]:
            return True
        return False
    expanded = _expand_home_spelling(target)
    if not expanded.startswith("/"):
        return False
    base = str(_base_dir())
    parent = str(_base_dir().parent)
    glob = expanded.endswith("/*")
    stem = expanded[:-2] if glob else expanded
    norm = os.path.normpath(stem)
    return norm in (base, parent)


def _segments(command: str) -> list[str]:
    return re.split(r"(?:&&|\|\||[;|])", command)


def _tokens(text: str) -> list[str]:
    """Split a segment into tokens, stripping surrounding quotes."""
    out = []
    for tok in _TOKEN_RE.findall(text):
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
            tok = tok[1:-1]
        out.append(tok)
    return out


def _cmd_rest(segment: str, word: str) -> Optional[str]:
    """Text after the first whole-word `word` in a segment, or None."""
    m = re.search(r"\b" + word + r"\b(.*)$", segment)
    return m.group(1) if m else None


def _rm_parent_traversal(command: str) -> Optional[str]:
    """Block `rm -rf` at a parent-dir target: `..`, `/tmp/..`, `foo/../..`.

    A named sibling (`rm -rf ../build`) stays allowed: it names exactly
    what goes, while an unnamed parent, a glob in the parent, or a path
    that climbs through `..` can wipe far more than intended.
    """
    for seg in _segments(command):
        rest = _cmd_rest(seg, "rm")
        if rest is None:
            continue
        toks = _tokens(rest)
        flags = [t for t in toks if t.startswith("-") and t != "-"]
        letters = "".join(t[1:] for t in flags if not t.startswith("--"))
        if "r" not in letters or "f" not in letters:
            continue
        for target in [t for t in toks if not t.startswith("-")]:
            if _is_wipe_root_target(target):
                return "recursive delete of workdir base (absolute path)"
            if target in ("..", "../"):
                return "recursive delete via parent dir"
            if target.startswith("../") and ("*" in target[3:] or target[3:] == ""):
                return "recursive delete via parent dir"
            if "/../" in target or target.endswith("/.."):
                return "recursive delete via parent traversal"
    return None


def _find_delete(command: str) -> Optional[str]:
    """Block `find <root-ish path> -delete` (or `-exec rm` on it)."""
    for seg in _segments(command):
        rest = _cmd_rest(seg, "find")
        if rest is None:
            continue
        toks = _tokens(rest)
        has_delete = "-delete" in toks or (
            "-exec" in toks and "rm" in toks[toks.index("-exec"):]
        )
        if not has_delete:
            continue
        # Valid find syntax puts the path first; no path means ".".
        # Same line as rm: a named target (../build) stays allowed, while
        # an unnamed parent, a parent glob, or a .. traversal is blocked.
        path = next((t for t in toks if not t.startswith("-")), ".")
        if _is_wipe_root_target(path):
            return "recursive delete via find on workdir base (absolute path)"
        if path in ("/", "~", "$HOME", "${HOME}", "..", "../"):
            return "recursive delete via find on root path"
        if path.startswith("../") and "*" in path[3:]:
            return "recursive delete via find on root path"
        if "/../" in path or path.endswith("/.."):
            return "recursive delete via find on root path"
    return None


def _recursive_perms(command: str) -> Optional[str]:
    """Block recursive chmod/chown rooted at / or home (bricks perms)."""
    for seg in _segments(command):
        for word in ("chmod", "chown"):
            rest = _cmd_rest(seg, word)
            if rest is None:
                continue
            toks = _tokens(rest)
            recursive = any(
                t == "--recursive" or (t.startswith("-") and not t.startswith("--") and "R" in t[1:])
                for t in toks
            )
            if not recursive:
                continue
            # chmod/chown take mode/owner first, then targets.
            targets = [t for t in toks if not t.startswith("-")][1:]
            for target in targets:
                if _is_wipe_root_target(target):
                    return f"recursive {word} on workdir base (absolute path)"
                # rstrip("/") alone would turn "/" into "" — keep root.
                norm = target.rstrip("/") or "/"
                if norm in ("/", "~", "$HOME", "${HOME}", "/*", "~/*", "$HOME/*", "${HOME}/*"):
                    return f"recursive {word} on root path"
    return None


def _wipe_at_workdir_root(command: str) -> Optional[str]:
    """Block wipe-everything targets when cwd IS the workdir base.

    `rm -rf *` in a subdirectory clears that directory (allowed); the
    same command with cwd = $HOME wipes home, so it is blocked there.
    """
    for seg in _segments(command):
        rest = _cmd_rest(seg, "rm")
        if rest is not None:
            toks = _tokens(rest)
            flags = [t for t in toks if t.startswith("-") and t != "-"]
            letters = "".join(t[1:] for t in flags if not t.startswith("--"))
            if "r" in letters and "f" in letters:
                for target in [t for t in toks if not t.startswith("-")]:
                    if target in ("*", ".*", ".", "./", "./*"):
                        return "recursive delete of workdir contents"
        rest = _cmd_rest(seg, "find")
        if rest is not None:
            toks = _tokens(rest)
            if "-delete" in toks:
                path = next((t for t in toks if not t.startswith("-")), ".")
                if path == ".":
                    return "recursive delete of workdir contents"
    return None


def check_dangerous(command: str, cwd: Optional[Path] = None) -> Optional[str]:
    """Return a human-readable block reason, or None if allowed.

    `cwd` is the already-resolved workdir for the request. When it is
    the workdir base itself, wipe-everything targets (`rm -rf *`,
    `find . -delete`) are blocked too; in a subdirectory they stay
    allowed. Pass no cwd to skip only that workdir-root rule.
    """
    if ALLOW_DANGEROUS:
        return None
    for rx, label in _DANGEROUS_RES:
        if rx.search(command):
            return label
    for helper in (_rm_parent_traversal, _find_delete, _recursive_perms):
        label = helper(command)
        if label:
            return label
    if cwd is not None:
        try:
            at_base = Path(cwd).resolve() == BASE_DIR.resolve()
        except OSError:
            at_base = False
        if at_base:
            label = _wipe_at_workdir_root(command)
            if label:
                return label
    return None


# ---------------------------------------------------------------------------
# Working directory validation
# ---------------------------------------------------------------------------

def resolve_workdir(cwd: Optional[str]) -> Path:
    """Resolve the requested cwd, constrained under BASE_DIR.

    Empty/None -> BASE_DIR. Relative paths resolve under BASE_DIR.
    Absolute paths must stay within BASE_DIR. Anything escaping raises
    HTTPException(400).
    """
    base = BASE_DIR.resolve()
    if not cwd or not cwd.strip():
        return base
    candidate = (base / cwd.strip()).resolve() if not os.path.isabs(cwd.strip()) else Path(cwd.strip()).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=400, detail="cwd must stay inside the workdir base")
    if not candidate.is_dir():
        raise HTTPException(status_code=400, detail="cwd is not a directory")
    return candidate


# ---------------------------------------------------------------------------
# Command execution with output cap and timeout
# ---------------------------------------------------------------------------

class ExecRequest(BaseModel):
    command: str = Field(max_length=MAX_COMMAND_LEN)
    cwd: Optional[str] = Field(default=None, max_length=1024)
    # Per-request timeout in seconds. Clamped to [1, COMMAND_TIMEOUT]:
    # a request can only shorten the server's configured ceiling, never
    # raise it.
    timeout_s: Optional[int] = Field(default=None, ge=1)


class ExecResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    truncated: bool = False
    duration_ms: int = 0


class _CapReader:
    """Non-blocking pipe reader that caps captured output.

    When the cap is hit the pipe is closed, so the child gets SIGPIPE
    instead of blocking forever on a full pipe buffer.
    """

    def __init__(self, stream) -> None:
        self.stream = stream
        self.fd = stream.fileno()
        os.set_blocking(self.fd, False)
        self.chunks: list[bytes] = []
        self.total = 0
        self.truncated = False
        self.closed = False

    def feed(self) -> None:
        """Read one chunk. Closes the stream on EOF or when capped."""
        try:
            # Never read more than cap+1 total: bounds overshoot to 1 byte.
            chunk = os.read(self.fd, min(65536, MAX_OUTPUT_BYTES - self.total + 1))
        except (OSError, BlockingIOError):
            return  # transient; keep the fd registered
        if not chunk:
            self.close()
            return
        self.chunks.append(chunk)
        self.total += len(chunk)
        if self.total > MAX_OUTPUT_BYTES:
            self.truncated = True
            self.close()

    def drain(self) -> None:
        while not self.closed:
            try:
                chunk = os.read(
                    self.fd, min(65536, MAX_OUTPUT_BYTES - self.total + 1)
                )
            except (OSError, BlockingIOError):
                break
            if not chunk:
                break
            self.chunks.append(chunk)
            self.total += len(chunk)
            if self.total > MAX_OUTPUT_BYTES:
                self.truncated = True
                break
        self.close()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.stream.close()
            except OSError:
                pass

    def text(self) -> str:
        return b"".join(self.chunks).decode("utf-8", errors="replace")


def run_command_capped(
    command: str, cwd: Path, timeout: int
) -> tuple[str, str, int, bool]:
    """Run command via the shell; cap each stream at MAX_OUTPUT_BYTES.

    Both pipes are drained concurrently so a chatty stderr can't deadlock
    a chatty stdout. Returns (stdout, stderr, exit_code, truncated).
    exit_code 124 means the command hit the timeout; 125 means the server
    failed to spawn it.
    """
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
    except Exception as e:  # never leak a traceback, still report it
        return "", f"server error: {e}", 125, False

    assert proc.stdout is not None and proc.stderr is not None
    readers = [_CapReader(proc.stdout), _CapReader(proc.stderr)]

    timed_out = False
    while True:
        live = [r for r in readers if not r.closed]
        if not live:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        try:
            ready, _, _ = select.select(
                [r.fd for r in live], [], [], min(0.2, remaining)
            )
        except (OSError, ValueError):
            break
        if not ready:
            if proc.poll() is not None:
                # Exited: final non-blocking drain, then done.
                for r in live:
                    r.drain()
                break
            continue
        ready_set = set(ready)
        for r in live:
            if r.fd in ready_set:
                r.feed()

    if timed_out:
        proc.kill()
    else:
        # Reap within the remaining deadline; kill if it overstays.
        remaining = deadline - time.monotonic()
        try:
            proc.wait(timeout=max(0.0, remaining))
        except subprocess.TimeoutExpired:
            proc.kill()
            timed_out = True
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    for r in readers:
        r.close()

    stdout, stderr = readers[0].text(), readers[1].text()
    truncated = readers[0].truncated or readers[1].truncated
    if timed_out:
        if stderr and not stderr.endswith("\n"):
            stderr += "\n"
        stderr += "command timed out"
        return stdout, stderr, 124, truncated
    if truncated:
        note = f"\n[output truncated at {MAX_OUTPUT_BYTES} bytes]"
        if readers[0].truncated:
            stdout += note
        if readers[1].truncated:
            stderr += note
    return (
        stdout,
        stderr,
        proc.returncode if proc.returncode is not None else 125,
        truncated,
    )


# ---------------------------------------------------------------------------
# Audit log (with rotation)
# ---------------------------------------------------------------------------

def _rotate_log_if_needed() -> None:
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > LOG_MAX_BYTES:
            backup = LOG_FILE.with_suffix(".log.1")
            if backup.exists():
                backup.unlink()
            shutil.move(str(LOG_FILE), str(backup))
    except OSError:
        pass  # logging must never break command execution


def _log_command(command: str, exit_code: int, ip: str, cwd: Path, duration_ms: int) -> None:
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    # Keep one command per log line: escape embedded newlines.
    safe = (
        command.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _rotate_log_if_needed()
    with LOG_FILE.open("a") as f:
        f.write(f"[{ts}] ip={ip} cwd={cwd} dur_ms={duration_ms} exit={exit_code} cmd={safe}\n")


# ---------------------------------------------------------------------------
# Activity stats (analytics over the audit log)
# ---------------------------------------------------------------------------

_STAT_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\] ip=(?P<ip>\S+) cwd=(?P<cwd>\S+) "
    r"dur_ms=(?P<dur>\d+) exit=(?P<exit>\d+) cmd=(?P<cmd>.*)$"
)
_BLOCKED_RE = re.compile(r"^BLOCKED\((?P<reason>[^)]*)\):\s*(?P<cmd>.*)$")


def _base_command(cmd: str) -> str:
    """First token of the command (sudo X -> X), for top-command stats."""
    m = _BLOCKED_RE.match(cmd)
    if m:
        cmd = m.group("cmd")
    parts = cmd.strip().split()
    if not parts:
        return "(empty)"
    if parts[0] == "sudo" and len(parts) > 1:
        return parts[1]
    return parts[0]


def compute_stats(lines: list[str]) -> dict:
    """Aggregate activity stats from raw audit-log lines.

    Malformed lines are skipped, never fatal: stats are best-effort.
    """
    total = 0
    ok = 0
    blocked = 0
    dur_total = 0
    dur_n = 0
    base_counts: dict[str, int] = {}
    day_counts: dict[str, int] = {}
    for ln in lines:
        m = _STAT_RE.match(ln.strip())
        if not m:
            continue
        total += 1
        exit_code = int(m.group("exit"))
        dur = int(m.group("dur"))
        cmd = m.group("cmd")
        bm = _BLOCKED_RE.match(cmd)
        if bm:
            blocked += 1
        elif exit_code == 0:
            ok += 1
        # Blocked commands never ran, so they carry no real duration.
        if not bm:
            dur_total += dur
            dur_n += 1
        base = _base_command(cmd)
        base_counts[base] = base_counts.get(base, 0) + 1
        day = m.group("ts")[:10]
        day_counts[day] = day_counts.get(day, 0) + 1
    top = sorted(base_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    return {
        "total_commands": total,
        "successful": ok,
        "failed": total - ok - blocked,
        "blocked": blocked,
        "success_rate": round(ok / total, 3) if total else None,
        "avg_duration_ms": round(dur_total / dur_n, 1) if dur_n else None,
        "top_commands": [{"command": c, "count": n} for c, n in top],
        "per_day": dict(sorted(day_counts.items())),
    }


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "linux-remote",
        "version": VERSION,
        "host": socket.gethostname(),
        "uptime_s": int(time.time() - STARTED_AT),
        "max_concurrent": MAX_CONCURRENT,
    }


@app.post("/exec", response_model=ExecResponse)
def exec_command(
    req: ExecRequest,
    request: Request,
    x_api_key: str = Header(default=""),
):
    require_key(request, x_api_key)
    command = (req.command or "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="empty command")
    # Resolve first: the denylist's workdir-root rule needs the real cwd,
    # and a cwd escaping the base is rejected before any command runs.
    workdir = resolve_workdir(req.cwd)
    blocked = check_dangerous(command, cwd=workdir)
    if blocked:
        _log_command(
            f"BLOCKED({blocked}): {command}", 403, _client_ip(request),
            workdir, 0,
        )
        raise HTTPException(
            status_code=403,
            detail=f"blocked destructive command ({blocked}); "
            "set LR_ALLOW_DANGEROUS=1 on the server to allow",
        )
    timeout = (
        COMMAND_TIMEOUT
        if req.timeout_s is None
        else min(req.timeout_s, COMMAND_TIMEOUT)
    )
    # Bound concurrent shells: a phone app firing many long commands must
    # not fork-bomb the server. Full slots get 503, never a queue.
    if not _exec_sem.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="server busy; too many concurrent commands",
        )
    started = time.monotonic()
    try:
        stdout, stderr, exit_code, truncated = run_command_capped(
            command, workdir, timeout
        )
    finally:
        _exec_sem.release()
    duration_ms = int((time.monotonic() - started) * 1000)
    _log_command(command, exit_code, _client_ip(request), workdir, duration_ms)
    return ExecResponse(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        truncated=truncated,
        duration_ms=duration_ms,
    )


class RotateKeyResponse(BaseModel):
    ok: bool = True
    api_key: str = ""


@app.post("/rotate-key", response_model=RotateKeyResponse)
def rotate_key(request: Request, x_api_key: str = Header(default="")):
    """Mint a fresh API key. The old key stops working immediately.

    The new key is written to the key file (0600) and returned once in the
    response body. Save it in the phone app right away.
    """
    require_key(request, x_api_key)
    global API_KEY
    new_key = secrets.token_urlsafe(32)
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    KEY_FILE.write_text(new_key + "\n")
    KEY_FILE.chmod(0o600)
    API_KEY = new_key
    return RotateKeyResponse(api_key=new_key)


@app.get("/recent")
def recent(request: Request, x_api_key: str = Header(default=""), n: int = 50):
    """Return the last n audit-log lines (newest first). Auth required."""
    require_key(request, x_api_key)
    n = max(1, min(n, 500))
    if not LOG_FILE.exists():
        return {"lines": []}
    with LOG_FILE.open() as f:
        lines = f.readlines()
    return {"lines": [ln.rstrip("\n") for ln in lines[-n:]][::-1]}


@app.get("/stats")
def stats(request: Request, x_api_key: str = Header(default=""), n: int = 500):
    """Activity analytics over the last n audit-log lines. Auth required."""
    require_key(request, x_api_key)
    n = max(1, min(n, 2000))
    if not LOG_FILE.exists():
        return compute_stats([])
    with LOG_FILE.open() as f:
        lines = f.readlines()
    return compute_stats(lines[-n:])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
