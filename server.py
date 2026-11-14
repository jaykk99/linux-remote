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
import shlex
import shutil
import socket
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Iterator, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

VERSION = "1.24.0"


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
    # v1.8.0: the old shred pattern needed TWO whitespace runs
    # (`\s+.*\s+/dev/`), so a bare `shred /dev/sda` with no flags
    # slipped through. One whitespace run before /dev/ is enough;
    # shredding a regular file (`shred secret.txt`) stays allowed.
    (r"\bwipefs\b|\bshred\b[^\n;|&]*\s/dev/", "disk wipe utility on device"),
]
_DANGEROUS_RES = [(re.compile(p, re.IGNORECASE), label) for p, label in _DANGEROUS_PATTERNS]


# ---------------------------------------------------------------------------
# Denylist helpers for cases regexes express badly (v1.4.0, extended
# v1.5.0, root spellings v1.6.0, shell-word spellings v1.7.0,
# fragmented command names v1.8.0)
# ---------------------------------------------------------------------------
# These scan per shell segment (split on ; && || |). Over-splitting only
# blocks more, never less: a dangerous command hidden behind a separator
# is still caught in its own segment.


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
    v1.6.0 adds the filesystem root itself, however spelled: v1.5.0 let
    `rm -rf /.`, `rm -rf //`, `find /. -delete`, and `chmod -R 000 /.`
    through because normpath never produced the base or parent paths
    for them (and find/chmod have no rm-style root guard of their own).
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
    # Root, however spelled: normpath keeps a leading "//" (POSIX
    # leaves it implementation-defined) and turns the empty stem of a
    # bare "/*" glob into ".", so collapse both to "/".
    if norm == "//" or (glob and stem == ""):
        norm = "/"
    return norm in (base, parent, "/")


def _segments(command: str) -> list[str]:
    return re.split(r"(?:&&|\|\||[;|])", command)


def _decode_ansi_c(body: str) -> str:
    """Decode the body of a bash $'...' ANSI-C-quoted string.

    Covers the spellings that turn into a wipe root: \\x2f and \\057
    both become "/", \\x2e becomes ".", so $'\\x2f', $'\\057',
    $'\\x2f\\x2f' and $'\\x2e\\x2e' decode to "/", "//" and "..".
    Unknown escapes collapse to the escaped char itself (\\/ -> "/",
    \\. -> "."), matching bash. Control escapes (\\n, \\t, \\a, \\e,
    \\xHH, \\ooo, \\uHHHH, \\UHHHHHHHH, \\cX) are decoded for
    completeness; they cannot spell a wipe root on their own.
    """
    out: list[str] = []
    i = 0
    simple = {
        "a": "\x07", "b": "\x08", "e": "\x1b", "E": "\x1b",
        "f": "\x0c", "n": "\n", "r": "\r", "t": "\t", "v": "\x0b",
        "\\": "\\", "'": "'", '"': '"', "?": "?",
    }
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        esc = body[i + 1]
        if esc in simple:
            out.append(simple[esc])
            i += 2
        elif esc == "x":
            j = i + 2
            hexdigits = ""
            while j < len(body) and len(hexdigits) < 2 and body[j] in "0123456789abcdefABCDEF":
                hexdigits += body[j]
                j += 1
            if hexdigits:
                out.append(chr(int(hexdigits, 16)))
                i = j
            else:
                out.append("x")
                i += 2
        elif esc in ("u", "U"):
            width = 4 if esc == "u" else 8
            j = i + 2
            hexdigits = ""
            while j < len(body) and len(hexdigits) < width and body[j] in "0123456789abcdefABCDEF":
                hexdigits += body[j]
                j += 1
            if hexdigits:
                try:
                    out.append(chr(int(hexdigits, 16)))
                except ValueError:
                    pass
                i = j
            else:
                out.append(esc)
                i += 2
        elif esc in "01234567":
            j = i + 1
            octdigits = ""
            while j < len(body) and len(octdigits) < 3 and body[j] in "01234567":
                octdigits += body[j]
                j += 1
            out.append(chr(int(octdigits, 8) & 0xFF))
            i = j
        elif esc == "c" and i + 2 < len(body):
            out.append(chr(ord(body[i + 2].upper()) & 0x1F))
            i += 3
        else:
            # Unknown escape: bash keeps the escaped char (\/ -> /).
            out.append(esc)
            i += 2
    return "".join(out)


def _decode_double_quoted(body: str) -> str:
    """Decode a bash "..." string: backslash is special only before
    $, `, ", \\ and newline; before anything else (e.g. "/") the
    backslash is kept, so "/\\/" inside double quotes stays a literal
    backslash-slash filename and is NOT a wipe root.
    """
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in '$`"\\\n':
            if body[i + 1] != "\n":
                out.append(body[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _tokens(text: str) -> list[str]:
    """Split a segment into shell words, joining adjacent fragments.

    The old regex tokenizer split $'/' into "$" and "/" and kept
    /$'' as "/" + "$''", so a wipe root spelled with ANSI-C hex
    ($'\\x2f'), an escaped slash (\\/), or a concatenated empty
    fragment (/$'', $HOME$'') never survived as one target: rm
    happened to catch some forms by scanning every fragment, but
    find (which checks only the first path token) and chmod missed
    them outright. Joining fragments the way the shell does — single
    quotes literal, double quotes decoded, $'...' ANSI-C decoded,
    $"..." as double quotes, backslash escaping the next char
    outside quotes — makes $'\\x2f', \\/, /$'' and $HOME$'' all
    decode to the same "/" / "$HOME" the shell would pass to rm,
    while named targets ($HOME/ca''che -> $HOME/cache) stay allowed.
    A standalone empty quote still yields one empty token; callers
    skip empty targets so it can never masquerade as "/".
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        chars: list[str] = []
        while i < n and not text[i].isspace():
            ch = text[i]
            if ch == "'":
                j = text.find("'", i + 1)
                if j == -1:
                    chars.append(text[i + 1:])
                    i = n
                else:
                    chars.append(text[i + 1:j])
                    i = j + 1
            elif ch == '"':
                j = i + 1
                raw: list[str] = []
                closed = False
                while j < n:
                    if text[j] == "\\" and j + 1 < n:
                        raw.append(text[j:j + 2])
                        j += 2
                    elif text[j] == '"':
                        closed = True
                        break
                    else:
                        raw.append(text[j])
                        j += 1
                chars.append(_decode_double_quoted("".join(raw)))
                i = j + 1 if closed else n
            elif ch == "\\":
                if i + 1 < n:
                    chars.append(text[i + 1])
                    i += 2
                else:
                    chars.append("\\")
                    i += 1
            elif ch == "$" and i + 1 < n and text[i + 1] == "'":
                j = i + 2
                raw = []
                closed = False
                while j < n:
                    if text[j] == "\\" and j + 1 < n:
                        raw.append(text[j:j + 2])
                        j += 2
                    elif text[j] == "'":
                        closed = True
                        break
                    else:
                        raw.append(text[j])
                        j += 1
                chars.append(_decode_ansi_c("".join(raw)))
                i = j + 1 if closed else n
            elif ch == "$" and i + 1 < n and text[i + 1] == '"':
                j = i + 2
                raw = []
                closed = False
                while j < n:
                    if text[j] == "\\" and j + 1 < n:
                        raw.append(text[j:j + 2])
                        j += 2
                    elif text[j] == '"':
                        closed = True
                        break
                    else:
                        raw.append(text[j])
                        j += 1
                chars.append(_decode_double_quoted("".join(raw)))
                i = j + 1 if closed else n
            else:
                chars.append(ch)
                i += 1
        out.append("".join(chars))
    return out


def _rm_has_rf(flags: list[str]) -> bool:
    """True if rm flags include both recursive and force, in any
    spelling: combined short flags (-rf), separate short flags
    (-r -f), or long flags (--recursive --force), mixed freely.
    The old code only read short-flag letters, so
    `rm --recursive --force /` slipped past the helper checks.
    """
    short = "".join(t[1:] for t in flags if t.startswith("-") and not t.startswith("--"))
    longs = [t[2:] for t in flags if t.startswith("--")]
    has_r = "r" in short or "recursive" in longs
    has_f = "f" in short or "force" in longs
    return has_r and has_f


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
        if not _rm_has_rf(flags):
            continue
        for target in [t for t in toks if not t.startswith("-") and t]:
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
        # Empty tokens (a standalone '' quote) are skipped, not paths.
        path = next((t for t in toks if not t.startswith("-") and t), ".")
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
            # Empty tokens are skipped: rstrip("/") would otherwise
            # turn "" into "/" and block a harmless quoted-empty arg.
            targets = [t for t in toks if not t.startswith("-") and t][1:]
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
            if _rm_has_rf(flags):
                for target in [t for t in toks if not t.startswith("-") and t]:
                    if target in ("*", ".*", ".", "./", "./*"):
                        return "recursive delete of workdir contents"
        rest = _cmd_rest(seg, "find")
        if rest is not None:
            toks = _tokens(rest)
            if "-delete" in toks:
                path = next((t for t in toks if not t.startswith("-") and t), ".")
                if path == ".":
                    return "recursive delete of workdir contents"
    return None


# ---------------------------------------------------------------------------
# v1.8.0: fragmented command names
# ---------------------------------------------------------------------------
# v1.7.0 decoded quoted TARGETS, but the COMMAND NAME itself was still
# matched as raw text: `\brm\b` needs the letters r and m adjacent, so
# a backslash-escaped or quote-split spelling (`r\m`, `r"m"`, `"r"m`,
# `r''m`) sailed past every regex and every `_cmd_rest` helper, for
# every dangerous command (rm, mkfs, dd, shutdown, chmod, find) —
# including behind `sudo`. The shell runs all of those as the plain
# command, so the denylist must too. Fix: decode each segment's
# command word (skipping wrappers, leading assignments, and sudo/nice
# flags) and re-run the checks on the command with that one word
# spliced back in decoded form. Only the command word is rewritten —
# arguments stay byte-identical, so a quoted argument can never gain
# (or lose) a block from this pass, and a plain command word is a
# no-op. The raw check always runs first, so this pass can only add
# blocks, never remove one. v1.9.0 covers the known limit this left
# open (substitutions, backticks, subshells) with its own scan below.

_WRAPPER_WORDS = {"sudo", "command", "builtin", "env", "time", "nice"}
_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-h", "-p", "-t", "-C"},
    "nice": {"-n"},
    "env": {"-u", "-C", "-S"},
}
_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _word_end(text: str, i: int) -> int:
    """End index of the shell word starting at `i` (quote-aware).

    Mirrors the fragment rules of `_tokens` without decoding: single
    quotes are literal, double / $' / $" quotes close at the next
    unescaped quote, and a backslash outside quotes escapes the next
    char. An unterminated quote runs to the end of the string.
    """
    n = len(text)
    while i < n and not text[i].isspace():
        ch = text[i]
        if ch == "'":
            j = text.find("'", i + 1)
            i = n if j == -1 else j + 1
        elif ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                elif text[j] == '"':
                    break
                else:
                    j += 1
            i = n if j >= n else j + 1
        elif ch == "$" and i + 1 < n and text[i + 1] in "'\"":
            quote = text[i + 1]
            j = i + 2
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                elif text[j] == quote:
                    break
                else:
                    j += 1
            i = n if j >= n else j + 1
        elif ch == "\\":
            i += 2 if i + 1 < n else 1
        else:
            i += 1
    return i


def _normalize_segment(segment: str) -> str:
    """Segment with its command word spliced back in decoded form.

    Skips leading wrappers (`sudo`, `command`, `builtin`, `env`,
    `time`, `nice` — chained, so `sudo sudo cmd` works), leading
    `VAR=value` assignments (and `env` / `sudo` VAR=value args), and
    wrapper flag words (consuming the value word after a
    value-taking flag, e.g. `sudo -u root`, `env -u NAME`). The
    first remaining word is the command word; if decoding it changes
    it (`r\\m` -> `rm`, `r"m"` -> `rm`, `''rm` -> `rm`), splice the
    decoded form in. A plain command word returns the segment
    unchanged. Only the first word is ever touched.
    v1.15.0: when that first word is itself a wrapper the loop
    above does not know (a _POWER_WRAPPERS word outside
    _WRAPPER_WORDS: chroot, nsenter, systemd-run, timeout, nohup,
    exec, coproc, busybox — and, since v1.16.0, unshare, setpriv,
    runuser), it is resolved through `_resolve_power_wrappers` to
    the program word it really runs, and THAT word is the one
    decoded and spliced (`nsenter -t 1 r\\m -rf /` -> `rm`). Coproc
    is ambiguous (its first word may be a coproc name, with the
    command second, or the command itself), so both coproc
    candidates are spliced; runuser's -c value is a command string,
    not a program word, so it is scanned by _power_wrapper_command
    instead and is not claimed here.
    """
    i = 0
    n = len(segment)
    wrapper: Optional[str] = None
    flags_phase = False
    while True:
        while i < n and segment[i].isspace():
            i += 1
        if i >= n:
            return segment
        end = _word_end(segment, i)
        raw = segment[i:end]
        toks = _tokens(raw)
        decoded = toks[0] if toks else ""
        if decoded in _WRAPPER_WORDS:
            # Wrappers chain (`sudo sudo cmd`, `env FOO=bar cmd`):
            # every leading wrapper is skipped, not just the first.
            wrapper = decoded
            flags_phase = wrapper in _VALUE_FLAGS or wrapper in ("command", "time", "builtin")
            i = end
            continue
        if _ASSIGN_RE.match(decoded) and (wrapper is None or wrapper in ("env", "sudo")):
            i = end
            continue
        if flags_phase:
            if decoded == "--":
                flags_phase = False
                i = end
                continue
            if decoded.startswith("-") and decoded != "-":
                i = end
                value_flag = decoded in _VALUE_FLAGS.get(wrapper or "", set())
                if value_flag:
                    while i < n and segment[i].isspace():
                        i += 1
                    if i < n:
                        i = _word_end(segment, i)
                continue
            flags_phase = False
            # Fall through: this word is the command word.
        if decoded in _POWER_WRAPPERS:
            # v1.15.0: this word runs a program word of its own
            # (see the docstring). Resolve to it and decode that
            # word instead; None means the wrapper runs no program
            # word here (flags run out, a non-executing mode, or a
            # -c string, which the command-string pass scans).
            # Coproc is ambiguous: _power_wrapper_command treats
            # the first word after coproc as its NAME whenever
            # more words follow, but a nameless coproc runs that
            # first word as its command, so `coproc r\m -rf /`
            # resolves through _resolve_power_wrappers to `-rf`,
            # not `rm`, and the fragmented name survives. Walk
            # the wrapper chain and also collect the word directly
            # after any coproc in it, then splice every candidate
            # (right to left, so earlier spans stay valid). The
            # named form still resolves as before, so this only
            # adds the nameless interpretation; it never removes
            # a block.
            words = _segment_words(segment)
            idx = next((k for k, w in enumerate(words) if w[2] == i), None)
            if idx is not None:
                decoded_words = [w[1] for w in words]
                candidates: list[int] = []
                resolved = _resolve_power_wrappers(decoded_words, idx)
                if resolved is not None:
                    candidates.append(resolved)
                cur = idx
                while 0 <= cur < len(decoded_words) and decoded_words[cur] in _POWER_WRAPPERS:
                    if decoded_words[cur] == "coproc" and cur + 1 < len(words):
                        candidates.append(cur + 1)
                    kind, nxt = _power_wrapper_command(decoded_words, cur)
                    if kind != "cmd" or nxt is None or nxt <= cur:
                        break
                    cur = nxt
                out = segment
                for cand in sorted(set(candidates), key=lambda k: words[k][2], reverse=True):
                    _raw, dec, s, e = words[cand]
                    if dec and dec != _raw:
                        out = out[:s] + dec + out[e:]
                return out
            return segment
        if decoded and decoded != raw:
            return segment[:i] + decoded + segment[end:]
        return segment


def _normalize_command(command: str) -> str:
    """Command with every segment's command word decoded (v1.8.0).

    Splits on the same separators as `_segments` (separators kept, so
    rejoining is exact); each segment is normalized independently.
    """
    parts = re.split(r"(&&|\|\||[;|])", command)
    return "".join(
        _normalize_segment(p) if idx % 2 == 0 else p for idx, p in enumerate(parts)
    )


# ---------------------------------------------------------------------------
# v1.9.0: recursive scan of substitutions, subshells, process substitutions
# ---------------------------------------------------------------------------
# v1.8.0 left this as a known limit, and it was real: a dangerous
# command hidden inside $(...), backticks, or a subshell slipped past
# every check, because the closing ) / ` is not a terminator any
# regex or helper accepts (`echo $(rm -rf /)`, `` `rm -rf /` ``,
# `(rm -rf /)` all sailed through). The shell EXECUTES all of those,
# so the denylist scans them as commands in their own right: every
# inner command string is run through the same raw-then-normalized
# checks, recursively (depth capped), so a fragmented name inside a
# substitution (`$(r\m -rf /)`) is caught too.
# Groups that are NOT commands are never yielded as commands, but
# their interiors are still scanned: bash executes a substitution
# nested inside them (`$(( $(cmd) ))`, `arr=(x $(cmd) y)` and
# `${x:-$(cmd)}` all run cmd). Quoting is respected throughout: a
# substitution inside single quotes (`echo '$(rm -rf /)'`) is literal
# text and stays allowed, while one inside double quotes
# (`echo "$(rm -rf /)"`) still runs and is blocked. This pass can
# only add blocks, never remove one.

_NESTED_MAX_DEPTH = 8
_SUBSHELL_KEYWORDS = {"time", "coproc"}
_WORD_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _skip_squote(text: str, i: int) -> int:
    """Index just past the single-quoted region starting at `i`."""
    j = text.find("'", i + 1)
    return len(text) if j == -1 else j + 1


def _skip_ansi_c(text: str, i: int) -> int:
    """Index just past the $'...' region starting at `i` ($ at `i`)."""
    j = i + 2
    n = len(text)
    while j < n:
        if text[j] == "\\" and j + 1 < n:
            j += 2
            continue
        if text[j] == "'":
            return j + 1
        j += 1
    return n


def _backtick_close(text: str, i: int) -> Optional[int]:
    """Index of the backtick closing the substitution at `i`, or None."""
    j = i + 1
    n = len(text)
    while j < n:
        if text[j] == "\\" and j + 1 < n:
            j += 2
            continue
        if text[j] == "`":
            return j
        j += 1
    return None


def _brace_close(text: str, i: int) -> Optional[int]:
    """Index of the } matching the { at `i` (quote-aware), or None."""
    depth = 0
    j = i
    n = len(text)
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "'":
            j = _skip_squote(text, j)
            continue
        if ch == '"':
            j += 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            continue
        if ch == "$" and j + 1 < n and text[j + 1] == "'":
            j = _skip_ansi_c(text, j)
            continue
        if ch == "`":
            close = _backtick_close(text, j)
            j = n if close is None else close + 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


def _paren_close(text: str, i: int) -> Optional[int]:
    """Index of the ) matching the ( at `i` (quote-aware), or None.

    Nested parens count (so $(( )) arithmetic and a subshell inside
    a substitution stay balanced), and quoted regions, backticks and
    ${...} groups are skipped so a ) inside them never closes early.
    """
    depth = 0
    j = i
    n = len(text)
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "'":
            j = _skip_squote(text, j)
            continue
        if ch == '"':
            j += 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            continue
        if ch == "$" and j + 1 < n and text[j + 1] == "'":
            j = _skip_ansi_c(text, j)
            continue
        if ch == "`":
            close = _backtick_close(text, j)
            j = n if close is None else close + 1
            continue
        if ch == "$" and j + 1 < n and text[j + 1] == "{":
            close = _brace_close(text, j + 1)
            j = n if close is None else close + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


def _dollar_paren(text: str, i: int, groups: list[str]) -> int:
    """Handle a $( at `i`: append its inner command, return next index.

    $(( arithmetic is not a command, so its interior is only scanned
    for nested substitutions (which bash does execute there).
    """
    n = len(text)
    if i + 2 < n and text[i + 2] == "(":
        close = _paren_close(text, i + 1)
        if close is None:
            return n
        _scan_groups_into(text[i + 2:close], groups)
        return close + 1
    close = _paren_close(text, i + 1)
    if close is None:
        groups.append(text[i + 2:])
        return n
    groups.append(text[i + 2:close])
    return close + 1


def _scan_dquoted_into(text: str, i: int, groups: list[str]) -> int:
    """Scan the "..." region opening at `i`, return index past it.

    Substitutions stay live inside double quotes ($(), backticks,
    ${...}), so they are collected here; a plain ( subshell does not
    execute inside quotes and is never collected.
    """
    n = len(text)
    i += 1
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == '"':
            return i + 1
        if ch == "`":
            close = _backtick_close(text, i)
            if close is None:
                groups.append(text[i + 1:])
                return n
            groups.append(text[i + 1:close])
            i = close + 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            i = _dollar_paren(text, i, groups)
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            close = _brace_close(text, i + 1)
            if close is None:
                return n
            _scan_groups_into(text[i + 2:close], groups)
            i = close + 1
            continue
        i += 1
    return n


def _scan_paren_group(text: str, i: int, groups: list[str]) -> int:
    """Handle a plain ( at `i`: yield a subshell / process substitution,
    or scan (never yield) a non-command group. Returns next index."""
    n = len(text)
    if i + 1 < n and text[i + 1] == "(":
        # (( ... )) arithmetic command: not a command, scan interior.
        close = _paren_close(text, i)
        if close is None:
            return n
        _scan_groups_into(text[i + 1:close], groups)
        return close + 1
    # Previous significant char decides the role: start / separator /
    # ( / { / ! means a subshell, < or > means process substitution,
    # = means array assignment, an abutting word means a function
    # definition (empty) or a case pattern, and a spaced word means a
    # case pattern — except time / coproc, which take a subshell.
    j = i - 1
    while j >= 0 and text[j] in " \t\n":
        j -= 1
    abuts = j == i - 1
    prev = text[j] if j >= 0 else ""
    close = _paren_close(text, i)
    interior = text[i + 1:] if close is None else text[i + 1:close]
    nxt = n if close is None else close + 1
    if j < 0 or prev in ";|&({!":
        groups.append(interior)
        return nxt
    if prev in "<>" and abuts:
        groups.append(interior)
        return nxt
    if prev == "=":
        _scan_groups_into(interior, groups)
        return nxt
    if prev in _WORD_CHARS:
        if abuts:
            # foo(...) with an empty body is a function definition;
            # anything else abutting a word is not a subshell either
            # (case patterns can carry substitutions, so scan it).
            if interior.strip() == "":
                return nxt
            _scan_groups_into(interior, groups)
            return nxt
        k = j
        while k >= 0 and text[k] in _WORD_CHARS:
            k -= 1
        if text[k + 1:j + 1] in _SUBSHELL_KEYWORDS:
            groups.append(interior)
            return nxt
        _scan_groups_into(interior, groups)
        return nxt
    _scan_groups_into(interior, groups)
    return nxt


def _scan_groups_into(text: str, groups: list[str]) -> None:
    """Append every inner command string in `text` to `groups`.

    Only executed groups are appended; non-command groups contribute
    their interiors (scanned for nested executed groups). Single
    quotes and $'...' regions are literal and contribute nothing.
    """
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            i = _skip_squote(text, i)
            continue
        if ch == '"':
            i = _scan_dquoted_into(text, i, groups)
            continue
        if ch == "`":
            close = _backtick_close(text, i)
            if close is None:
                groups.append(text[i + 1:])
                return
            groups.append(text[i + 1:close])
            i = close + 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            i = _dollar_paren(text, i, groups)
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "'":
            i = _skip_ansi_c(text, i)
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == '"':
            i = _scan_dquoted_into(text, i + 1, groups)
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            close = _brace_close(text, i + 1)
            if close is None:
                return
            _scan_groups_into(text[i + 2:close], groups)
            i = close + 1
            continue
        if ch == "(":
            i = _scan_paren_group(text, i, groups)
            continue
        i += 1


def _scan_groups(text: str) -> list[str]:
    """Inner command strings executed via $(), backticks, subshells,
    and process substitutions in `text` (see _scan_groups_into)."""
    groups: list[str] = []
    _scan_groups_into(text, groups)
    return groups


def _check_nested(command: str, cwd: Optional[Path] = None, depth: int = 0) -> Optional[str]:
    """Denylist pass over every nested command in `command`.

    Same checks as the top level (raw, then command-word-normalized),
    recursed into each inner command so `$(echo $(rm -rf /))` is
    caught at whatever depth it hides. Depth-capped; the cap only
    stops absurd nesting, real commands nest far shallower.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return None
    for inner in _scan_groups(command):
        # _check_all (defined below) runs every pass over the inner
        # command, so a -c string, an interpreter -c string, or a
        # heredoc body hidden inside a substitution is caught too.
        label = _check_all(inner, cwd, depth + 1)
        if label:
            return label
    return None


# ---------------------------------------------------------------------------
# v1.10.0: command-string arguments (bash -c / eval)
# ---------------------------------------------------------------------------
# v1.9.0 left this as a known limit, and it was real — but only for
# some commands. `rm` forms inside a -c / eval string were already
# caught (the helpers find `rm` anywhere in a segment), while the
# power commands were not: they have only the anchored regex
# (`^` or a separator before shutdown/reboot/halt/poweroff), and
# inside `bash -c 'shutdown -h now'` or `eval 'shutdown -h now'`
# there is neither — the string starts with bash/eval. Nested
# quoting broke the rest too: `bash -c 'eval "rm -rf /"'` slipped
# past the helpers because the extra quote layer turned the `/`
# token into `/'`. The shell EXECUTES the -c / eval string as a
# command, so the denylist scans it as one: the string is extracted
# (decoded, so a fragmented name inside it is caught by the
# normalization pass) and run through the same checks, recursively,
# so `bash -c 'eval "rm -rf /"'` is caught at the inner layer.
# Only a command-position interpreter counts: `echo eval '...'` is
# just printing, and a -c string that is only a variable (`bash -c
# "$cmd"`) stays opaque — the value is not visible statically, so
# that form is a noted gap, not a claimed block. Interpreter -c/-e
# strings for other languages (python -c, perl -e) are NOT scanned
# here: that string is code, not shell, and scanning it as shell
# would not even catch its os.system/system() forms (their trailing
# quote/paren breaks the same token the helpers need). This pass
# can only add blocks, never remove one.

_SHELL_COMMAND_STRINGS = {"bash", "sh", "dash", "zsh"}


def _segment_words(segment: str) -> list[tuple[str, str, int, int]]:
    """(raw, decoded, start, end) per shell word in a segment.

    Spans come from `_word_end` (quote-aware, so a quoted string is
    one word even with spaces inside); decoding comes from `_tokens`,
    so a fragmented or quoted word decodes the way the shell sees it.
    """
    words: list[tuple[str, str, int, int]] = []
    i = 0
    n = len(segment)
    while True:
        while i < n and segment[i].isspace():
            i += 1
        if i >= n:
            break
        end = _word_end(segment, i)
        raw = segment[i:end]
        toks = _tokens(raw)
        words.append((raw, toks[0] if toks else "", i, end))
        i = end
    return words


def _extract_command_strings(command: str) -> list[str]:
    """Decoded command strings the shell will execute from `command`.

    Per segment, wrappers, assignments and wrapper flags are skipped
    exactly like `_normalize_segment`, then: if the command word is
    `eval`, the rest of the segment (decoded, minus a leading `--`)
    is its command string; if it is bash/sh/dash/zsh, the word after
    its -c flag is — exact `-c`, combined flags with -c last
    (`-xc`), or an attached string (`-c'...'`). An absolute path
    (`/bin/bash`) counts via its basename, as does a fragmented name
    (`ba\\sh`). Returns decoded strings: the form the interpreter
    actually runs, so a nested eval inside one is itself extracted
    on the recursive pass.
    """
    out: list[str] = []
    # v1.11.0: segment both ways and union the results. _segments
    # splits inside quotes, so it truncates a -c string holding a
    # `;` (`bash -c 'python3 -c "import os; ..."'` lost everything
    # after the inner `;`); _split_top_level is quote-aware, so it
    # keeps the whole string. The old segmentation stays first, so
    # every previously extracted string is still extracted exactly
    # as before, and the quote-aware pass only adds strings.
    for segment in list(_segments(command)) + _split_top_level(command):
        words = _segment_words(segment)
        if not words:
            continue
        idx = 0
        wrapper: Optional[str] = None
        flags_phase = False
        cmd_idx: Optional[int] = None
        while idx < len(words):
            _raw, decoded, _s, _e = words[idx]
            if decoded in _WRAPPER_WORDS:
                wrapper = decoded
                flags_phase = wrapper in _VALUE_FLAGS or wrapper in ("command", "time", "builtin")
                idx += 1
                continue
            if _ASSIGN_RE.match(decoded) and (wrapper is None or wrapper in ("env", "sudo")):
                idx += 1
                continue
            if flags_phase:
                if decoded == "--":
                    flags_phase = False
                    idx += 1
                    continue
                if decoded.startswith("-") and decoded != "-":
                    idx += 1
                    if decoded in _VALUE_FLAGS.get(wrapper or "", set()):
                        idx += 1  # consume the flag's value word
                    continue
                flags_phase = False
            cmd_idx = idx
            break
        if cmd_idx is None:
            continue
        # v1.14.0: same resolution as _skip_wrappers: a power
        # wrapper this loop does not know (timeout / nohup / exec /
        # coproc / busybox / chroot / nsenter / systemd-run /
        # unshare / setpriv / runuser) would otherwise be taken as
        # the command word and a shell -c string behind it missed
        # outright.
        if words[cmd_idx][1] in _POWER_WRAPPERS:
            resolved = _resolve_power_wrappers(
                [w[1] for w in words], cmd_idx
            )
            if resolved is None:
                continue
            cmd_idx = resolved
        _raw, decoded, _s, _end = words[cmd_idx]
        base = decoded.rsplit("/", 1)[-1]
        if base == "eval":
            rest_words = [w[1] for w in words[cmd_idx + 1:]]
            if rest_words and rest_words[0] == "--":
                rest_words = rest_words[1:]
            rest = " ".join(rest_words)
            if rest:
                out.append(rest)
        elif base in _SHELL_COMMAND_STRINGS:
            j = cmd_idx + 1
            while j < len(words):
                d = words[j][1]
                if d == "--":
                    break
                if d == "-c":
                    if j + 1 < len(words):
                        out.append(words[j + 1][1])
                    break
                if d.startswith("-c") and len(d) > 2:
                    out.append(d[2:])
                    break
                if d.startswith("-") and not d.startswith("--") and d.endswith("c"):
                    if j + 1 < len(words):
                        out.append(words[j + 1][1])
                    break
                if d.startswith("-") and d != "-":
                    j += 1
                    continue
                break
    return list(dict.fromkeys(out))


def _check_command_strings(command: str, cwd: Optional[Path] = None, depth: int = 0) -> Optional[str]:
    """Denylist pass over every -c / eval command string in `command`.

    Each extracted string gets the same checks as a top-level command
    (raw, then command-word-normalized, then nested groups, then its
    own -c / eval strings), so nesting of any depth is caught up to
    the shared depth cap. Depth-capped; real commands nest far
    shallower than the cap.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return None
    for inner in _extract_command_strings(command):
        # v1.11.0: a string that is only variable references is
        # resolved from a literal assignment in the same command
        # (`cmd='shutdown -h now'; eval "$cmd"`) and scanned as the
        # resolved text; if no assignment is visible the program it
        # will run is unknowable, so it is blocked as opaque rather
        # than waved through (v1.10.0's noted gap, now closed).
        resolved = _variable_only_resolution(inner, command)
        if resolved is not None:
            kind, value = resolved
            if kind == "opaque":
                return "opaque command string (variable value not visible)"
            inner = value
        label = _check_all(inner, cwd, depth + 1)
        if label:
            return label
    return None


# ---------------------------------------------------------------------------
# v1.11.0: interpreter code strings, heredoc-fed interpreters, and
# variable-only command strings
# ---------------------------------------------------------------------------
# v1.10.0 closed bash -c / eval but left three noted gaps, all real:
# (1) `python3 -c "import os; os.system('rm -rf /')"` sailed through
# because the code string is not shell, and scanning it as shell
# cannot work: the trailing quote/paren breaks the `/` token every
# rm/power pattern needs. (2) A heredoc body fed to an interpreter
# (`bash <<EOF` / `python3 <<EOF`) is executed, but only some of its
# lines were caught incidentally: a power command on a body line has
# no ^ or separator before it, and a python body has no shell tokens
# at all. (3) A -c string that is only a variable (`bash -c
# "$cmd"`) was waved through as opaque. The shell / interpreter
# EXECUTES all three, so the denylist now scans what they execute:
# interpreter code strings are scanned for shell commands passed to
# a sink (os.system, system(), execSync, backticks, ...) plus direct
# wipe calls (shutil.rmtree('/'), FileUtils.rm_rf('/'),
# fs.rmSync('/', {recursive: true})), heredoc/herestring bodies are
# scanned as shell or as code when the receiving command is an
# interpreter reading stdin, and a variable-only string is resolved
# from a literal assignment in the same command or blocked opaque.
# Only a command-position interpreter counts, and a heredoc body is
# only scanned when its consumer actually executes stdin: `cat
# <<EOF` data, `bash script.sh <<EOF` input to that script, and a
# -c code string's own stdin are data, not code, and stay unscanned
# by this pass. This pass can only add blocks, never remove one.

_VAR_REF_RE = re.compile(
    r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\}|[@*#?$!-]|[0-9]+)"
)
_ASSIGN_LITERAL_RE = re.compile(
    r"""(?:^|[;\n&|]\s*)(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)="""
    r"""('([^']*)'|"([^"]*)"|([^\s;&|'"$`\\]+))"""
)


def _assigned_literals(command: str) -> dict[str, str]:
    """Literal VAR=value assignments visible in `command`.

    Only quoted literals and bare words without $ / backtick / quote
    count: anything else could expand, so it is not a known value.
    A later assignment wins, matching shell execution order.
    """
    out: dict[str, str] = {}
    for m in _ASSIGN_LITERAL_RE.finditer(command):
        value = m.group(3)
        if value is None:
            value = m.group(4)
        if value is None:
            value = m.group(5)
        if value is not None:
            out[m.group(1)] = value
    return out


def _variable_only_resolution(
    string: str, command: str
) -> Optional[tuple[str, Optional[str]]]:
    """Resolve a string made only of variable references.

    Returns None when the string is not variable-only (it has literal
    text, so the normal passes scan it), ("resolved", text) when
    every reference has a literal assignment in `command`, and
    ("opaque", None) when any reference's value is not visible.
    """
    refs = list(_VAR_REF_RE.finditer(string))
    if not refs:
        return None
    if _VAR_REF_RE.sub("", string).strip():
        return None
    assigns = _assigned_literals(command)
    parts: list[str] = []
    for m in refs:
        tok = m.group(0)
        if tok.startswith("${"):
            name = tok[2:-1]
        elif tok[1:].isalpha() or tok[1] == "_":
            name = tok[1:]
        elif tok[1:].isdigit() or tok in ("$@", "$*", "$#", "$?", "$!", "$-", "$$"):
            return ("opaque", None)
        else:
            name = tok[1:]
        if name not in assigns:
            return ("opaque", None)
        parts.append(assigns[name])
    return ("resolved", " ".join(parts))


def _resolve_power_wrappers(decoded: list[str], idx: int) -> Optional[int]:
    """Follow chained power wrappers to the word they really run.

    `decoded` is a segment's decoded words and `idx` points at a
    wrapper word from _POWER_WRAPPERS. Every _power_wrapper_command
    step strictly advances, so the loop terminates. Returns None
    when the chain runs no command (flags run out, a non-executing
    mode, or an env -S string that itself runs a power command —
    that last case is already blocked by the command-position pass,
    so extraction has nothing to add).
    """
    while 0 <= idx < len(decoded) and decoded[idx] in _POWER_WRAPPERS:
        kind, nxt = _power_wrapper_command(decoded, idx)
        if kind != "cmd" or nxt is None:
            return None
        idx = nxt
    return idx if 0 <= idx < len(decoded) else None


def _skip_wrappers(words: list[tuple[str, str, int, int]]) -> Optional[int]:
    """Index of the command word in `words`, skipping wrappers.

    Same skipping as `_extract_command_strings` (chained wrappers,
    leading assignments, wrapper flag values): factored out so the
    interpreter and heredoc passes share it exactly.
    """
    idx = 0
    wrapper: Optional[str] = None
    flags_phase = False
    while idx < len(words):
        _raw, decoded, _s, _e = words[idx]
        if decoded in _WRAPPER_WORDS:
            wrapper = decoded
            flags_phase = wrapper in _VALUE_FLAGS or wrapper in ("command", "time", "builtin")
            idx += 1
            continue
        if _ASSIGN_RE.match(decoded) and (wrapper is None or wrapper in ("env", "sudo")):
            idx += 1
            continue
        if flags_phase:
            if decoded == "--":
                flags_phase = False
                idx += 1
                continue
            if decoded.startswith("-") and decoded != "-":
                idx += 1
                if decoded in _VALUE_FLAGS.get(wrapper or "", set()):
                    idx += 1
                continue
            flags_phase = False
        # v1.14.0: the loop above only knows _WRAPPER_WORDS, so a
        # power wrapper it does not know (timeout / nohup / exec /
        # coproc / busybox / chroot / nsenter / systemd-run /
        # unshare / setpriv / runuser) would be returned as the
        # command word and the interpreter / heredoc passes would
        # miss the real command behind it. Resolve through
        # _power_wrapper_command instead.
        if decoded in _POWER_WRAPPERS:
            return _resolve_power_wrappers([w[1] for w in words], idx)
        return idx
    return None


def _split_top_level(command: str, split_pipes: bool = True) -> list[str]:
    """Split `command` on top-level separators only.

    Unlike `_segments`, separators inside quotes, backticks, $(),
    ${}, subshells, and brace groups are not separators: a `;`
    inside `python3 -c "import os; os.system(...)"` belongs to the
    code string, not to the outer command, and splitting there
    would lose the sink call. Newlines count as separators (a
    multiline command runs line by line); a backslash-newline is a
    continuation, not a separator. With split_pipes False a single
    `|` (and `|&`) is not a separator, so a whole pipeline stays
    one piece for the xargs pass, which splits it into stages
    itself.
    """
    parts: list[str] = []
    start = 0
    i = 0
    n = len(command)
    paren = 0
    brace = 0
    while i < n:
        ch = command[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            i = _skip_squote(command, i)
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if command[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if command[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "'":
            i = _skip_ansi_c(command, i)
            continue
        if ch == "`":
            close = _backtick_close(command, i)
            i = n if close is None else close + 1
            continue
        if ch == "(":
            paren += 1
            i += 1
            continue
        if ch == ")":
            paren = max(0, paren - 1)
            i += 1
            continue
        if ch == "{":
            brace += 1
            i += 1
            continue
        if ch == "}":
            brace = max(0, brace - 1)
            i += 1
            continue
        if paren == 0 and brace == 0:
            if command[i:i + 2] in ("&&", "||"):
                parts.append(command[start:i])
                i += 2
                start = i
                continue
            if not split_pipes and command[i:i + 2] == "|&":
                # A stderr pipe is not a separator here: the & of
                # |& must not split on its own either.
                i += 2
                continue
            if ch == "|" and not split_pipes:
                i += 1
                continue
            if ch in ";|&\n":
                parts.append(command[start:i])
                i += 1
                start = i
                continue
        i += 1
    parts.append(command[start:])
    return parts


# --- interpreter code strings -------------------------------------------------

_INTERPRETERS: dict[str, dict] = {
    "python": {
        "names": {"python", "python3"},
        "code_letters": {"c"},
        "code_longs": set(),
        "value_flags": {"-W", "-X"},
    },
    "perl": {
        "names": {"perl"},
        "code_letters": {"e"},
        "code_longs": set(),
        "value_flags": {"-I", "-M"},
    },
    "ruby": {
        "names": {"ruby"},
        "code_letters": {"e"},
        "code_longs": set(),
        "value_flags": {"-I", "-r"},
    },
    "node": {
        "names": {"node", "nodejs"},
        "code_letters": {"e", "p"},
        "code_longs": {"--eval", "--print"},
        "value_flags": {"-r", "--require"},
    },
    "php": {
        "names": {"php"},
        "code_letters": {"r"},
        "code_longs": set(),
        "value_flags": {"-d", "-f"},
    },
}
_NAME_TO_LANG = {
    name: lang for lang, spec in _INTERPRETERS.items() for name in spec["names"]
}


def _extract_interpreter_code(command: str) -> list[tuple[str, str]]:
    """(lang, code) for every interpreter code string in `command`.

    Per top-level segment (quote-aware, so a `;` inside the code
    string does not split it), wrappers and assignments are skipped,
    then: an exact code flag (`-c`, `-e`, `-r`, `-p`, `--eval`)
    takes the next word; an attached flag (`-c'...'`) takes the
    rest of the word; combined flags with the code letter last
    (`-we`, `-uc`) take the next word. An absolute path counts via
    its basename, as does a fragmented name. After `--` a flag word
    is a script name, not a flag, so extraction stops.
    """
    out: list[tuple[str, str]] = []
    for segment in _split_top_level(command):
        words = _segment_words(segment)
        if not words:
            continue
        cmd_idx = _skip_wrappers(words)
        if cmd_idx is None:
            continue
        base = words[cmd_idx][1].rsplit("/", 1)[-1]
        lang = _NAME_TO_LANG.get(base)
        if lang is None:
            continue
        spec = _INTERPRETERS[lang]
        letters: set[str] = spec["code_letters"]
        j = cmd_idx + 1
        while j < len(words):
            d = words[j][1]
            if d == "--":
                break
            if d in spec["code_longs"]:
                if j + 1 < len(words):
                    out.append((lang, words[j + 1][1]))
                break
            if len(d) == 2 and d[0] == "-" and d[1] in letters:
                if j + 1 < len(words):
                    out.append((lang, words[j + 1][1]))
                break
            if len(d) > 2 and d[0] == "-" and not d.startswith("--") and d[1] in letters:
                out.append((lang, d[2:]))
                break
            if len(d) > 2 and d[0] == "-" and not d.startswith("--") and d[-1] in letters:
                if j + 1 < len(words):
                    out.append((lang, words[j + 1][1]))
                break
            if d in spec["value_flags"]:
                j += 2
                continue
            if d.startswith("-") and d != "-":
                if any(d.startswith(vf) and len(d) > len(vf) for vf in spec["value_flags"]):
                    j += 1
                    continue
                j += 1
                continue
            break
    return out


def _py_escape(code: str, i: int) -> tuple[str, int]:
    """Decode one backslash escape at `i` (the backslash); return (char, next)."""
    esc = code[i + 1]
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}
    if esc in simple:
        return simple[esc], i + 2
    if esc == "x":
        hexdigits = code[i + 2:i + 4]
        if len(hexdigits) == 2 and all(c in "0123456789abcdefABCDEF" for c in hexdigits):
            return chr(int(hexdigits, 16)), i + 4
        return "x", i + 2
    if esc == "u":
        hexdigits = code[i + 2:i + 6]
        if len(hexdigits) == 4 and all(c in "0123456789abcdefABCDEF" for c in hexdigits):
            try:
                return chr(int(hexdigits, 16)), i + 6
            except ValueError:
                pass
        return "u", i + 2
    if esc in "01234567":
        j = i + 1
        octdigits = ""
        while j < len(code) and len(octdigits) < 3 and code[j] in "01234567":
            octdigits += code[j]
            j += 1
        return chr(int(octdigits, 8) & 0xFF), j
    return esc, i + 2


def _parse_python_string(code: str, i: int) -> Optional[tuple[str, int]]:
    """Parse a Python string literal at `i` (optional r/b/f/u prefix).

    Returns (value, end) or None. f-strings keep their braces raw:
    the interpolated text becomes part of the value the sink runs,
    so scanning it raw is the safe reading.
    """
    j = i
    while j < len(code) and code[j] in "rRbBfFuU":
        j += 1
    if j >= len(code) or code[j] not in "'\"":
        return None
    raw = "r" in code[i:j].lower()
    q = code[j]
    if code[j:j + 3] == q * 3:
        k = j + 3
        buf: list[str] = []
        while k < len(code):
            if code[k] == "\\" and k + 1 < len(code):
                if raw:
                    buf.append(code[k:k + 2])
                    k += 2
                else:
                    ch, k = _py_escape(code, k)
                    buf.append(ch)
                continue
            if code[k:k + 3] == q * 3:
                return "".join(buf), k + 3
            buf.append(code[k])
            k += 1
        return None
    k = j + 1
    buf = []
    while k < len(code):
        if code[k] == "\\" and k + 1 < len(code):
            if raw:
                buf.append(code[k:k + 2])
                k += 2
            else:
                ch, k = _py_escape(code, k)
                buf.append(ch)
            continue
        if code[k] == q:
            return "".join(buf), k + 1
        if code[k] == "\n":
            return None
        buf.append(code[k])
        k += 1
    return None


def _parse_c_string(code: str, i: int) -> Optional[tuple[str, int]]:
    """Parse a perl/ruby/node/php string (or JS template) at `i`.

    Returns (value, end) or None. A backslash keeps its escaped char
    (\\n -> newline, \\$ -> $); a JS ${...} interpolation stays raw,
    since its text is interpolated into the shell command the sink
    runs.
    """
    if i >= len(code) or code[i] not in "'\"`":
        return None
    q = code[i]
    k = i + 1
    buf: list[str] = []
    while k < len(code):
        if code[k] == "\\" and k + 1 < len(code):
            nxt = code[k + 1]
            buf.append({"n": "\n", "r": "\r", "t": "\t"}.get(nxt, nxt))
            k += 2
            continue
        if code[k] == q:
            return "".join(buf), k + 1
        if q != "`" and code[k] == "\n":
            return None
        buf.append(code[k])
        k += 1
    return None


def _parse_string_list(
    code: str, i: int, parse_fn
) -> Optional[tuple[str, int]]:
    """Parse a [..] / (..) list of string literals at `i`, joined.

    The program is the first element: if it is not a string literal
    the command it runs is unknowable, so the sink is skipped. Later
    non-string elements are skipped, not fatal.
    """
    close = "]" if code[i] == "[" else ")"
    k = i + 1
    parts: list[str] = []
    first = True
    while k < len(code):
        while k < len(code) and code[k] in " \t\r\n,":
            k += 1
        if k < len(code) and code[k] == close:
            return (" ".join(parts), k + 1) if parts else None
        parsed = parse_fn(code, k)
        if parsed is None:
            if first:
                return None
            while k < len(code) and code[k] not in ",]})":
                k += 1
            continue
        parts.append(parsed[0])
        k = parsed[1]
        first = False
    return None


_SINK_RES: dict[str, re.Pattern] = {
    "python": re.compile(
        r"\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call|getoutput)"
        r"|os\.exec[lv][a-z]*|os\.spawn[lv][a-z]*)\s*\("
    ),
    # perl/ruby/php also take a bare string argument without parens
    # (`system "rm -rf /"`), so their patterns stop at the word.
    "perl": re.compile(r"\b(?:system|exec)\b"),
    "ruby": re.compile(r"\b(?:system|exec|spawn)\b"),
    "node": re.compile(
        r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("
    ),
    "php": re.compile(r"\b(?:exec|system|shell_exec|passthru|popen)\b"),
}


# ---------------------------------------------------------------------------
# v1.18.0: variable-valued sink arguments
# ---------------------------------------------------------------------------
# v1.11.0 left this as a noted gap: a sink whose first argument is a
# variable was skipped as unknowable, so `cmd='shutdown -h now';
# python3 -c "import os; os.system('$cmd')"` and `python3 -c
# "import os; cmd='shutdown -h now'; os.system(cmd)"` both sailed
# through — the value is visible in the same command, the sink runs
# it, and the denylist never saw it. The fix resolves the variable
# the same way v1.11.0 resolves variable-only command strings: from
# a literal assignment in the code itself (`cmd = '...'` /
# `cmd = ['...']` / `$cmd = '...'`) or, for a `$name` form, from a
# shell assignment in the same command (`cmd='...'`, which is how
# the value got into a double-quoted code string). A string-literal
# argument holding a `$name` is scanned both raw and with visible
# shell values substituted in, since a double-quoted code string
# interpolates them before the interpreter sees it. A variable with
# no visible value is opaque and blocked, exactly like a
# variable-only -c string since v1.11.0: the program it will run is
# unknowable. Expressions stay skipped (`os.system(sys.argv[1])`,
# `os.system(cmd + ' -la')`): only a bare variable as the whole
# first argument resolves. This pass can only add blocks, never
# remove one.


_CODE_ASSIGN_RES: dict[str, re.Pattern] = {
    "python": re.compile(r"(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)"),
    "ruby": re.compile(r"(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)"),
    "node": re.compile(r"(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)"),
    "perl": re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)"),
    "php": re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)"),
}

_SHELL_VAR_REF_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _assigned_code_literals(lang: str, code: str) -> dict[str, str]:
    """Literal VAR = 'value' assignments visible in `code`.

    Only string literals count (and string lists, joined with
    spaces, for `subprocess`-style argv variables): anything else
    could be any value, so it is not a known value. A later
    assignment wins. `==` and attribute assignments (`a.b = 'x'`)
    do not count.
    """
    out: dict[str, str] = {}
    parse_fn = _parse_python_string if lang == "python" else _parse_c_string
    for m in _CODE_ASSIGN_RES[lang].finditer(code):
        k = m.end()
        while k < len(code) and code[k] in " \t\r\n":
            k += 1
        if k < len(code) and code[k] in "[(":
            parsed = _parse_string_list(code, k, parse_fn)
            if parsed is not None:
                out[m.group(1)] = parsed[0]
            continue
        parsed = parse_fn(code, k)
        if parsed is not None:
            out[m.group(1)] = parsed[0]
    return out


def _substitute_shell_vars(value: str, shell_assigns: dict[str, str]) -> Optional[str]:
    """`value` with visible `$name` refs replaced, or None if none.

    Only refs with a literal shell assignment in the same command
    are replaced; anything else stays as-is. A double-quoted code
    string interpolates these before the interpreter sees it; a
    single-quoted one does not, so this errs toward blocking when
    a dangerous value is visible in the same command, the same
    approximation v1.11.0 makes for variable-only -c strings.
    """
    found = False

    def repl(m: re.Match) -> str:
        nonlocal found
        name = m.group(1) or m.group(2)
        if name in shell_assigns:
            found = True
            return shell_assigns[name]
        return m.group(0)

    new = _SHELL_VAR_REF_RE.sub(repl, value)
    return new if found else None


def _sink_arg_variable(
    lang: str,
    code: str,
    k: int,
    shell_assigns: dict[str, str],
    code_assigns: dict[str, str],
) -> tuple[Optional[str], bool]:
    """Resolve a variable first argument at `k`, or (None, opaque?).

    Returns (value, False) when the argument is a variable with a
    visible literal value, (None, True) when it is a variable with
    no visible value, and (None, False) when it is not a variable
    argument at all (an expression, a call, ...), which stays
    skipped as before. A `$name` / `${name}` form resolves from a
    code assignment first (a native perl/php `$var`) and then from
    a shell assignment (interpolation into a double-quoted code
    string); a bare name resolves from a code assignment only — a
    bare word is never shell-interpolated. The variable must be the
    whole first argument: a trailing `.`, `+`, `->`, or similar
    makes it an expression, not the variable itself.
    """
    if k < len(code) and code[k] == "$":
        m = re.match(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", code[k:])
        if not m:
            return None, False
        rest = code[k + m.end():].lstrip(" \t\r\n")
        if rest and rest[0] not in ",);":
            return None, False
        name = m.group(1) or m.group(2)
        if name in code_assigns:
            return code_assigns[name], False
        if name in shell_assigns:
            return shell_assigns[name], False
        return None, True
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", code[k:])
    if not m:
        return None, False
    rest = code[k + m.end():].lstrip(" \t\r\n")
    if rest and rest[0] not in ",);":
        return None, False
    name = m.group(0)
    if name in code_assigns:
        return code_assigns[name], False
    return None, True


def _sink_first_arg(
    lang: str,
    code: str,
    k: int,
    shell_assigns: dict[str, str],
    code_assigns: dict[str, str],
) -> tuple[list[str], bool]:
    """([shell strings], opaque?) for the first sink argument at `k`.

    A string literal (or string list) scans as before, plus its
    shell-substituted form when it holds a `$name` with a visible
    shell value. A variable argument resolves via
    `_sink_arg_variable`. Anything else (an expression, a call, a
    non-string list element) stays skipped as before.
    """
    parse_fn = _parse_python_string if lang == "python" else _parse_c_string
    if k < len(code) and code[k] in "[(":
        parsed = _parse_string_list(code, k, parse_fn)
        if parsed is not None:
            return [parsed[0]], False
        return [], False
    parsed = parse_fn(code, k)
    if parsed is not None:
        values = [parsed[0]]
        sub = _substitute_shell_vars(parsed[0], shell_assigns)
        if sub is not None and sub != parsed[0]:
            values.append(sub)
        return values, False
    value, is_opaque = _sink_arg_variable(lang, code, k, shell_assigns, code_assigns)
    if value is not None:
        return [value], False
    return [], is_opaque


def _sink_shell_strings(
    lang: str,
    code: str,
    shell_assigns: Optional[dict[str, str]] = None,
    code_assigns: Optional[dict[str, str]] = None,
) -> tuple[list[str], bool]:
    """Shell command strings a sink in `code` will execute.

    Paren form: the first argument, string or string list. Bare form
    (perl/ruby/php): a string argument with no parens. Backtick and
    %x/qx forms (perl/ruby/php) are shell code directly. The second
    return value is True when a sink takes a variable argument with
    no visible value (opaque): the program it will run is
    unknowable, so the caller blocks it rather than waving it
    through.
    """
    out: list[str] = []
    opaque = False
    shell_assigns = shell_assigns or {}
    code_assigns = code_assigns or {}
    for m in _SINK_RES[lang].finditer(code):
        k = m.end()
        while k < len(code) and code[k] in " \t\r\n":
            k += 1
        if lang in ("perl", "ruby", "php") and k < len(code) and code[k] != "(":
            values, is_opaque = _sink_first_arg(lang, code, k, shell_assigns, code_assigns)
            out.extend(values)
            opaque = opaque or is_opaque
            continue
        if lang in ("perl", "ruby", "php"):
            # Bare-word pattern: the paren itself is still to consume.
            if k >= len(code) or code[k] != "(":
                continue
            k += 1
            while k < len(code) and code[k] in " \t\r\n":
                k += 1
        values, is_opaque = _sink_first_arg(lang, code, k, shell_assigns, code_assigns)
        out.extend(values)
        opaque = opaque or is_opaque
    if lang in ("perl", "ruby", "php"):
        out.extend(_backtick_shell_strings(code, lang))
    return out, opaque


def _backtick_shell_strings(code: str, lang: str) -> list[str]:
    """Shell code in backticks / %x / qx outside string literals.

    A quote-aware walk: backticks inside a quoted string are literal
    text, not execution, and stay unscanned.
    """
    out: list[str] = []
    i = 0
    n = len(code)
    pairs = {"[": "]", "{": "}", "(": ")", "<": ">"}
    while i < n:
        ch = code[i]
        if ch == "\\":
            i += 2
            continue
        if ch in "'\"":
            q = ch
            i += 1
            while i < n:
                if code[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if code[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if ch == "`":
            j = i + 1
            while j < n:
                if code[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if code[j] == "`":
                    break
                j += 1
            if j < n:
                out.append(code[i + 1:j])
            i = j + 1
            continue
        if (
            (lang == "ruby" and code[i:i + 2] == "%x")
            or (lang == "perl" and code[i:i + 2] == "qx")
        ) and i + 2 < n:
            d = code[i + 2]
            if d.isalnum() or d in " \t\r\n":
                i += 1
                continue
            close = pairs.get(d, d)
            depth = 0
            j = i + 3
            while j < n:
                if code[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if d in pairs:
                    if code[j] == d:
                        depth += 1
                    elif code[j] == close:
                        if depth == 0:
                            break
                        depth -= 1
                elif code[j] == close:
                    break
                j += 1
            if j < n:
                out.append(code[i + 3:j])
            i = j + 1
            continue
        i += 1
    return out


# ---------------------------------------------------------------------------
# v1.20.0: variable wipe targets in direct wipe calls
# ---------------------------------------------------------------------------
# v1.11.0 only checked a LITERAL first argument to a direct wipe
# call (shutil.rmtree, File::Path rmtree, FileUtils.rm_rf,
# fs.rmSync), and left a variable target as a noted gap — so
# `p = '/'; shutil.rmtree(p)` sailed through even though the value
# is visible in the same code string, and so did the `path='/'
# keyword form and a second wipe call after a benign first one
# (the old code only ever examined the FIRST match). The fix
# resolves the first argument the way v1.18.0 resolves sink
# arguments: a literal string is checked as before; a bare / $name
# variable resolves from a literal assignment in the same code
# (or, for a $name form, from a shell assignment in the same
# command); a variable assigned from a home expression
# (os.path.expanduser('~'), $ENV{HOME}, Dir.home) counts as home.
# A variable with no visible value is opaque and blocked, exactly
# like a variable-only -c string since v1.11.0 and an opaque sink
# argument since v1.18.0: the target it will delete is unknowable.
# Expressions stay skipped (`shutil.rmtree(os.path.join(a, b))`):
# only a bare variable as the whole first argument resolves.
# Node still only blocks when `recursive` is in the call, so an
# opaque non-recursive fs.rmSync stays allowed like a literal one.
# v1.22.0: the three gaps above are closed — a wipe call reached
# through `getattr(shutil, 'rmtree')` (literal attribute, or a bare
# name whose literal assignment in the same code is 'rmtree', also
# through an `import shutil as <alias>` module name), a `path=`
# keyword after the first argument (`rmtree(ignore_errors=True,
# path='/')`, top-level arguments only, so a `path=` inside a
# nested call or a string is not misread as this call's keyword),
# and the node analogue of the alias (`const {rmSync} =
# require('fs')`, `as` / `:` alias, `rmdirSync`, `require('node:fs')`,
# destructuring from an identifier bound to `require('fs')`, the
# ESM `import {rmSync} from 'fs'`, and the bracket forms
# `fs['rmSync']` / `require('fs')['rmSync']`). The first-argument
# reader was split so the same literal / variable / home / opaque
# resolution serves both the first argument and the later keyword.
# What stays a noted gap: a dynamically looked-up call whose
# attribute name has no visible value (`getattr(shutil, name)` with
# no `name = 'rmtree'` in the code), `path=` passed inside a
# `**{'path': ...}` kwargs dict, and the ruby analogue of the alias
# (a bare `rm_rf` after `include FileUtils`).
# This pass can only add blocks, never remove one.


def _wipe_var_is_home(lang: str, code: str, name: str) -> bool:
    """True if `name` is assigned from a home expression in `code`.

    Same home expressions the literal checks accept, on the right
    hand side of a plain assignment to this variable. Any such
    assignment blocks: the denylist errs toward blocking, as
    elsewhere.
    """
    if lang == "python":
        exprs = [
            r"os\.path\.expanduser\s*\(\s*['\"]~",
            r"os\.environ\s*\[\s*['\"]HOME['\"]\s*\]",
            r"os\.getenv\s*\(\s*['\"]HOME['\"]",
            r"(?:pathlib\.)?Path\.home\s*\(\s*\)",
        ]
    elif lang == "perl":
        exprs = [r"\$ENV\{HOME\}"]
    elif lang == "ruby":
        exprs = [r"Dir\.home\b"]
    else:
        return False
    for expr in exprs:
        if re.search(
            r"(?<![.\w])" + re.escape(name) + r"\s*=(?!=)\s*" + expr, code
        ):
            return True
    return False


def _wipe_value_at(
    lang: str,
    code: str,
    j: int,
    shell_assigns: dict[str, str],
    code_assigns: dict[str, str],
) -> tuple[str, Optional[str]]:
    """(kind, value) for a wipe target starting at index `j` in `code`.

    kind "value": a literal string, or a variable resolved to one.
    kind "home": a home expression, or a variable assigned from
    one in the same code. kind "opaque": a variable argument with
    no visible value. kind "skip": anything else (an expression, a
    call, ...). The variable must be the whole argument: a trailing
    `.`, `+`, `->` or `=` makes it an expression, not the variable
    itself.
    """
    # Home-expression forms (same as the old literal checks).
    if lang == "python":
        if re.match(r"os\.path\.expanduser\s*\(\s*['\"]~", code[j:]):
            return "home", None
        if re.match(r"os\.environ\s*\[\s*['\"]HOME['\"]\s*\]", code[j:]):
            return "home", None
        if re.match(r"os\.getenv\s*\(\s*['\"]HOME['\"]", code[j:]):
            return "home", None
        if re.match(r"(?:pathlib\.)?Path\.home\s*\(\s*\)", code[j:]):
            return "home", None
    elif lang == "perl":
        if re.match(r"\$ENV\{HOME\}", code[j:]):
            return "home", None
    elif lang == "ruby":
        if re.match(r"Dir\.home\b", code[j:]):
            return "home", None
    parse_fn = _parse_python_string if lang == "python" else _parse_c_string
    parsed = parse_fn(code, j)
    if parsed is not None:
        return "value", parsed[0]
    if lang in ("perl", "php"):
        m = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*", code[j:])
    else:
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", code[j:])
    if not m:
        return "skip", None
    rest = code[j + m.end():].lstrip(" \t\r\n")
    if rest and rest[0] not in ",);":
        return "skip", None
    name = m.group(0)
    if _wipe_var_is_home(lang, code, name):
        return "home", None
    lookup = name[1:] if name.startswith("$") else name
    if lookup in code_assigns:
        return "value", code_assigns[lookup]
    if name.startswith("$") and lookup in shell_assigns:
        return "value", shell_assigns[lookup]
    return "opaque", None


def _wipe_first_arg(
    lang: str,
    code: str,
    k: int,
    shell_assigns: dict[str, str],
    code_assigns: dict[str, str],
) -> tuple[str, Optional[str]]:
    """(kind, value) for the first argument of a wipe call at `k`.

    Same kinds as _wipe_value_at. A leading `path=` keyword (python)
    is skipped first, so `shutil.rmtree(path='/')` reads the same
    way as `shutil.rmtree('/')`. A `path=` keyword after the first
    argument is NOT read here: _wipe_later_path_kwarg handles it.
    """
    j = k
    while j < len(code) and code[j] in " \t\r\n":
        j += 1
    if lang == "python":
        m = re.match(r"path\s*=\s*", code[j:])
        if m:
            j += m.end()
    return _wipe_value_at(lang, code, j, shell_assigns, code_assigns)


def _wipe_later_path_kwarg(
    lang: str,
    code: str,
    paren_idx: int,
    shell_assigns: dict[str, str],
    code_assigns: dict[str, str],
) -> tuple[str, Optional[str]]:
    """(kind, value) for a `path=` keyword after the first argument.

    Only top-level arguments of the call are scanned, so a `path=`
    inside a nested call, a dict literal or a string is not this
    call's keyword (a `**{'path': ...}` kwargs dict stays a noted
    gap). The first argument is not re-checked here: it was already
    read by _wipe_first_arg. Returns ("skip", None) when no later
    `path=` keyword carries a resolvable target; an expression
    value (`path=os.path.join(...)`) is skipped and scanning
    continues with the next argument.
    """
    close = _paren_close(code, paren_idx)
    if close is None:
        return "skip", None
    parse_fn = _parse_python_string if lang == "python" else _parse_c_string
    # Split the argument list at top-level commas.
    spans: list[tuple[int, int]] = []
    depth = 0
    arg_start = paren_idx + 1
    i = paren_idx + 1
    while i < close:
        ch = code[i]
        if ch in "'\"":
            parsed = parse_fn(code, i)
            i = parsed[1] if parsed is not None else i + 1
            continue
        if ch == "#":
            nl = code.find("\n", i, close)
            i = close if nl == -1 else nl + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((arg_start, i))
            arg_start = i + 1
        i += 1
    spans.append((arg_start, close))
    for start, end in spans[1:]:
        m = re.match(r"\s*path\s*=\s*", code[start:end])
        if not m:
            continue
        kind, value = _wipe_value_at(
            lang, code, start + m.end(), shell_assigns, code_assigns
        )
        if kind != "skip":
            return kind, value
    return "skip", None



def _python_rmtree_call_names(code: str) -> list[str]:
    """Regex alternatives for `rmtree` calls reachable in `code`.

    Always `shutil.rmtree`; plus any name the code binds to it:
    `from shutil import rmtree` (bare, `as` alias, multi-name and
    parenthesised imports included, `*` binds `rmtree` itself)
    and `<alias>.rmtree` for `import shutil as <alias>`. A bare
    name is guarded by a lookbehind so `shutil.rmtree` and
    `myrmtree` never match it as a bare call.
    """
    names = [r"shutil\.rmtree"]
    for m in re.finditer(r"from\s+shutil\s+import\s*(\([^)]*\)|[^\n;]+)", code):
        chunk = m.group(1)
        if chunk.startswith("("):
            chunk = chunk[1:-1]
        if chunk.strip() == "*":
            names.append(r"(?<![\w.])rmtree")
            continue
        for part in chunk.split(","):
            part = part.strip()
            mm = re.match(r"rmtree(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$", part)
            if mm:
                alias = mm.group(1) or "rmtree"
                names.append(r"(?<![\w.])" + re.escape(alias))
    for m in re.finditer(r"import\s+shutil\s+as\s+([A-Za-z_][A-Za-z0-9_]*)", code):
        names.append(re.escape(m.group(1)) + r"\.rmtree")
    return names


def _python_shutil_module_names(code: str) -> list[str]:
    """Names the `shutil` module goes by in `code`.

    Always `shutil` itself, plus any alias bound by
    `import shutil as <alias>`.
    """
    names = ["shutil"]
    for m in re.finditer(r"import\s+shutil\s+as\s+([A-Za-z_][A-Za-z0-9_]*)", code):
        names.append(m.group(1))
    return names


def _python_getattr_rmtree_sites(
    code: str, code_assigns: dict[str, str]
) -> list[tuple[int, int]]:
    """(start, end) of `getattr(<shutil>, 'rmtree')(...)` call sites.

    The attribute must be the literal 'rmtree', or a bare name whose
    literal assignment in the same code is 'rmtree'. An attribute
    name with no visible value stays a noted gap: the call it names
    is unknowable, and blocking every `getattr(shutil, <unknown>)`
    call would also block benign lookups written the same way, such
    as `getattr(shutil, 'copy')`.
    """
    mod = "|".join(re.escape(n) for n in _python_shutil_module_names(code))
    getattr_re = re.compile(
        r"getattr\s*\(\s*(?:%s)\s*,\s*"
        r"(?:(['\"])rmtree\1|([A-Za-z_][A-Za-z0-9_]*))\s*\)\s*\(\s*" % mod
    )
    sites: list[tuple[int, int]] = []
    for m in getattr_re.finditer(code):
        if m.group(2) is not None and code_assigns.get(m.group(2)) != "rmtree":
            continue
        sites.append((m.start(), m.end()))
    return sites


def _node_rm_call_names(code: str) -> list[str]:
    """Regex alternatives for `rmSync` / `rmdirSync` calls in `code`.

    Always `fs.rmSync` / `fs.rmdirSync`, the bracket forms
    `fs['rmSync']` / `fs["rmdirSync"]`, and the inline
    `require('fs').rmSync(...)` form (also `require('node:fs')`,
    also bracketed). Plus any bare name the code binds to one of
    them by destructuring: `const {rmSync} = require('fs')`,
    `const {rmSync: delTree} = require('fs')`,
    `const {rmSync} = fs` where `fs` itself came from
    `require('fs')`, and the ESM `import {rmSync} from 'fs'`.
    A bare name is guarded by a lookbehind so `fs.rmSync` and
    `myrmSync` never match it as a bare call. Destructuring from
    `require('fs').promises` does NOT bind: promises has no rmSync.
    """
    names = [
        r"fs\.rm(?:dir)?Sync",
        r"fs\[['\"]rm(?:dir)?Sync['\"]\]",
        r"require\(['\"](?:node:)?fs['\"]\)\.rm(?:dir)?Sync",
        r"require\(['\"](?:node:)?fs['\"]\)\[['\"]rm(?:dir)?Sync['\"]\]",
    ]
    fs_ids = ["fs"]
    for m in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"require\s*\(\s*['\"](?:node:)?fs['\"]\s*\)",
        code,
    ):
        fs_ids.append(m.group(1))
    src = r"(?:require\s*\(\s*['\"](?:node:)?fs['\"]\s*\)|%s)" % "|".join(
        re.escape(i) for i in dict.fromkeys(fs_ids)
    )
    for m in re.finditer(
        r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*" + src + r"(?!\s*\.)", code
    ):
        for part in m.group(1).split(","):
            part = part.strip()
            mm = re.match(r"(rm(?:dir)?Sync)(?:\s*:\s*([A-Za-z_][A-Za-z0-9_]*))?$", part)
            if mm:
                names.append(r"(?<![\w.])" + re.escape(mm.group(2) or mm.group(1)))
    for m in re.finditer(
        r"import\s*\{([^}]*)\}\s*from\s*['\"](?:node:)?fs['\"]", code
    ):
        for part in m.group(1).split(","):
            part = part.strip()
            mm = re.match(r"(rm(?:dir)?Sync)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$", part)
            if mm:
                names.append(r"(?<![\w.])" + re.escape(mm.group(2) or mm.group(1)))
    return names


def _check_direct_wipe(
    lang: str,
    code: str,
    cwd: Optional[Path] = None,
    shell_assigns: Optional[dict[str, str]] = None,
    code_assigns: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Block a direct wipe call with a root/home target in `code`.

    Every wipe call in the code is examined, not just the first:
    a benign first call no longer hides a wipe in a later one.
    Only root/home targets count: a named subdirectory
    (`shutil.rmtree('/tmp/build')`, or a variable holding one)
    stays allowed, same as the shell named-target policy.
    """
    shell_assigns = shell_assigns or {}
    if code_assigns is None:
        code_assigns = _assigned_code_literals(lang, code)
    if lang == "python":
        # v1.21.0: also the names the code binds to shutil.rmtree
        # with `from shutil import rmtree [as alias]` or
        # `import shutil as <alias>`, checked the same way.
        # v1.22.0: also `getattr(shutil, 'rmtree')(...)`, and a
        # `path=` keyword after the first argument.
        call_re = re.compile(
            r"(?:%s)\s*\(\s*" % "|".join(_python_rmtree_call_names(code))
        )
        call_sites = [(m.start(), m.end()) for m in call_re.finditer(code)]
        call_sites += _python_getattr_rmtree_sites(code, code_assigns)
        label_root = "recursive delete of root via shutil.rmtree"
        label_home = "recursive delete of home dir via shutil.rmtree"
        label_opaque = "opaque wipe target (variable value not visible) via shutil.rmtree"
    elif lang == "perl":
        # Paren-optional: perl lets `rmtree $dir` stand without
        # parens, and that form hid a variable target outright.
        call_re = re.compile(r"(?:File::Path::)?(?:rmtree|remove_tree)\s*\(?\s*")
        call_sites = [(m.start(), m.end()) for m in call_re.finditer(code)]
        label_root = "recursive delete of root via rmtree"
        label_home = "recursive delete of home dir via rmtree"
        label_opaque = "opaque wipe target (variable value not visible) via rmtree"
    elif lang == "ruby":
        call_re = re.compile(r"FileUtils\.(?:rm_rf|rm_r|remove_entry_secure)\s*\(?\s*")
        call_sites = [(m.start(), m.end()) for m in call_re.finditer(code)]
        label_root = "recursive delete of root via FileUtils"
        label_home = "recursive delete of home dir via FileUtils"
        label_opaque = "opaque wipe target (variable value not visible) via FileUtils"
    elif lang == "node":
        # Also the inline form require('fs').rmSync(...), which
        # never spells `fs.rmSync` as text, and (v1.22.0) any bare
        # name the code binds to rmSync / rmdirSync by destructuring
        # or ESM import.
        call_re = re.compile(
            r"(?:%s)\s*\(\s*" % "|".join(_node_rm_call_names(code))
        )
        call_sites = [(m.start(), m.end()) for m in call_re.finditer(code)]
        label_root = "recursive delete of root via fs.rmSync"
        label_home = "recursive delete of home dir via fs.rmSync"
        label_opaque = "opaque wipe target (variable value not visible) via fs.rmSync"
    else:
        return None
    for start, end in call_sites:
        if lang == "node" and "recursive" not in code[start:start + 300]:
            continue
        kind, value = _wipe_first_arg(lang, code, end, shell_assigns, code_assigns)
        if kind == "home":
            return label_home
        if kind == "value" and value is not None and _is_wipe_target_value(value):
            return label_root
        if kind == "opaque":
            return label_opaque
        if lang == "python":
            # A `path=` keyword after the first argument: the old
            # code only ever read the first argument, so
            # `rmtree(ignore_errors=True, path='/')` sailed through.
            paren_idx = end - 1
            while paren_idx > start and code[paren_idx] in " \t\r\n":
                paren_idx -= 1
            kind, value = _wipe_later_path_kwarg(
                lang, code, paren_idx, shell_assigns, code_assigns
            )
            if kind == "home":
                return label_home
            if kind == "value" and value is not None and _is_wipe_target_value(value):
                return label_root
            if kind == "opaque":
                return label_opaque
    return None


def _is_wipe_target_value(value: str) -> bool:
    """True if a literal wipe target is root, its parent, or `..`.

    A bare `~` is NOT home here: no wipe API expands it, so it names
    a literal directory called `~`. Home only counts via expanduser /
    $ENV{HOME} / Dir.home, handled by the caller.
    """
    if value.rstrip("/") == "..":
        return True
    return _is_wipe_root_target(value)


def _check_interpreter_code(
    lang: str, code: str, cwd: Optional[Path] = None, depth: int = 0,
    shell_assigns: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Denylist pass over one interpreter code string.

    Each shell string a sink will execute gets the full shell checks
    (so `os.system("bash -c 'shutdown -h now'")` stacks through the
    -c pass), then the direct wipe calls are checked. A sink whose
    first argument is a variable with no visible value is opaque:
    the program it will run is unknowable, so it is blocked rather
    than waved through.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return None
    code_assigns = _assigned_code_literals(lang, code)
    shell_cmds, opaque = _sink_shell_strings(lang, code, shell_assigns, code_assigns)
    if opaque:
        return "opaque sink argument (variable value not visible)"
    for shell_cmd in shell_cmds:
        label = _check_all(shell_cmd, cwd, depth + 1)
        if label:
            return label
    return _check_direct_wipe(lang, code, cwd, shell_assigns, code_assigns)


def _check_interpreter_strings(
    command: str, cwd: Optional[Path] = None, depth: int = 0
) -> Optional[str]:
    """Denylist pass over every interpreter code string in `command`.

    A variable-only code string resolves from a literal assignment
    in the same command or is blocked as opaque, exactly like the
    shell -c case.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return None
    shell_assigns = _assigned_literals(command)
    for lang, code in _extract_interpreter_code(command):
        resolved = _variable_only_resolution(code, command)
        if resolved is not None:
            kind, value = resolved
            if kind == "opaque":
                return "opaque interpreter code string (variable value not visible)"
            code = value
        label = _check_interpreter_code(lang, code, cwd, depth + 1, shell_assigns)
        if label:
            return label
    return None


# --- heredocs / herestrings ----------------------------------------------------

def _line_redirect_ops(
    command: str, start: int
) -> tuple[list[tuple[str, str, bool, int]], int]:
    """Heredoc / herestring operators on the line at `start`.

    Returns (ops, line_end): ops is [(kind, delim-or-word,
    strip_tabs, op_pos)] in source order for every `<<[-]DELIM`
    and `<<< word` on that line, quote-aware (a `<<` inside
    quotes is text, not a redirect); line_end is the index of
    the newline ending the line, or len(command). Several
    operators can share one line (`cmd <<A <<B`); their bodies
    follow the line in operator order, so the caller collects
    them all before reading any body.
    """
    ops: list[tuple[str, str, bool, int]] = []
    n = len(command)
    line_end = command.find("\n", start)
    if line_end == -1:
        line_end = n
    j = start
    while j < line_end:
        ch = command[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "'":
            j = _skip_squote(command, j)
            continue
        if ch == '"':
            k = j + 1
            while k < n:
                if command[k] == "\\" and k + 1 < n:
                    k += 2
                    continue
                if command[k] == '"':
                    k += 1
                    break
                k += 1
            j = k
            continue
        if ch == "$" and j + 1 < n and command[j + 1] == "'":
            j = _skip_ansi_c(command, j)
            continue
        if ch == "`":
            close = _backtick_close(command, j)
            j = n if close is None else close + 1
            continue
        if ch == "<" and j + 1 < line_end and command[j + 1] == "<":
            if j + 2 < line_end and command[j + 2] == "<":
                k = j + 3
                while k < line_end and command[k] in " \t":
                    k += 1
                if k < line_end:
                    end = _word_end(command, k)
                    toks = _tokens(command[k:end])
                    if toks:
                        ops.append(("herestring", toks[0], False, j))
                    j = end
                else:
                    j = line_end
                continue
            op = j
            k = j + 2
            strip_tabs = False
            if k < line_end and command[k] == "-":
                strip_tabs = True
                k += 1
            while k < line_end and command[k] in " \t":
                k += 1
            if k >= line_end:
                j = line_end
                continue
            end = _word_end(command, k)
            toks = _tokens(command[k:end])
            if not toks or not toks[0]:
                j = end
                continue
            ops.append(("heredoc", toks[0], strip_tabs, op))
            j = end
            continue
        j += 1
    return ops, line_end


def _extract_heredocs(command: str) -> list[tuple[str, str, int]]:
    """(kind, body, operator offset) for every heredoc / herestring
    in `command`.

    Quote-aware: a `<<` inside quotes is text, not a redirect. For
    `<<[-]DELIM` the body is the lines up to the line that is exactly
    DELIM (leading tabs stripped for `<<-`); for `<<< word` the body
    is the decoded word. An unterminated heredoc takes the rest.
    Several operators can share one line (`cmd <<A <<B`); their
    bodies follow the line in operator order. The offset is where
    the `<<` / `<<<` operator starts: bodies follow their operators
    in source order, so the offset is what attributes a body to the
    stage that redirected it (v1.23.0).
    """
    out: list[tuple[str, str, int]] = []
    n = len(command)
    i = 0
    while i < n:
        ch = command[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            i = _skip_squote(command, i)
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if command[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if command[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "'":
            i = _skip_ansi_c(command, i)
            continue
        if ch == "<" and i + 1 < n and command[i + 1] == "<":
            if i + 2 < n and command[i + 2] == "<":
                j = i + 3
                while j < n and command[j] in " \t":
                    j += 1
                if j < n:
                    end = _word_end(command, j)
                    toks = _tokens(command[j:end])
                    if toks:
                        out.append(("herestring", toks[0], i))
                    i = end
                else:
                    i = n
                continue
            # Heredoc: several operators can share one line
            # (`cmd <<A <<B`, `cmd <<A <<<x`); their bodies
            # follow the line in operator order, so collect
            # them all before reading any body.
            ops, line_end = _line_redirect_ops(command, i)
            if not any(kind == "heredoc" for kind, _w, _s, _p in ops):
                for kind, word, _s, pos in ops:
                    if kind == "herestring":
                        out.append(("herestring", word, pos))
                i = line_end
                continue
            pos = line_end + 1 if line_end < n else n
            after = n
            for kind, word, strip_tabs, op in ops:
                if kind == "herestring":
                    out.append(("herestring", word, op))
                    continue
                body_lines: list[str] = []
                after = n
                while True:
                    eol = command.find("\n", pos)
                    line = command[pos:] if eol == -1 else command[pos:eol]
                    cmp_line = line.lstrip("\t") if strip_tabs else line
                    if cmp_line.rstrip("\r") == word:
                        after = n if eol == -1 else eol + 1
                        break
                    body_lines.append(line)
                    if eol == -1:
                        after = n
                        break
                    pos = eol + 1
                out.append(("heredoc", "\n".join(body_lines), op))
                pos = after
            i = after
            continue
        i += 1
    return out


def _filter_redirect_words(args: list[str]) -> list[str]:
    """Drop heredoc/herestring operators (and their words) from args.

    A standalone `<<` / `<<<` / `<` / `>` takes the following word
    (delimiter / file); an attached form (`<<EOF`, `<<<'...'`)
    carries it in the same word.
    """
    out: list[str] = []
    k = 0
    while k < len(args):
        a = args[k]
        if a in ("<<", "<<-", "<<<", "<", ">", ">>", ">&", "<&"):
            k += 2
            continue
        if a.startswith("<<"):
            k += 1
            continue
        out.append(a)
        k += 1
    return out


def _stdin_kind(base: str, args: list[str]) -> Optional[str]:
    """'shell' / lang if this interpreter reads its program from stdin.

    No code flag, no module flag, and no script-file argument: the
    first remaining non-flag word is a script file, so the stdin
    that follows is data to that script, not a program. `-` (and
    bash `-s`, including combined `-xs`) mean stdin explicitly, and
    anything after them is positional params, not a script file.
    """
    if base in _SHELL_COMMAND_STRINGS:
        kind = "shell"
        code_letters = {"c"}
        value_flags: set[str] = {"-o"}
    elif base in _NAME_TO_LANG:
        kind = _NAME_TO_LANG[base]
        spec = _INTERPRETERS[kind]
        code_letters = spec["code_letters"]
        value_flags = spec["value_flags"]
    else:
        return None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return kind if i + 1 >= len(args) else None
        if kind == "php" and (a == "-f" or (a.startswith("-f") and len(a) > 2)):
            return None
        if a in ("-",) or (kind == "shell" and a == "-s"):
            return kind
        if a.startswith("-") and a != "-" and not a.startswith("--"):
            if a[-1] in code_letters:
                return None
            if a[1] in code_letters:
                return None
            if kind == "shell" and "s" in a[1:]:
                return kind
            if a in value_flags:
                i += 2
                continue
            if any(a.startswith(vf) and len(a) > len(vf) for vf in value_flags):
                i += 1
                continue
            i += 1
            continue
        if a.startswith("--"):
            i += 1
            continue
        return None
    return kind


def _stdin_consumers(command: str) -> set[str]:
    """Interpreter kinds in `command` that read a program from stdin."""
    kinds: set[str] = set()
    for segment in _split_top_level(command):
        words = _segment_words(segment)
        if not words:
            continue
        cmd_idx = _skip_wrappers(words)
        if cmd_idx is None:
            continue
        base = words[cmd_idx][1].rsplit("/", 1)[-1]
        args = _filter_redirect_words([w[1] for w in words[cmd_idx + 1:]])
        kind = _stdin_kind(base, args)
        if kind is not None:
            kinds.add(kind)
    return kinds


def _check_heredocs(
    command: str, cwd: Optional[Path] = None, depth: int = 0
) -> Optional[str]:
    """Denylist pass over heredoc/herestring bodies fed to interpreters.

    A body is only scanned when some segment's interpreter reads
    stdin (same segment, or downstream of a pipe like `cat <<EOF |
    bash`); bodies fed to anything else are data and stay unscanned.
    A shell body gets the full shell checks; a code body gets the
    interpreter-code checks.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return None
    bodies = _extract_heredocs(command)
    if not bodies:
        return None
    kinds = _stdin_consumers(command)
    if not kinds:
        return None
    shell_assigns = _assigned_literals(command)
    for _kind, body, _pos in bodies:
        if not body.strip():
            continue
        # <<- strips leading tabs before the interpreter sees the
        # body, and leading whitespace before a command is ignored
        # generally, so scan the dedented body: otherwise a
        # tab-indented `shutdown` slips past the anchored regex.
        # Dedenting only adds blocks; the body itself is unchanged.
        scan_body = "\n".join(ln.lstrip(" \t") for ln in body.split("\n"))
        if "shell" in kinds:
            label = _check_all(scan_body, cwd, depth + 1)
            if label:
                return label
        for lang in kinds:
            if lang == "shell":
                continue
            label = _check_interpreter_code(lang, scan_body, cwd, depth + 1, shell_assigns)
            if label:
                return label
    return None


# ---------------------------------------------------------------------------
# v1.12.0: power commands on later lines of a plain multiline command
# ---------------------------------------------------------------------------
# The power-control regex is anchored to the start of the string or
# to a ; && || | separator, so `echo hi\nshutdown` sailed through:
# the shell runs each line of a multiline command in turn, but the
# denylist only saw a command position at the start of the string.
# Fix: scan the command line by line for a power word in command
# position, skipping lines that are not executed as commands:
# heredoc bodies (data unless fed to an interpreter, which the
# heredoc pass already scans), lines inside a multiline quoted
# string, and continuations joined by a trailing backslash. A
# backslash-newline joins lines before the shell splits commands, so
# `echo foo \\\nshutdown` is one echo with `shutdown` as an argument
# and stays allowed. The first word is decoded the way the shell
# decodes it (quotes/backslashes via _tokens), so `"shutdown"` and
# `shut\\down` on a later line are caught exactly like the plain
# spelling. Only the power words are checked here: rm and friends
# match unanchored anywhere, so they never needed line starts.

_POWER_WORDS = {"shutdown", "reboot", "halt", "poweroff"}


def _power_first_word(line: str) -> bool:
    """True if `line` starts with a power command (or sudo + one).

    Mirrors the anchored regex's bare-`sudo` allowance: `sudo -u
    root reboot` is not caught here, exactly as it is not caught at
    the start of the string. A power word as part of a longer word
    (`shutdown_cmd=...`) or as an argument (`grep reboot`) is not a
    command position and stays allowed.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    m = re.match(
        r"(sudo\s+)?(shutdown|reboot|halt|poweroff)(?![A-Za-z0-9_])",
        stripped,
        re.IGNORECASE,
    )
    if m:
        return True
    # Quoted or backslash-fragmented first word: decode it the way
    # the shell does and compare that. A trailing separator on the
    # decoded word (`"shutdown";`) is not part of the command name.
    words = _tokens(stripped)
    if not words:
        return False
    first = words[0].lower().rstrip(";|&")
    if first in _POWER_WORDS:
        return True
    if first == "sudo" and len(words) > 1:
        second = words[1].lower().rstrip(";|&")
        if second in _POWER_WORDS:
            return True
    return False


def _logical_command_lines(command: str) -> Iterator[str]:
    """Logical command lines of `command`, excluding heredoc bodies.

    Walks the command's physical lines tracking multiline quote
    state, arithmetic depth (so `<<` inside `$((1<<2))` is a shift,
    not a heredoc), and pending heredoc delimiters (so a body line
    is data, not a command). Lines joined by a trailing backslash
    outside quotes are one logical line. Each completed logical
    line is yielded in order, including heredoc operator lines (when
    their body starts); heredoc body lines and delimiter lines are
    never yielded. v1.12.0's multiline power scan and v1.13.0's
    command-position scan both walk these lines, so both agree on
    what counts as a command.
    """
    quote: Optional[str] = None  # None, "sq", "dq", "ansi" ($'..'), "dsq" ($"..)
    heredocs: list[tuple[str, bool]] = []  # (delimiter, <<- strips tabs)
    arith = 0
    cur = ""
    cur_open = False  # True once cur holds an unfinished logical line
    last_was_body = False

    for raw_line in command.split("\n"):
        raw = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if heredocs:
            # Entering the body ends the operator line's logical
            # line: yield it now, or a power word on the operator
            # line itself would never be finalized if the command
            # ends inside the body.
            if cur_open and quote is None:
                yield cur
                cur_open = False
            delim, dash = heredocs[0]
            cand = raw.lstrip("\t") if dash else raw
            if cand == delim:
                heredocs.pop(0)
            # Body lines (and the delimiter line itself) are not
            # commands; the logical line before the body already
            # ended at the previous boundary.
            last_was_body = True
            continue
        # A logical line ends at this boundary unless the previous
        # line continues it (open quote, or a trailing backslash
        # outside quotes joining the next line).
        if cur_open and quote is None and not _continues(cur):
            yield cur
            cur_open = False
        if not cur_open:
            cur = raw
            cur_open = True
        else:
            cur += raw
        last_was_body = False
        # Scan this line for quote changes, arithmetic depth, and
        # heredoc operators. Quote state and arithmetic depth carry
        # across lines; heredoc bodies start on the NEXT line.
        i = 0
        n = len(raw)
        while i < n:
            if quote is not None:
                ch = raw[i]
                if quote == "sq":
                    if ch == "'":
                        quote = None
                    i += 1
                else:
                    if ch == "\\" and i + 1 < n:
                        i += 2
                    elif (quote == "dq" and ch == '"') or (
                        quote == "ansi" and ch == "'"
                    ) or (quote == "dsq" and ch == '"'):
                        quote = None
                        i += 1
                    else:
                        i += 1
                continue
            ch = raw[i]
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                quote = "sq"
                i += 1
                continue
            if ch == '"':
                quote = "dq"
                i += 1
                continue
            if ch == "$" and i + 1 < n and raw[i + 1] == "'":
                quote = "ansi"
                i += 2
                continue
            if ch == "$" and i + 1 < n and raw[i + 1] == '"':
                quote = "dsq"
                i += 2
                continue
            if ch == "#" and (i == 0 or raw[i - 1] in " \t;&|()"):
                break
            if raw[i:i + 2] == "((":
                arith += 1
                i += 2
                continue
            if raw[i:i + 2] == "))" and arith > 0:
                arith -= 1
                i += 2
                continue
            if ch == "<" and raw[i:i + 3] == "<<<":
                i += 3
                continue
            if ch == "<" and raw[i:i + 2] == "<<" and arith == 0:
                j = i + 2
                dash = False
                if j < n and raw[j] == "-":
                    dash = True
                    j += 1
                while j < n and raw[j] in " \t":
                    j += 1
                if j < n and raw[j] in "'\"":
                    q = raw[j]
                    k = raw.find(q, j + 1)
                    if k != -1 and k > j + 1:
                        heredocs.append((raw[j + 1:k], dash))
                        i = k + 1
                        continue
                k = j
                while k < n and (raw[k].isalnum() or raw[k] in "_-."):
                    k += 1
                if k > j:
                    heredocs.append((raw[j:k], dash))
                    i = k
                    continue
                i += 2
                continue
            i += 1
    if not last_was_body and cur_open:
        yield cur


def _check_multiline_power(command: str) -> Optional[str]:
    """Block a power command on a later line of a multiline command.

    Each logical line from _logical_command_lines is checked for a
    power word in first position; heredoc bodies are data, not
    commands, and are never checked here.
    """
    for line in _logical_command_lines(command):
        if _power_first_word(line):
            return "system power control"
    return None


def _continues(line: str) -> bool:
    """True if `line` ends with an odd run of backslashes: the final
    backslash escapes the newline, joining the next line to this
    one before the shell splits commands."""
    count = len(line) - len(line.rstrip("\\"))
    return count % 2 == 1


# ---------------------------------------------------------------------------
# v1.13.0: power commands in any command position
# ---------------------------------------------------------------------------
# The power-control regex only saw a power word at the start of the
# string or right after a ; && || | separator, and v1.12.0 only
# added later lines of a multiline command. A power word in any
# other command position sailed through: behind a wrapper (`time`,
# `command`, `env`, `nice`, `nohup`, `timeout`, `sudo` with flags,
# `exec`, `coproc`, `busybox`), after a control keyword (`if`,
# `while`, `until`, `then`, `do`, `else`, `elif`), inside a brace
# group or function body, after a case pattern, or as a find -exec
# command. The shell runs all of those as the power command, so
# this pass walks each logical line's decoded words tracking
# command position: a word counts only when it IS the command, never
# when it is an argument, a pattern, a variable name, or an
# assignment value. Non-executing wrapper forms stay allowed:
# `command -v` / `-V` only describe a command, `sudo -l` / `-e` /
# `-v` / `-h` only list, edit, or validate, and `builtin` refuses a
# power word outright (verified: bash reports "not a shell
# builtin"), so none of them can run it. A bare function definition
# (`f() { reboot; }` with no call) is blocked too: the body is a
# loaded command waiting for a call, and the denylist blocks the
# pattern, not the call site. Subshells, substitutions, -c strings,
# and interpreter strings recurse through _check_all, so this pass
# covers them without special-casing. This pass can only add
# blocks, never remove one.

# Words after which the next word is still a command position:
# control keywords whose condition or body executes, group openers,
# and negation. `for` / `select` are deliberately absent: the word
# after them is a loop variable name, not a command.
_POWER_POSITION_KEYWORDS = {
    "then", "do", "else", "elif", "if", "while", "until", "{", "(", "!",
}

# Wrappers that run the command word found after their flags.
_POWER_WRAPPERS = {
    "time", "command", "env", "nice", "nohup", "timeout", "sudo",
    "exec", "coproc", "busybox",
    # v1.14.0: chroot / nsenter / systemd-run run their command
    # word too, behind their own flags (and, for chroot, the root).
    "chroot", "nsenter", "systemd-run",
    # v1.16.0: unshare / setpriv / runuser run their command word
    # too, behind their own flags (and, for runuser, the user).
    "unshare", "setpriv", "runuser",
}

# Sudo long flags that take a separate value word.
_SUDO_VALUE_LONGS = {
    "--user", "--group", "--prompt", "--chdir", "--role", "--type",
    "--close-from", "--timestamp-timeout", "--command-timeout",
}
# Sudo short flag letters: mode letters never run a command,
# value letters consume the rest of the cluster or the next word.
_SUDO_MODE_LETTERS = set("hlveV")
_SUDO_VALUE_LETTERS = set("ugptC")


# A function definition's head: `f()`, `f(){`, `f()(` — the word
# after it is the body, a command position. Anything else ending in
# `)` (a substitution, a subshell word) is not: `$(echo ls)
# reboot` runs ls with reboot as its argument, not reboot itself.
_FUNC_DEF_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\(\)[{(]?")


# ---------------------------------------------------------------------------
# v1.14.0: chroot / nsenter / systemd-run as power-command wrappers
# ---------------------------------------------------------------------------
# v1.13.0's wrapper set missed three tools that run a command word
# of their own: `chroot /mnt reboot`, `nsenter -t 1 reboot`, and
# `systemd-run --scope reboot` all sailed through, because the
# wrapper word itself is not a power word and the power word sits
# in argument position. Each joins _POWER_WRAPPERS, so chained
# wrappers (`sudo chroot / reboot`, `time nsenter -t 1 reboot`),
# control-keyword positions, and env -S split strings resolve
# through the same logic as the v1.13.0 wrappers. The same hole
# also hid interpreter and shell -c strings behind a wrapper:
# _extract_command_strings and _skip_wrappers only knew
# _WRAPPER_WORDS, so `chroot /mnt sh -c 'reboot'` (and the same
# shape behind timeout / nohup / exec / coproc / busybox, missed
# since before v1.13.0) extracted nothing. Both now resolve a
# _POWER_WRAPPERS word to the word it runs before looking for a
# shell or interpreter, so the fix covers the older wrappers'
# -c form too, with no previously extracted string removed.
#
# Flag parsing follows each tool's own --help (verified locally):
# chroot takes NEWROOT then COMMAND; --userspec / --groups take a
# required value (= form or separate word), --skip-chdir takes
# none, and chroot has no short options. nsenter's namespace flags
# take optional values ([=<file>] in its help), so a separate word
# is NEVER consumed for them: `nsenter -w /ns reboot` runs /ns
# with reboot as its argument, not reboot; only --target and
# --wdns (and short -t / -W) take a required value. systemd-run's
# value longs and short value letters (-H / -M / -u / -p / -E)
# take a required value (= form or separate word); every other
# flag is boolean. An unknown flag is skipped as one token, the
# same convention as the older wrappers: every flag in the local
# --help output of all three tools is covered above, so an unknown
# flag is one the tool itself would reject. The one way this
# misaligns is a future value-taking long flag added to one of
# these tools after this version's help output. No non-executing
# mode is special-cased here: a bare wrapper with no command word
# still returns ("args", None), exactly like the older wrappers.
#
# systemd-run value-taking long flags (all others are boolean).
_SYSTEMD_RUN_VALUE_LONGS = {
    "--host", "--machine", "--unit", "--property", "--description",
    "--slice", "--expand-environment", "--service-type", "--uid",
    "--gid", "--nice", "--working-directory", "--setenv",
    "--path-property", "--socket-property", "--on-active", "--on-boot",
    "--on-startup", "--on-unit-active", "--on-unit-inactive",
    "--on-calendar", "--timer-property",
}

# setpriv value-taking long flags (all others are boolean, and
# --dump is a non-executing mode handled in _power_wrapper_command).
_SETPRIV_VALUE_LONGS = {
    "--ambient-caps", "--inh-caps", "--bounding-set", "--ruid",
    "--euid", "--rgid", "--egid", "--reuid", "--regid", "--groups",
    "--securebits", "--pdeathsig", "--selinux-label",
    "--apparmor-profile",
}

# unshare long flags that take a required value (a separate word or
# an = form). The namespace flags (--mount[=<file>], --uts, --ipc,
# --net, --pid, --user, --cgroup, --time) and --kill-child /
# --mount-proc take an OPTIONAL value, so only the = form counts
# and a separate word is the program; every other long is boolean.
_UNSHARE_VALUE_LONGS = {
    "--root", "--wd", "--setuid", "--setgid", "--propagation",
    "--setgroups", "--monotonic", "--boottime", "--map-user",
    "--map-group", "--map-users", "--map-groups",
}

# runuser long flags that take a required value (a separate word or
# an = form). --command / --session-command are handled separately:
# their value is a shell command string, not a plain value.
_RUNUSER_VALUE_LONGS = {
    "--user", "--group", "--supp-group", "--whitelist-environment",
    "--shell",
}


# ---------------------------------------------------------------------------
# v1.16.0: unshare / setpriv / runuser as power-command wrappers
# ---------------------------------------------------------------------------
# v1.14.0's wrapper set missed three more tools that run a command
# word of their own: `unshare -f reboot`, `setpriv --reuid 0 reboot`,
# and `runuser -u root reboot` all sailed through, because the
# wrapper word itself is not a power word and the power word sits in
# argument position. Each joins _POWER_WRAPPERS, so chained
# wrappers, control-keyword positions, env -S split strings, shell /
# interpreter -c extraction, and the v1.15.0 fragmented-name splice
# all resolve through the same logic as the older wrappers, with no
# previously extracted string or block removed.
#
# Flag parsing follows each tool's own --help (verified locally):
# unshare's namespace flags take an optional value ([=<file>] in its
# help), so a separate word is NEVER consumed for them: `unshare -m
# reboot` runs reboot, while `unshare -m/ns reboot` runs reboot in
# that namespace; --kill-child / --mount-proc are optional-value
# too. --root / --wd / --setuid / --setgid and short -R / -w / -S /
# -G take a required value (= form or separate word), as do
# --propagation / --setgroups / --monotonic / --boottime /
# --map-user / --map-group / --map-users / --map-groups; every
# other flag is boolean. setpriv's value longs take a required
# value (= form or separate word); --dump / -d only show state and
# never exec, so they return ("args", None) like `command -v`.
# runuser has two forms: with -u the words after the user are the
# command (after an optional --), without -u the first word is the
# user and the rest are shell arguments, never a command word, so
# that form returns ("args", None). Its -c / --command /
# --session-command value is itself a shell command string, so it
# is scanned with the full checks (the way env -S is): a power
# command inside it blocks, a harmless string does not. An unknown
# flag is skipped as one token, the same convention as the older
# wrappers: every flag in the local --help output of all three
# tools is covered above, so an unknown flag is one the tool
# itself would reject. No non-executing mode is special-cased
# beyond setpriv --dump: a bare wrapper with no command word still
# returns ("args", None), exactly like the older wrappers.
#
def _power_wrapper_command(
    words: list[str], i: int, depth: int = 0
) -> tuple[str, Optional[int]]:
    """Resolve the wrapper at words[i] to what it runs.

    Returns ("cmd", j) when words[j] is the command word (re-process
    it at command position, so chained wrappers compose), ("args",
    None) when the wrapper runs no command (a non-executing mode, or
    the words run out), and ("block", None) when the wrapper's own
    argument is itself a power command (`env -S reboot`: the -S
    string is split and executed by env).
    """
    wrapper = words[i]
    j = i + 1
    if wrapper == "time":
        while j < len(words) and words[j] == "-p":
            j += 1
    elif wrapper == "command":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("-") and tok != "-":
                if any(c in "vV" for c in tok[1:]):
                    return ("args", None)
                j += 1
                continue
            break
    elif wrapper == "env":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("-") and tok != "-":
                if tok in ("-u", "-C", "-S"):
                    if j + 1 >= len(words):
                        return ("args", None)
                    if tok == "-S" and _split_string_runs_power(
                        words[j + 1], depth + 1
                    ):
                        return ("block", None)
                    j += 2
                    continue
                if tok.startswith("-S") and len(tok) > 2:
                    if _split_string_runs_power(tok[2:], depth + 1):
                        return ("block", None)
                    j += 1
                    continue
                if tok.startswith("-u") and len(tok) > 2:
                    j += 1
                    continue
                if tok.startswith("-C") and len(tok) > 2:
                    j += 1
                    continue
                if tok in _SUDO_VALUE_LONGS or tok.startswith("--"):
                    # v1.17.0: --split-string is -S spelled long, and
                    # its value was consumed here without ever being
                    # scanned (`env --split-string 'bash -c reboot'`
                    # sailed through). It is a split string of its
                    # own, scanned the same way — separate word or
                    # = form. --unset / --chdir take a plain value.
                    if tok == "--split-string":
                        if j + 1 >= len(words):
                            return ("args", None)
                        if _split_string_runs_power(
                            words[j + 1], depth + 1
                        ):
                            return ("block", None)
                        j += 2
                    elif tok.startswith("--split-string="):
                        if _split_string_runs_power(
                            tok.split("=", 1)[1], depth + 1
                        ):
                            return ("block", None)
                        j += 1
                    elif tok in ("--unset", "--chdir"):
                        j += 2
                    else:
                        j += 1
                    continue
                # v1.17.0: a value-taking short inside a cluster
                # (`-iS '...'` / `-iS'...'`): the exact and attached
                # checks above only see a leading -S / -u / -C, so
                # walk the cluster — S scans its split-string value
                # (the rest of the cluster, or the next word), u / C
                # consume their value, anything else is boolean.
                k = 1
                value_taken = False
                while k < len(tok):
                    c = tok[k]
                    if c == "S":
                        if k + 1 < len(tok):
                            val = tok[k + 1:]
                            j += 1
                        elif j + 1 < len(words):
                            val = words[j + 1]
                            j += 2
                        else:
                            return ("args", None)
                        if _split_string_runs_power(val, depth + 1):
                            return ("block", None)
                        value_taken = True
                        break
                    if c in "uC":
                        j += 1 if k + 1 < len(tok) else 2
                        value_taken = True
                        break
                    k += 1
                if not value_taken:
                    j += 1
                continue
            if _ASSIGN_RE.match(tok):
                j += 1
                continue
            break
    elif wrapper == "nice":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("-") and tok != "-":
                if tok == "-n" or tok == "--adjustment":
                    j += 2
                elif tok.startswith("--adjustment="):
                    j += 1
                elif tok.startswith("-n") and len(tok) > 2:
                    j += 1
                elif re.fullmatch(r"-\d+", tok):
                    j += 1
                else:
                    j += 1
                continue
            break
    elif wrapper == "nohup":
        while j < len(words) and words[j] in ("--", "--help", "--version"):
            j += 1
    elif wrapper == "timeout":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if tok in ("--signal", "--kill-after"):
                    j += 2
                else:
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                k = 1
                consumed_value = False
                while k < len(tok):
                    if tok[k] in "sk":
                        j += 1 if k + 1 < len(tok) else 2
                        consumed_value = True
                        break
                    k += 1
                if not consumed_value:
                    j += 1
                continue
            break
        # The first non-flag word is the duration, not the command.
        if j < len(words):
            j += 1
    elif wrapper == "sudo":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if tok in ("--list", "--validate", "--edit", "--help"):
                    return ("args", None)
                if tok in _SUDO_VALUE_LONGS:
                    j += 2
                else:
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                k = 1
                value_taken = False
                while k < len(tok):
                    c = tok[k]
                    if c in _SUDO_MODE_LETTERS:
                        return ("args", None)
                    if c in _SUDO_VALUE_LETTERS:
                        j += 1 if k + 1 < len(tok) else 2
                        value_taken = True
                        break
                    k += 1
                if not value_taken:
                    j += 1
                continue
            if _ASSIGN_RE.match(tok):
                j += 1
                continue
            break
    elif wrapper == "exec":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("-") and tok != "-":
                if tok == "-a":
                    j += 2
                elif tok.startswith("-a") and len(tok) > 2:
                    j += 1
                else:
                    j += 1
                continue
            break
    elif wrapper == "coproc":
        # `coproc CMD` runs CMD; `coproc NAME CMD ...` names the
        # coproc NAME and runs CMD. Count the words up to the first
        # separator-terminated word: one word is the command, two
        # or more means the first is the name.
        count = 0
        k = j
        while k < len(words):
            count += 1
            if words[k] != words[k].rstrip(";|&"):
                break
            k += 1
        if count == 0:
            return ("args", None)
        if count >= 2:
            j += 1
    elif wrapper == "busybox":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("-") and tok != "-":
                j += 1
                continue
            break
    elif wrapper == "chroot":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if "=" in tok:
                    j += 1
                elif tok in ("--userspec", "--groups"):
                    j += 2
                else:
                    # --skip-chdir / --help / --version take no value.
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                # chroot has no short options: an unknown flag makes
                # chroot error out, so skipping it can only over-,
                # never under-, block.
                j += 1
                continue
            break
        # The first non-flag word is NEWROOT, not the command.
        if j < len(words):
            j += 1
    elif wrapper == "nsenter":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if "=" in tok:
                    j += 1
                elif tok in ("--target", "--wdns"):
                    j += 2
                else:
                    # Optional-arg longs (--mount[=file],
                    # --setuid[=uid], --root[=dir], ...) and boolean
                    # longs never take a separate word: the next
                    # word is the program.
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                k = 1
                value_taken = False
                while k < len(tok):
                    c = tok[k]
                    if c in "tW":
                        # -t / -W take a required value: the rest
                        # of the cluster, or the next word.
                        j += 1 if k + 1 < len(tok) else 2
                        value_taken = True
                        break
                    # Every other short flag is boolean or takes an
                    # optional attached value only (-m / -S / -w /
                    # ...): a separate word is the program.
                    k += 1
                if not value_taken:
                    j += 1
                continue
            break
    elif wrapper == "systemd-run":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if "=" in tok:
                    j += 1
                elif tok in _SYSTEMD_RUN_VALUE_LONGS:
                    j += 2
                else:
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                k = 1
                value_taken = False
                while k < len(tok):
                    c = tok[k]
                    if c in "HMupE":
                        # -H / -M / -u / -p / -E take a required
                        # value: the rest of the cluster, or the
                        # next word. All other shorts are boolean.
                        j += 1 if k + 1 < len(tok) else 2
                        value_taken = True
                        break
                    k += 1
                if not value_taken:
                    j += 1
                continue
            break
    elif wrapper == "unshare":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if "=" in tok:
                    j += 1
                elif tok in _UNSHARE_VALUE_LONGS:
                    j += 2
                else:
                    # Optional-value longs (--mount[=<file>],
                    # --kill-child[=<signame>], --mount-proc[=<dir>])
                    # and boolean longs never take a separate word.
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                k = 1
                value_taken = False
                while k < len(tok):
                    c = tok[k]
                    if c in "RwSG":
                        # -R / -w / -S / -G take a required value:
                        # the rest of the cluster, or the next word.
                        j += 1 if k + 1 < len(tok) else 2
                        value_taken = True
                        break
                    # Every other short is boolean or takes an
                    # optional attached value only (-m / -u / -i /
                    # -n / -p / -U / -C / -T): a separate word is
                    # the program.
                    k += 1
                if not value_taken:
                    j += 1
                continue
            break
    elif wrapper == "setpriv":
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if tok == "--dump":
                    # --dump shows state and does not exec.
                    return ("args", None)
                if "=" in tok:
                    j += 1
                elif tok in _SETPRIV_VALUE_LONGS:
                    j += 2
                else:
                    # Boolean longs (--nnp, --clear-groups,
                    # --keep-groups, --init-groups, --reset-env,
                    # --help, --version) take no value.
                    j += 1
                continue
            if tok.startswith("-") and tok != "-":
                if "d" in tok[1:]:
                    # -d shows state and does not exec. setpriv
                    # has no other short options, so any other
                    # short token is skipped as one token.
                    return ("args", None)
                j += 1
                continue
            break
    elif wrapper == "runuser":
        # Two forms: `runuser -u USER [--] COMMAND` runs COMMAND,
        # while `runuser [-] [USER [ARGS...]]` (su-compatible, no
        # -u) runs the user's shell with the rest as shell
        # arguments, never a command word. -c / --command /
        # --session-command run a shell command string instead, so
        # that value is scanned with the full checks.
        seen_u = False
        while j < len(words):
            tok = words[j]
            if tok == "--":
                j += 1
                break
            if tok.startswith("--"):
                if "=" in tok:
                    name, val = tok.split("=", 1)
                    if name in ("--command", "--session-command"):
                        if _check_all(val, None, depth + 1) is not None:
                            return ("block", None)
                    if name == "--user":
                        seen_u = True
                    j += 1
                    continue
                if tok in ("--command", "--session-command"):
                    if j + 1 >= len(words):
                        return ("args", None)
                    if _check_all(words[j + 1], None, depth + 1) is not None:
                        return ("block", None)
                    j += 2
                    continue
                if tok == "--user":
                    seen_u = True
                if tok in _RUNUSER_VALUE_LONGS:
                    j += 2
                    continue
                # Boolean longs (--login, --preserve-environment,
                # --fast, --pty, --help, --version) take no value.
                j += 1
                continue
            if tok.startswith("-") and tok != "-":
                k = 1
                value_taken = False
                while k < len(tok):
                    c = tok[k]
                    if c == "c":
                        # -c takes a command string: attached, or
                        # the next word.
                        if k + 1 < len(tok):
                            val = tok[k + 1:]
                            j += 1
                        elif j + 1 < len(words):
                            val = words[j + 1]
                            j += 2
                        else:
                            return ("args", None)
                        if _check_all(val, None, depth + 1) is not None:
                            return ("block", None)
                        value_taken = True
                        break
                    if c in "ugGws":
                        if c == "u":
                            seen_u = True
                        j += 1 if k + 1 < len(tok) else 2
                        value_taken = True
                        break
                    # Boolean shorts (-m, -p, -l, -f, -P, -h, -V)
                    # and a bare "-" (login) take no value.
                    k += 1
                if not value_taken:
                    j += 1
                continue
            break
        if not seen_u:
            # No -u: the first word is the user, the rest are
            # shell arguments, never a command word.
            return ("args", None)
    if j >= len(words):
        return ("args", None)
    return ("cmd", j)


def _split_string_runs_power(value: str, depth: int = 0) -> bool:
    """True if an env -S split-string runs a power command.

    v1.17.0: the v1.13.0 version only looked at the split string's
    first word, so an interpreter behind it sailed through
    (`env -S 'bash -c reboot'`, `env -S 'python3 -c
    "import os; os.system(\\"reboot\\")"'`). The split string is
    argv, not a shell line, so it is split the way env splits it
    (shlex, which matches env's quote/backslash handling) and the
    resulting command is scanned with the full checks — the same
    checks a directly typed command gets, so shell / interpreter
    -c / -e code, wrappers, chained wrappers, and nested env -S
    strings are all caught, while a power word that is only an
    argument (`env -S 'echo reboot'`, `env -S 'grep -r reboot
    /etc'`) stays allowed. A quoted separator inside an argument
    is still treated as a separator by the command-position scan,
    exactly as the same text is at top level (`echo 'hi;' reboot`
    blocks there too), so `env -S 'echo hi; reboot'` blocks as
    well. Unbalanced quotes make shlex fail; env would refuse
    such a string, but the check fails closed and scans the raw
    value. Depth-capped, and each nesting level's split string is
    a strictly shorter substring of its parent, so recursion
    always terminates.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return False
    try:
        argv = shlex.split(value)
    except ValueError:
        return _check_all(value, None, depth + 1) is not None
    if not argv:
        return False
    return _check_all(shlex.join(argv), None, depth + 1) is not None


def _segment_command_power(segment: str) -> bool:
    """True if `segment` runs a power command in command position.

    Walks the segment's decoded words: command position holds at
    the start, after a separator, after a control keyword or group
    opener, after a case pattern, after a function definition's
    head, and through wrappers to their command word. An ordinary command word ends command position
    until the next separator, except that a find -exec / -execdir /
    -ok / -okdir primary opens a new command position for its own
    command. A power word glued to a following operator
    (`reboot&&echo`) counts; a power word glued to a following
    word (`rebootfoo`) does not.
    """
    words = _tokens(segment)
    current_command: Optional[str] = None
    cmd_pos = True
    i = 0
    while i < len(words):
        raw = words[i]
        core = raw.rstrip(";|&")
        had_sep = core != raw
        if not core:
            cmd_pos = True
            current_command = None
            i += 1
            continue
        if not cmd_pos:
            if current_command == "find" and core in (
                "-exec", "-execdir", "-ok", "-okdir",
            ):
                cmd_pos = True
            elif current_command == "case" and ")" in core:
                # The pattern ends at the LAST `)`: `foo)` ends it
                # (next word is the arm body), `foo)echo` runs echo
                # (its arguments stay arguments), `()foo)` is an
                # empty pattern glued to the next one.
                tail = core.rsplit(")", 1)[1].rstrip(";|&")
                if tail.lower() in _POWER_WORDS:
                    return True
                if not tail or had_sep:
                    cmd_pos = True
                    current_command = None
            elif core == "()":
                # Spaced function-definition parens (`f () { ... }`):
                # the word after them is the body. A bare `)` alone
                # is not reset: `$(echo hi) reboot` runs echo's
                # output with reboot as its argument.
                cmd_pos = True
                current_command = None
            elif had_sep:
                cmd_pos = True
                current_command = None
            i += 1
            continue
        if _ASSIGN_RE.match(core):
            pass
        elif core in _POWER_POSITION_KEYWORDS:
            pass
        elif core.lower() in _POWER_WORDS:
            return True
        elif core in _POWER_WRAPPERS:
            kind, idx = _power_wrapper_command(words, i)
            if kind == "block":
                return True
            if kind == "cmd":
                i = idx
                continue
            cmd_pos = False
            current_command = None
        else:
            lowered = core.lower()
            for pw in _POWER_WORDS:
                if lowered.startswith(pw) and len(lowered) > len(pw) \
                        and lowered[len(pw)] in ";|&":
                    return True
            current_command = core
            cmd_pos = False
        if had_sep or _FUNC_DEF_RE.fullmatch(core):
            cmd_pos = True
            current_command = None
        i += 1
    return False


def _check_command_position_power(command: str) -> Optional[str]:
    """Block a power command in any command position of `command`.

    Each logical line from _logical_command_lines is walked with
    _segment_command_power, so heredoc bodies (data, not commands)
    are never scanned as commands here, exactly as the v1.12.0 line
    scan treats them. Subshells, substitutions, -c strings, and
    interpreter strings already recurse through _check_all, so
    nested positions are covered by the recursion, not by this pass.
    """
    for line in _logical_command_lines(command):
        if _segment_command_power(line):
            return "system power control"
    return None


# ---------------------------------------------------------------------------
# v1.19.0: echo / printf piped into xargs
# ---------------------------------------------------------------------------
# The denylist scanned the shell line as written, but xargs runs a
# command composed from its input, so the wipe target (or the whole
# command) can arrive as data: `echo / | xargs rm -rf` runs
# `rm -rf /`, and `echo 'rm -rf /' | xargs -I{} sh -c '{}'` runs
# `sh -c 'rm -rf /'`, yet no check ever saw either composed
# command — the target is data on the left of the pipe, the rm -rf
# on the right. The fix composes the command xargs will actually
# run and scans it with the full checks, when the input is literal
# in the same command: an echo / printf feeder (simulated from its
# arguments), a herestring, or a heredoc feeding xargs (or feeding
# a cat that feeds xargs). A bare `echo 'rm -rf /' | xargs` stays
# allowed: with no command xargs runs echo (verified against the
# local xargs), so the data is only ever printed, never executed.
#
# Semantics follow the local tools, verified by running them:
# /bin/sh is dash, so a bare `echo` is dash's builtin (escapes
# interpreted by default, only -n is a flag, -e is literal text);
# /bin/echo is coreutils (escapes only with -e). xargs splits its
# input on blanks with quote/backslash processing (an unmatched
# quote makes it error out and run nothing), on NULs with -0, on
# the -d delimiter (whose value has its escapes decoded, so '-d
# \\n' is a newline), and -E truncates at the first matching line.
# -I replaces the string in the initial args with each input line
# (blank lines skipped, a line with spaces stays one argument);
# the command word itself is never substituted, and with no
# placeholder in the args the line is dropped, not appended.
# Batching flags (-n / -L / -P / -s) only split runs, so they are
# consumed and ignored: the full word list is composed and
# scanned, which is fail-closed against any single batch. Shell
# values visible in the same command are substituted into feeder
# words (the v1.18.0 approximation: quoting is not tracked, so a
# single-quoted $var is substituted too — it errs toward blocking,
# never toward missing a visible value).
#
# What stays a noted gap, not a claimed block: input that is not
# visible in the command — find / ls output, a file (`cat file |
# xargs ...`, `xargs -a file ...`), a variable with no visible
# assignment, and -d with a value that does not decode to exactly
# one char (verified against the local xargs: it refuses such a
# value with exit 1 and runs nothing, so skipping the invocation
# is safe, not a bypass). This pass can only add blocks, never
# remove one.
#
# v1.23.0: a heredoc feeding xargs is attributed by operator
# position now, not by counting heredocs in the command: with
# more than one heredoc v1.19.0 could not tell which body was a
# stage's stdin and skipped the invocation, so `xargs -I{}
# sh -c '{}' <<B` with a `shutdown` body sailed through whenever
# another heredoc appeared anywhere in the command. Bodies
# follow their operators in source order, so the operator's
# offset in the whole command picks the body, and redirects
# apply left to right with the last one winning (`cat <<A <<B`
# reads B, `cat <<<x <<B` reads B's body). A stage whose offset
# cannot be located is skipped, never misattributed.


def _split_pipes(piece: str) -> list[str]:
    """Split `piece` into pipeline stages on top-level | / |& only.

    Mirrors _split_top_level's quote/paren tracking: a | inside
    quotes, backticks, $(), ${} or a subshell is not a pipe, and ||
    is a separator, not a pipe.
    """
    parts: list[str] = []
    start = 0
    i = 0
    n = len(piece)
    paren = 0
    brace = 0
    while i < n:
        ch = piece[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            i = _skip_squote(piece, i)
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if piece[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if piece[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if ch == "$" and i + 1 < n and piece[i + 1] == "'":
            i = _skip_ansi_c(piece, i)
            continue
        if ch == "`":
            close = _backtick_close(piece, i)
            i = n if close is None else close + 1
            continue
        if ch == "(":
            paren += 1
            i += 1
            continue
        if ch == ")":
            paren = max(0, paren - 1)
            i += 1
            continue
        if ch == "{":
            brace += 1
            i += 1
            continue
        if ch == "}":
            brace = max(0, brace - 1)
            i += 1
            continue
        if paren == 0 and brace == 0:
            if piece[i:i + 2] == "||":
                i += 2
                continue
            if piece[i:i + 2] == "|&" or ch == "|":
                parts.append(piece[start:i])
                i += 2 if piece[i:i + 2] == "|&" else 1
                start = i
                continue
        i += 1
    parts.append(piece[start:])
    return parts


def _decode_backslash_escapes(text: str, hex_ok: bool) -> tuple[str, bool]:
    """Decode \\a \\b \\f \\n \\r \\t \\v \\\\ \\e \\0ooo (and \\xHH
    when hex_ok) in `text`. Returns (decoded, stopped): \\c stops
    output here, so the caller drops everything after it (and, for
    echo, the trailing newline). An unknown escape stays literal,
    the way dash leaves it. \\x is only decoded when hex_ok: dash
    echo does not decode it, so decoding it there would turn a
    literal '\\x2f' into a slash that is never a slash at runtime.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    simple = {
        "a": "\x07", "b": "\x08", "e": "\x1b", "f": "\x0c",
        "n": "\n", "r": "\r", "t": "\t", "v": "\x0b",
        "\\": "\\", "'": "'", '"': '"',
    }
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        esc = text[i + 1]
        if esc == "c":
            return "".join(out), True
        if esc in simple:
            out.append(simple[esc])
            i += 2
        elif esc == "0":
            j = i + 1
            digits = ""
            while j < n and len(digits) < 3 and text[j] in "01234567":
                digits += text[j]
                j += 1
            out.append(chr(int(digits, 8) & 0xFF))
            i = j
        elif esc == "x" and hex_ok:
            j = i + 2
            digits = ""
            while j < n and len(digits) < 2 and text[j] in "0123456789abcdefABCDEF":
                digits += text[j]
                j += 1
            if digits:
                out.append(chr(int(digits, 16)))
                i = j
            else:
                out.append("x")
                i += 2
        else:
            out.append("\\")
            out.append(esc)
            i += 2
    return "".join(out), False


def _echo_output_text(
    args: list[str], raw_word: str, shell_assigns: dict[str, str]
) -> str:
    """Stdout text of an echo feeder: its args joined with spaces.

    A bare `echo` is dash's builtin (escapes decoded, only -n is
    a flag); an absolute path is coreutils echo (escapes only
    with -e, -n / -e / -E may cluster). Shell values visible in
    the same command are substituted into the words first.
    """
    builtin = "/" not in raw_word
    decode = builtin
    newline = True
    i = 0
    while i < len(args):
        a = args[i]
        if builtin:
            if a == "-n":
                newline = False
                i += 1
                continue
            break
        if len(a) > 1 and a[0] == "-" and all(c in "neE" for c in a[1:]):
            if "n" in a:
                newline = False
            if "e" in a:
                decode = True
            if "E" in a:
                decode = False
            i += 1
            continue
        break
    words: list[str] = []
    for a in args[i:]:
        sub = _substitute_shell_vars(a, shell_assigns)
        words.append(sub if sub is not None else a)
    text = " ".join(words)
    if decode:
        text, stopped = _decode_backslash_escapes(text, hex_ok=False)
        if stopped:
            return text
    if newline:
        text += "\n"
    return text


def _printf_once(fmt: str, args: list[str]) -> tuple[str, int]:
    """One pass of the format over `args`; returns (text, used).

    Only the directives a feeder plausibly uses are modelled
    exactly (%s %d %i %c %x %o %b %%); anything else consumes an
    argument and yields it as-is, so the text stays visible
    rather than vanishing. A directive with no argument left
    yields its empty / zero default.
    """
    out: list[str] = []
    i = 0
    n = len(fmt)
    used = 0
    while i < n:
        ch = fmt[i]
        if ch != "%" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        if fmt[i + 1] == "%":
            out.append("%")
            i += 2
            continue
        j = i + 1
        while j < n and fmt[j] in "-+ #0":
            j += 1
        while j < n and fmt[j].isdigit():
            j += 1
        if j < n and fmt[j] == ".":
            j += 1
            while j < n and fmt[j].isdigit():
                j += 1
        if j >= n:
            out.append("%")
            i += 1
            continue
        conv = fmt[j]
        arg = args[used] if used < len(args) else None
        if conv == "s":
            out.append(arg if arg is not None else "")
            used += 1
        elif conv in "di":
            try:
                out.append(str(int(arg, 10)) if arg is not None else "0")
            except ValueError:
                out.append("0")
            used += 1
        elif conv == "c":
            out.append(arg[0] if arg else "")
            used += 1
        elif conv in "xX":
            try:
                v = int(arg, 10) if arg is not None else 0
                out.append(format(v, "x" if conv == "x" else "X"))
            except ValueError:
                out.append("0")
            used += 1
        elif conv == "o":
            try:
                v = int(arg, 10) if arg is not None else 0
                out.append(format(v, "o"))
            except ValueError:
                out.append("0")
            used += 1
        elif conv == "b":
            decoded, _stopped = _decode_backslash_escapes(
                arg if arg is not None else "", hex_ok=True
            )
            out.append(decoded)
            used += 1
        else:
            out.append(arg if arg is not None else "")
            used += 1
        i = j + 1
    return "".join(out), used


def _printf_output_text(args: list[str], shell_assigns: dict[str, str]) -> str:
    """Stdout text of a printf feeder: format filled from its args.

    The format is reused cyclically while arguments remain, the
    way printf does; a format with no directives prints once and
    ignores extra arguments. Backslash escapes in the format (and
    in %b arguments) are decoded; \\c stops output.
    """
    if not args:
        return ""
    fmt = args[0]
    sub = _substitute_shell_vars(fmt, shell_assigns)
    if sub is not None:
        fmt = sub
    fmt, stopped = _decode_backslash_escapes(fmt, hex_ok=True)
    if stopped:
        return fmt
    fmt_args = [
        _substitute_shell_vars(a, shell_assigns) or a for a in args[1:]
    ]
    out: list[str] = []
    argi = 0
    while True:
        chunk, used = _printf_once(fmt, fmt_args[argi:])
        out.append(chunk)
        argi += used
        if argi >= len(fmt_args) or used == 0:
            break
    return "".join(out)


_XARGS_VALUE_SHORTS = set("adEILnPs")
_XARGS_OPTIONAL_SHORTS = set("eil")
_XARGS_BOOL_SHORTS = set("orptx0")
_XARGS_VALUE_LONGS = {
    "--arg-file", "--delimiter", "--max-args", "--max-lines",
    "--max-procs", "--max-chars", "--process-slot-var",
}
_XARGS_OPTIONAL_LONGS = {"--eof", "--replace"}
_XARGS_BOOL_LONGS = {
    "--null", "--no-run-if-empty", "--verbose", "--exit",
    "--open-tty", "--interactive", "--show-limits", "--help",
    "--version",
}


def _xargs_delimiter(value: Optional[str]) -> str:
    """The single delimiter char of a -d value, or "" if unknowable.

    xargs decodes backslash escapes in the value, so '-d \\n' is
    a newline, not a backslash. "" means the invocation cannot be
    composed and is skipped, never silently split another way.
    """
    if value is None:
        return ""
    if len(value) == 1:
        return value
    decoded, _stopped = _decode_backslash_escapes(value, hex_ok=True)
    return decoded if len(decoded) == 1 else ""


def _apply_xargs_value(parsed: dict, flag: str, value: Optional[str]) -> None:
    """Apply one xargs value-taking flag to `parsed`."""
    if flag in ("-a", "--arg-file"):
        parsed["arg_file"] = True
    elif flag in ("-d", "--delimiter"):
        parsed["delimiter"] = _xargs_delimiter(value)
    elif flag in ("-E", "--eof", "-e"):
        # -E takes its value (separate word or attached); -e /
        # --eof with no = value means no EOF string.
        parsed["eof"] = value
    elif flag in ("-I", "--replace", "-i"):
        parsed["replace"] = value if value is not None else "{}"
    # -L / -l / -n / -P / -s only batch the runs; they never
    # change what any single run executes, so their values are
    # consumed and dropped.


def _parse_xargs_args(words: list[str]) -> dict:
    """Parse xargs's flags from `words` (after the xargs word).

    Flag parsing follows xargs's own --help (verified locally):
    -a / -d / -E / -I / -L / -n / -P / -s take a required value
    (rest of the cluster, or the next word); -e / -i / -l take
    an optional value (rest of the cluster only, defaulting to no
    EOF string / "{}" / one line); -o / -p / -r / -t / -x / -0
    are boolean. Long flags take = values, or the next word when
    the value is required; --eof / --replace take a value only in
    = form. `--` ends the flags. An unknown flag is skipped as
    one token, the same convention as the wrapper parsers. The
    result holds the command word xargs will run (None when it
    defaults to echo), its initial args, and the input-shaping
    flags: -I replace string, -0, -d delimiter ("" when the
    value did not decode to one char), -E eof string, -a (input
    from a file), -r.
    """
    parsed = {
        "command": None,
        "initial_args": [],
        "replace": None,
        "null": False,
        "delimiter": None,
        "eof": None,
        "arg_file": False,
        "no_run_if_empty": False,
    }
    i = 0
    n = len(words)
    while i < n:
        tok = words[i]
        if tok == "--":
            i += 1
            break
        if tok.startswith("--"):
            name, eq, val = tok.partition("=")
            if name in _XARGS_BOOL_LONGS:
                if name == "--null":
                    parsed["null"] = True
                elif name == "--no-run-if-empty":
                    parsed["no_run_if_empty"] = True
                i += 1
                continue
            if name in _XARGS_VALUE_LONGS:
                if eq:
                    value: Optional[str] = val
                    i += 1
                elif i + 1 < n:
                    value = words[i + 1]
                    i += 2
                else:
                    value = None
                    i += 1
                _apply_xargs_value(parsed, name, value)
                continue
            if name in _XARGS_OPTIONAL_LONGS:
                value = val if eq else None
                _apply_xargs_value(parsed, name, value)
                i += 1
                continue
            # Unknown long flag: skip one token.
            i += 1
            continue
        if tok.startswith("-") and tok != "-":
            j = 1
            consumed_next = False
            while j < len(tok):
                c = tok[j]
                if c in _XARGS_BOOL_SHORTS:
                    if c == "0":
                        parsed["null"] = True
                    elif c == "r":
                        parsed["no_run_if_empty"] = True
                    j += 1
                    continue
                if c in _XARGS_VALUE_SHORTS:
                    if j + 1 < len(tok):
                        value = tok[j + 1:]
                    elif i + 1 < n:
                        value = words[i + 1]
                        consumed_next = True
                    else:
                        value = None
                    _apply_xargs_value(parsed, "-" + c, value)
                    j = len(tok)
                    continue
                if c in _XARGS_OPTIONAL_SHORTS:
                    value = tok[j + 1:] if j + 1 < len(tok) else None
                    _apply_xargs_value(parsed, "-" + c, value)
                    j = len(tok)
                    continue
                # Unknown short letter: skip the whole cluster.
                j = len(tok)
            i += 2 if consumed_next else 1
            continue
        break
    if i < n:
        parsed["command"] = words[i]
        parsed["initial_args"] = words[i + 1:]
    return parsed


def _stage_stdin_text(
    stage: str,
    stage_offset: Optional[int],
    heredocs: list[tuple[str, str, int]],
) -> Optional[str]:
    """Input text arriving on `stage`'s stdin via <<< or <<, or None.

    Attribution is by operator position: `heredocs` holds every
    heredoc / herestring in the whole command with the offset of
    its operator, and a stage's stdin comes from the operators
    inside its own span [stage_offset, stage_offset + len(stage)).
    Bodies follow their operators in source order, so this holds
    with any number of heredocs in the command (v1.23.0: v1.19.0
    could only use the body when the command had exactly one).
    Redirects apply left to right and the last one wins, so a
    stage with several stdin redirects reads the last one's body
    — `cat <<A <<B` reads B, `cat <<<x <<B` reads B's body and
    `cat <<B <<<x` reads x (verified against the local shell).
    A herestring's word gets a trailing newline, the way xargs
    sees it as a line of input. An unlocatable stage (offset
    None) yields None, the same as an unknowable input.
    """
    if stage_offset is None:
        return None
    start = stage_offset
    end = stage_offset + len(stage)
    docs = [
        (kind, body)
        for kind, body, pos in heredocs
        if start <= pos < end
    ]
    if not docs:
        return None
    # Last redirect wins; its body is the stage's stdin.
    kind, body = docs[-1]
    return body + "\n" if kind == "herestring" else body


def _has_stdout_redirect(args: list[str]) -> bool:
    """True if `args` redirect the command's stdout elsewhere.

    A feeder whose stdout is redirected (`echo / > file | xargs
    ...`) sends nothing down the pipe, so its simulated text
    must not be composed: the pipe is empty. An unquoted `>`
    word is a redirect; a quoted or escaped one decodes to the
    same word, which errs toward an empty pipe — the safe side
    for composition, since an empty input cannot hide a target.
    """
    return any(re.match(r"^\d*>", a) for a in args)


def _feeder_input_text(
    stage: str,
    stage_offset: Optional[int],
    heredocs: list[tuple[str, str, int]],
    shell_assigns: dict[str, str],
) -> Optional[str]:
    """Stdout text of the stage feeding xargs, or None if unknowable.

    Only literal feeders are modelled: echo / printf (simulated
    from their arguments), and cat with its stdin from a heredoc
    or herestring and no file arguments. Anything else (find, ls,
    a file, a variable with no visible assignment) is unknowable:
    the xargs invocation is skipped, a noted gap, not a claimed
    block.
    """
    words = _segment_words(stage)
    if not words:
        return None
    cmd_idx = _skip_wrappers(words)
    if cmd_idx is None:
        return None
    raw, decoded, _s, _e = words[cmd_idx]
    base = decoded.rsplit("/", 1)[-1]
    args = [w[1] for w in words[cmd_idx + 1:]]
    if _has_stdout_redirect(args):
        return ""
    if base == "echo":
        return _echo_output_text(args, raw, shell_assigns)
    if base == "printf":
        return _printf_output_text(args, shell_assigns)
    if base == "cat":
        rest = _filter_redirect_words(args)
        if any(not a.startswith("-") for a in rest):
            return None  # reads a file: content not visible
        return _stage_stdin_text(stage, stage_offset, heredocs)
    return None


def _truncate_at_eof(text: str, eof: Optional[str]) -> str:
    """`text` up to (not including) the first line equal to `eof`."""
    if eof is None:
        return text
    lines = text.split("\n")
    for k, ln in enumerate(lines):
        if ln == eof:
            return "\n".join(lines[:k])
    return text


def _xargs_input_words(text: str, parsed: dict) -> Optional[list[str]]:
    """Input items of `text` the way xargs splits them, or None.

    -0 splits on NULs, -d on its delimiter, otherwise on blanks
    with xargs's quote/backslash processing (shlex matches it: an
    unmatched quote makes xargs error out and run nothing, so
    that input yields None and the invocation is skipped). The
    -E EOF string truncates the input at the first matching line.
    Empty items are dropped: they cannot be a wipe target or a
    power word.
    """
    if parsed["delimiter"] == "":
        return None
    if parsed["null"] and parsed["delimiter"] is not None:
        return None  # -0 and -d together: xargs refuses
    if parsed["null"]:
        return [w for w in text.split("\0") if w]
    if parsed["delimiter"] is not None:
        return [w for w in text.split(parsed["delimiter"]) if w]
    text = _truncate_at_eof(text, parsed["eof"])
    try:
        return shlex.split(text)
    except ValueError:
        return None


def _xargs_input_lines(text: str, parsed: dict) -> Optional[list[str]]:
    """Input lines for -I mode, or None.

    -I reads lines (blank lines are skipped, verified against
    the local xargs); -0 / -d change the separator to NULs / the
    delimiter, and -E truncates at the first matching line.
    """
    if parsed["delimiter"] == "":
        return None
    if parsed["null"] and parsed["delimiter"] is not None:
        return None
    if parsed["null"]:
        parts = text.split("\0")
        if parts and parts[-1] == "":
            parts.pop()
        return parts
    if parsed["delimiter"] is not None:
        parts = text.split(parsed["delimiter"])
        if parts and parts[-1] == "":
            parts.pop()
        return parts
    text = _truncate_at_eof(text, parsed["eof"])
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [ln for ln in lines if ln.strip()]


def _check_xargs(
    command: str, cwd: Optional[Path] = None, depth: int = 0
) -> Optional[str]:
    """Denylist pass over the command xargs composes from its input.

    Per pipeline, an xargs stage's command and initial args are
    parsed, the input text is taken from a herestring / heredoc
    on the stage itself or from the preceding feeder stage, and
    the composed command (command + initial args + input words,
    or one command per input line with the -I string replaced)
    gets the full checks. A stage with no command runs echo and
    is safe; an unknowable input (find / ls / a file / an
    unresolvable variable) skips that invocation. Depth-capped;
    every composed string is strictly shorter than the command
    it came from, so recursion always terminates.
    """
    if depth >= _NESTED_MAX_DEPTH:
        return None
    shell_assigns = _assigned_literals(command)
    # Every heredoc / herestring in the command, with its operator
    # offset: that is what attributes a body to the stage that
    # redirected it, however many heredocs the command has.
    heredocs = _extract_heredocs(command)
    cursor = 0
    for piece in _split_top_level(command, split_pipes=False):
        # Pieces and stages are verbatim slices of `command`, in
        # order, so their offsets are found with an advancing
        # search; a stage whose offset cannot be located gets
        # None and its stdin is unknowable, never misattributed.
        piece_start = command.find(piece, cursor)
        if piece_start == -1:
            piece_start = None
        else:
            cursor = piece_start + len(piece)
        stages = _split_pipes(piece)
        stage_cursor = 0
        stage_offsets: list[Optional[int]] = []
        for stage in stages:
            rel = piece.find(stage, stage_cursor)
            if rel == -1:
                stage_offsets.append(None)
                continue
            stage_cursor = rel + len(stage)
            if piece_start is None:
                stage_offsets.append(None)
                continue
            off = piece_start + rel
            stage_offsets.append(
                off if command[off:off + len(stage)] == stage else None
            )
        for k, stage in enumerate(stages):
            words = _segment_words(stage)
            if not words:
                continue
            cmd_idx = _skip_wrappers(words)
            if cmd_idx is None:
                continue
            _raw, decoded, _s, _e = words[cmd_idx]
            if decoded.rsplit("/", 1)[-1] != "xargs":
                continue
            parsed = _parse_xargs_args([w[1] for w in words[cmd_idx + 1:]])
            if parsed["arg_file"]:
                continue  # input from a file: noted gap
            if parsed["command"] is None:
                continue  # default command is echo: safe
            text = _stage_stdin_text(stage, stage_offsets[k], heredocs)
            if text is None and k > 0:
                text = _feeder_input_text(
                    stages[k - 1], stage_offsets[k - 1], heredocs,
                    shell_assigns,
                )
            if text is None:
                continue  # input not visible: noted gap
            if parsed["replace"] is not None:
                lines = _xargs_input_lines(text, parsed)
                if lines is None:
                    continue
                for line in lines:
                    args = [
                        a.replace(parsed["replace"], line)
                        for a in parsed["initial_args"]
                    ]
                    composed = shlex.join([parsed["command"]] + args)
                    label = _check_all(composed, cwd, depth + 1)
                    if label:
                        return label
            else:
                input_words = _xargs_input_words(text, parsed)
                if input_words is None:
                    continue
                if not input_words and parsed["no_run_if_empty"]:
                    continue
                composed = shlex.join(
                    [parsed["command"]] + parsed["initial_args"] + input_words
                )
                label = _check_all(composed, cwd, depth + 1)
                if label:
                    return label
    return None


def _check_all(command: str, cwd: Optional[Path] = None, depth: int = 0) -> Optional[str]:
    """Every denylist pass over `command`, recursing into sub-strings.

    Raw, then command-word-normalized, then nested groups, -c /
    eval strings, interpreter code strings, heredoc bodies, power
    words on later lines of a multiline command, power words in
    any command position, and commands xargs composes from literal
    piped input — each pass only adds blocks. Sub-passes are depth-capped and every
    sub-string they recurse into is strictly shorter than its
    parent, so recursion always terminates.
    """
    label = _check_dangerous_once(command, cwd)
    if label:
        return label
    normalized = _normalize_command(command)
    if normalized != command:
        label = _check_dangerous_once(normalized, cwd)
        if label:
            return label
    label = _check_nested(command, cwd, depth)
    if label:
        return label
    label = _check_command_strings(command, cwd, depth)
    if label:
        return label
    label = _check_interpreter_strings(command, cwd, depth)
    if label:
        return label
    label = _check_heredocs(command, cwd, depth)
    if label:
        return label
    label = _check_multiline_power(command)
    if label:
        return label
    label = _check_command_position_power(command)
    if label:
        return label
    return _check_xargs(command, cwd, depth)


def _check_dangerous_once(command: str, cwd: Optional[Path] = None) -> Optional[str]:
    """One pass of the denylist over `command` (raw or normalized)."""
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


def check_dangerous(command: str, cwd: Optional[Path] = None) -> Optional[str]:
    """Return a human-readable block reason, or None if allowed.

    `cwd` is the already-resolved workdir for the request. When it is
    the workdir base itself, wipe-everything targets (`rm -rf *`,
    `find . -delete`) are blocked too; in a subdirectory they stay
    allowed. Pass no cwd to skip only that workdir-root rule.

    Passes (each only adds blocks): the raw command first, then
    (v1.8.0) the same checks on the command with each segment's
    command word decoded, so a fragmented command name (`r\\m -rf
    /`) is caught exactly like the plain spelling, then (v1.9.0)
    the same checks over every command hidden inside a
    substitution, subshell, or process substitution, recursively,
    then (v1.10.0) the same checks over every command string passed
    to bash/sh -c or eval, recursively, then (v1.11.0) the same
    checks over interpreter code strings, variable-resolved command
    strings, and heredoc/herestring bodies fed to interpreters,
    then (v1.12.0) a heredoc-aware line scan for power commands on
    later lines of a plain multiline command, then (v1.13.0) a
    command-position scan for power commands behind wrappers,
    control keywords, brace groups, function bodies, case patterns,
    and find -exec primaries, then (v1.14.0) the same
    command-position scan extended to chroot / nsenter /
    systemd-run wrappers, whose command word follows their flags
    and (for chroot) the new root, and the shell / interpreter
    -c extraction extended past those wrappers (and past
    timeout / nohup / exec / coproc / busybox) to the command
    they run, then (v1.16.0) the same command-position scan
    extended to unshare / setpriv / runuser wrappers, whose
    command word follows their flags (and, for runuser, the user),
    with runuser's -c / --command / --session-command value
    scanned as a shell command string of its own, and the shell /
    interpreter -c extraction and the fragmented-name splice
    extended past them the same way, then (v1.17.0) the env -S /
    --split-string split string scanned with the full checks (it
    is argv, split the way env splits it), so interpreter -c /
    -e code behind it is caught, with --split-string checked the
    same way and -S found inside a short-option cluster
    (`-iS '...'`), then (v1.19.0) the same checks over the command
    xargs composes from literal piped input (echo / printf /
    heredoc / herestring feeding it, with -I template
    substitution), so a wipe target or power command arriving as
    data is caught, while a bare `echo ... | xargs` (which only
    ever runs echo) stays allowed, then (v1.20.0) direct wipe calls
    with a variable target (resolved from a literal assignment in
    the code or the shell command, or blocked as opaque), the
    `path=` keyword form, and every wipe call in the code, not
    just the first, then (v1.21.0) a direct wipe call reached
    through an import alias (`from shutil import rmtree` with an
    `as` alias, multi-name / parenthesised import or `*`, and
    `import shutil as <alias>`), checked the same way as
    `shutil.rmtree` itself, then (v1.23.0) heredoc input to xargs
    attributed by operator position, so a stage's stdin is its own
    heredoc's body however many heredocs the command has (last
    redirect wins on a stage), closing the multi-heredoc bypass.
    """
    if ALLOW_DANGEROUS:
        return None
    return _check_all(command, cwd)


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


def _read_meminfo() -> Optional[dict]:
    """Memory totals from /proc/meminfo (Linux only); None elsewhere.

    Returns total and available bytes, or None when the file is
    missing or unreadable (non-Linux hosts, containers without
    /proc) or lacks the fields we need.
    """
    fields: dict[str, int] = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0].endswith(":"):
                    try:
                        fields[parts[0][:-1]] = int(parts[1])
                    except ValueError:
                        continue
    except OSError:
        return None
    if "MemTotal" not in fields or "MemAvailable" not in fields:
        return None
    return {
        "total_bytes": fields["MemTotal"] * 1024,
        "available_bytes": fields["MemAvailable"] * 1024,
    }


@app.get("/system")
def system_info(request: Request, x_api_key: str = Header(default="")):
    """Read-only host snapshot: load, memory, disk. Auth required.

    Disk figures are for the filesystem holding the workdir base, so
    the phone shows the disk its commands actually write to. Memory
    is null on hosts without /proc/meminfo; load is null where
    getloadavg is unavailable. Nothing here runs a command.
    """
    require_key(request, x_api_key)
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    mem = _read_meminfo()
    disk = shutil.disk_usage(_base_dir())
    return {
        "ok": True,
        "service": "linux-remote",
        "version": VERSION,
        "host": socket.gethostname(),
        "uptime_s": int(time.time() - STARTED_AT),
        "cpu_count": os.cpu_count(),
        "load_1": load1,
        "load_5": load5,
        "load_15": load15,
        "memory": None if mem is None else {
            "total_bytes": mem["total_bytes"],
            "available_bytes": mem["available_bytes"],
            "used_pct": (
                round(100 * (1 - mem["available_bytes"] / mem["total_bytes"]), 1)
                if mem["total_bytes"] else None
            ),
        },
        "disk": {
            "total_bytes": disk.total,
            "free_bytes": disk.free,
            "used_pct": (
                round(100 * (1 - disk.free / disk.total), 1)
                if disk.total else None
            ),
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
