"""linux-remote server.

Remote shell access from your phone. Whoever holds the API key gets
full shell access on this machine, so keep the key secret and never
expose this port to the public internet. Use Tailscale.

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000

Env:
    PORT        port to listen on (default 8000)
"""

from __future__ import annotations

import datetime
import os
import secrets
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DATA_DIR = Path.home() / ".linux-remote"
KEY_FILE = DATA_DIR / "key"
LOG_FILE = DATA_DIR / "commands.log"


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


app = FastAPI(title="linux-remote", lifespan=lifespan)

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


def get_or_create_key() -> str:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip()
    key = secrets.token_urlsafe(32)
    KEY_FILE.write_text(key + "\n")
    KEY_FILE.chmod(0o600)
    return key


API_KEY = get_or_create_key()


@app.on_event("startup")
def _announce() -> None:
    print("=" * 60)
    print("linux-remote server starting")
    print(f"API key: {API_KEY}")
    print(f"Key file: {KEY_FILE}")
    print("Save that key in the phone app. It is only printed here once.")
    print("=" * 60)


class ExecRequest(BaseModel):
    command: str


class ExecResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int


def _log_command(command: str, exit_code: int) -> None:
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    # Keep one command per log line: escape embedded newlines.
    safe = command.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        f.write(f"[{ts}] exit={exit_code} cmd={safe}\n")


@app.get("/health")
def health():
    return {"ok": True, "service": "linux-remote"}


@app.post("/exec", response_model=ExecResponse)
def exec_command(req: ExecRequest, x_api_key: str = Header(default="")):
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="bad or missing API key")
    command = (req.command or "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="empty command")
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, exit_code = "", "command timed out after 300s", 124
    except Exception as e:  # never leak a traceback, still log it
        stdout, stderr, exit_code = "", f"server error: {e}", 125
    _log_command(command, exit_code)
    return ExecResponse(stdout=stdout, stderr=stderr, exit_code=exit_code)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
