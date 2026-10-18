#!/bin/bash
# Start the linux-remote server.
# Usage: ./start.sh [port]
set -e
cd "$(dirname "$0")"
PORT="${1:-8000}"
export PORT
exec uvicorn server:app --host 0.0.0.0 --port "$PORT"
