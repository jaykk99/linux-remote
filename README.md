# linux-remote

Run shell commands on your Linux machine straight from your phone.

Two parts:

- `server.py` - FastAPI server that runs commands you send it.
- `app/index.html` - phone web app. Open it in your phone browser, type the
  server URL and API key, then type commands.

## Setup (on the Linux machine)

```bash
cd ~/workspace/linux-remote
pip install -r requirements.txt
./start.sh          # listens on 0.0.0.0:8000
./start.sh 9000     # or a custom port
```

On first run the server prints your API key once and saves it to
`~/.linux-remote/key`. Copy it into the phone app.

To regenerate the key: delete `~/.linux-remote/key` and restart the server.

Every command is logged to `~/.linux-remote/commands.log`.

## Remote access via Tailscale

Don't open port 8000 to the public internet. Use Tailscale instead:

1. Install Tailscale on the Linux machine and on your phone, sign in to the
   same account.
2. On the Linux machine, find its Tailscale IP: `tailscale ip -4`
3. In the phone app, set the server URL to `http://<that-ip>:8000`
4. Done. Traffic stays on your private Tailscale network.

## API

- `GET /health` - no auth, returns `{"ok": true}`
- `POST /exec` - header `X-API-Key: <key>`, body `{"command": "ls ~"}`,
  returns `{"stdout": "...", "stderr": "...", "exit_code": 0}`

## Security

Read this before running it:

- Whoever has the API key gets **full shell access** to this machine.
  Keep the key secret. It lives at `~/.linux-remote/key` with 0600 perms.
- Do **not** expose port 8000 to the public internet. Use Tailscale.
- The key is a bearer secret. If it leaks, delete the key file and restart
  to get a fresh one.
- There is deliberately no command filtering. This is your machine and your
  commands.
