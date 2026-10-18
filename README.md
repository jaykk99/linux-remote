# linux-remote

Run shell commands on your Linux machine straight from your phone.

Two parts:

- `server.py` - FastAPI server that runs commands you send it.
- `app/` - installable phone app (PWA). Install it on your phone, set a PIN
  once, enter the API key and server URL once, then just unlock with your
  PIN and type commands.

## Phone app (install it)

The app is a PWA, so it installs like a real app:

1. **Serve the `app/` folder over HTTPS or localhost.** The server itself
   can do it: `cd app && python3 -m http.server 8080` on the Linux box,
   then open `http://<linux-tailscale-ip>:8080` on your phone.
   (Service workers need HTTPS or localhost. Tailscale IPs count as
   secure enough on Android Chrome.)
2. **Android Chrome:** tap the three-dot menu > "Add to Home screen" >
   "Install". It now opens fullscreen like a native app.
3. **iPhone Safari:** Share button > "Add to Home Screen".

First run: set a 4-6 digit PIN, confirm it, then paste the API key and
server URL. After that, every launch just asks for the PIN. The key and
URL stay saved on the phone. Tap the gear icon to change them or to lock
the app.

The PIN is stored as a SHA-256 hash, never in plaintext.

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

## Live URL

https://linux-remote-app.onrender.com

Repo: https://github.com/jaykk99/linux-remote
