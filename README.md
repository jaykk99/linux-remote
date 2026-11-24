Live: https://linux-remote-app.onrender.com/

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

First run: set a 4-6 digit PIN (tap the checkmark key to finish a 4 or 5
digit PIN), confirm it, then paste the API key and
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

- `GET /health` - no auth, returns
  `{"ok": true, "service": "linux-remote", "version": "...", "host": "...", "uptime_s": 123}`
- `POST /exec` - header `X-API-Key: <key>`,
  body `{"command": "ls ~", "cwd": "projects/app", "timeout_s": 30}`
  (`cwd` optional, must stay inside the workdir base; `timeout_s`
  optional, 1..server max, can only shorten the `LR_TIMEOUT` ceiling),
  returns `{"stdout": "...", "stderr": "...", "exit_code": 0,
  "truncated": false, "duration_ms": 12}`.
  Exit code 124 means the command hit the server timeout.
- `POST /rotate-key` - header `X-API-Key: <current key>`. Mints a fresh
  key, invalidates the old one immediately, and returns
  `{"ok": true, "api_key": "<new key>"}`. Save the new key in the phone
  app right away.
- `GET /recent?n=50` - header `X-API-Key: <key>`. Last `n` audit-log
  lines, newest first.
- `GET /stats?n=500` - header `X-API-Key: <key>`. Analytics over the last
  `n` audit-log lines (max 2000): total/successful/failed/blocked counts,
  success rate, average duration, top commands, per-day counts. The phone
  app shows these as a summary strip in the activity view.
- `GET /system` - header `X-API-Key: <key>`, read-only host snapshot:
  load averages, CPU count, memory (total/available/used %) from
  `/proc/meminfo`, and disk usage of the filesystem holding the workdir
  base. Memory is null on hosts without `/proc/meminfo`; load is null
  where `getloadavg` is unavailable. The phone app shows load, memory
  used, and free disk as cards in the activity view.
- `GET /processes?n=20&sort=cpu` - header `X-API-Key: <key>`, read-only
  top processes by CPU time (`sort=cpu`, default) or resident memory
  (`sort=mem`); `n` clamps to 1..100. Each row has pid, user, name,
  full command line, state, cpu_seconds, and mem_bytes, read straight
  from `/proc` (empty list on hosts without `/proc`). The phone app
  lists the top 5 in the activity view.
- `GET /network` - header `X-API-Key: <key>`, read-only network
  snapshot: per-interface IPv4 address, netmask, and MAC (ioctl) plus
  rx/tx byte and packet counters from `/proc/net/dev`, and the default
  gateway and its interface from `/proc/net/route`. Addresses are null
  where an interface has none; counters are 0 and the list empty on
  hosts without `/proc/net`. The phone app lists interfaces in the
  activity view, marking the gateway interface.
- `GET /disk` - header `X-API-Key: <key>`, read-only per-mount disk
  usage: device, mountpoint, fstype, total/free bytes, and used
  percent, from `/proc/mounts` and `statvfs`. Mounts `statvfs` cannot
  read, and filesystems reporting zero size, are skipped; the list is
  empty on hosts without `/proc/mounts`. The phone app lists mounts
  in the activity view.
- `GET /services` - header `X-API-Key: <redacted>
  snapshot: one row per installed systemd `*.service` unit (name,
  Description from its `[Unit]` section, enabled via a `*.wants`
  entry, masked via a `/dev/null` symlink, active where systemd has
  a live cgroup for it, main pid from that cgroup). The list is
  empty on hosts without systemd unit directories. The phone app
  lists services in the activity view, active ones first.
- `GET /uptime` - header `X-API-Key: <key>`, read-only host uptime:
  seconds since the host booted from `/proc/uptime`, and the boot
  time (UTC, ISO 8601) from the `btime` line of `/proc/stat`. Both
  are null on hosts without `/proc/uptime`; boot time is null where
  the `btime` line is absent. The phone app shows host uptime as a
  card in the activity view.
- `GET /cpu` - header `X-API-Key: <key>`, read-only CPU snapshot:
  model name, core count, and clock from `/proc/cpuinfo`, plus the
  aggregate and per-core time counters from `/proc/stat` (user,
  nice, system, idle, iowait, irq, softirq, steal, total ticks)
  with `usage_pct`, the share of time spent working since boot.
  Identity fields are null/0 on hosts without `/proc/cpuinfo`;
  overall is null and the list empty where `/proc/stat` has no
  usable cpu line. The phone app shows overall CPU usage as a card
  and lists per-core usage in the activity view.
- `GET /memory` - header `X-API-Key: <key>`, read-only memory
  breakdown: total, free, available, buffers, and cached bytes
  from `/proc/meminfo`, plus swap total/free, with used bytes and
  `used_pct` (total minus available, matching `/system`) and the
  same for swap. All fields are null on hosts without
  `/proc/meminfo` or without a MemTotal line; buffers, cached,
  and swap default to 0 where their lines are absent, and
  `swap_used_pct` is null where there is no swap. The phone app
  shows memory and swap cards in the activity view, and a swap
  card in the stats strip where the host has swap.
- `GET /temperature` - header `X-API-Key: <key>`, read-only
  thermal zone temperatures: one row per `thermal_zoneN` under
  `/sys/class/thermal` (zone name, sensor type from its `type`
  file, temperature in degrees C from its `temp` file in
  millidegrees), plus `hottest`, the warmest zone. The list is
  empty on hosts without thermal zones. The phone app lists the
  zones in the activity view, naming the hottest one.
- `GET /battery` - header `X-API-Key: <key>`, read-only battery
  charge state: one row per battery under `/sys/class/power_supply`
  (status, capacity percent, present flag, voltage/current/power,
  energy now and full in Wh, or charge now and full in Ah where
  the battery reports charge instead of energy, technology, cycle
  count, manufacturer/model), plus `available`, true when at
  least one battery is present, and `lowest`, the present battery
  with the lowest reported capacity. AC adapters and other
  non-battery supplies are skipped. On hosts with no battery at
  all the list is empty, `available` is false, and `lowest` is
  null: an honest no-battery state, not an error. The phone app
  shows the lowest charge as a card in the stats strip and lists
  the batteries in the activity view, saying so where the host
  has no battery.
- `GET /gpu` - header `X-API-Key: <key>`, read-only GPU
  inventory: one row per `card<n>` under `/sys/class/drm`
  (PCI vendor/device IDs, vendor name where the ID is known,
  kernel driver name, and total VRAM in bytes where the driver
  reports it: amdgpu `mem_info_vram_total`, or the NVIDIA proc
  info `Video Memory` line; integrated GPUs report none, which
  is null, not zero), plus `available`, true when at least one
  GPU is found. Render/control nodes, connector symlinks, and
  the `version` file are skipped. On hosts with no GPU at all
  the list is empty and `available` is false: an honest no-GPU
  state, not an error. The phone app lists the GPUs in the
  activity view, saying so where the host has no GPU.
- `GET /fans` - header `X-API-Key: <key>`, read-only fan speeds:
  one row per `fan<n>_input` under `/sys/class/hwmon` (chip name
  from the device's `name` file, fan label, speed in RPM, min/max
  RPM limits where the driver reports them, and PWM duty cycle as
  a percent from the raw 0-255 value), plus `available`, true when
  at least one fan is found, and `fastest`, the fan with the
  highest reported RPM. Non-fan inputs are skipped. On hosts with
  no fans at all the list is empty and `available` is false: an
  honest no-fan state, not an error. The phone app lists the fans
  in the activity view, saying so where the host has no fans.

## Configuration (env vars)

- `PORT` - listen port (default 8000)
- `LR_TIMEOUT` - per-command timeout in seconds (default 300)
- `LR_MAX_COMMAND_LEN` - max command length in chars (default 32768)
- `LR_MAX_OUTPUT_BYTES` - cap on captured stdout/stderr each
  (default 1048576); over-limit output is truncated with a notice
- `LR_MAX_BODY_BYTES` - max request body size (default 65536)
- `LR_RATE_LIMIT` / `LR_RATE_WINDOW` - failed-auth attempts per window
  in seconds before a temporary 429 ban (default 10 / 300)
- `LR_ALLOW_DANGEROUS=1` - disable the destructive-command denylist
  (default off)
- `LR_LOG_MAX_BYTES` - rotate `commands.log` past this size
  (default 5MB)
- `LR_WORKDIR` - base dir commands may run in (default `$HOME`);
  the `cwd` field in `/exec` must resolve inside it
- `LR_MAX_CONCURRENT` - max simultaneous `/exec` commands (default 8);
  extra commands get 503 while all slots are busy

## Security

Read this before running it:

- Whoever has the API key gets **full shell access** to this machine.
  Keep the key secret. It lives at `~/.linux-remote/key` with 0600 perms.
- Do **not** expose port 8000 to the public internet. Use Tailscale.
- The key is a bearer secret. If it leaks, hit **Rotate API key** in the
  phone app's settings (or `POST /rotate-key`) instead of restarting.
- Failed API-key attempts are rate limited per IP (temporary 429 bans),
  which blunts brute-force guessing.
- As a typo guard, the server blocks obviously destructive commands
  (`rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, raw disk writes, `mkfs`,
  fork bombs, `reboot`, ...). Also blocked: parent-dir deletes
  (`rm -rf ..`, `rm -rf /tmp/..`, `find / -delete`) and recursive
  permission wipes (`chmod -R 000 /`). Only the home-dir root itself is
  blocked; clearing a subdirectory like `rm -rf $HOME/cache` stays
  allowed, as does deleting one named sibling (`rm -rf ../build`).
  With cwd at the workdir base, wipe-everything targets (`rm -rf *`,
  `find . -delete`) are blocked too; in a subdirectory they stay allowed.
  Power commands on later lines of a multiline command are blocked as
  well; heredoc bodies fed to `cat` or a script file stay allowed data.
  The phone app shows the block reason. Set `LR_ALLOW_DANGEROUS=1` on
  the server to turn this off.
- Every command is audit-logged with timestamp, client IP, working dir,
  duration, and exit code to `~/.linux-remote/commands.log`
  (auto-rotated). View it from the phone via `GET /recent`.

## Phone app

- Tap a shortcut chip to run it; tap the `x` on a chip to remove it.
  Add your own shortcuts in Settings.
- Set a working directory in Settings to run every command from there.
- Each output card has a **Copy** button.
- The status pill shows the server's hostname and re-checks every
  minute, so a dropped Tailscale link shows up on its own.
- **Server profiles:** the Settings panel keeps a list of servers
  (name + URL + API key + working dir). Add one per machine and switch
  with the dropdown. Your old single-server settings migrate into a
  "Default" profile automatically.
- **Recent activity:** tap the &#8635; button in the top bar to browse
  the server's audit log (newest first) and re-run any command with one
  tap. Blocked destructive commands are shown in red and can't be
  re-run from there.
- **PIN lockout:** 8 wrong PINs in a row locks the unlock screen for
  60 seconds.
- Very long output is shortened for display (first 100k chars per
  stream) so the phone stays smooth; the server still caps and marks
  truncation separately.

## Live URL

https://linux-remote-app.onrender.com

Repo: https://github.com/jaykk99/linux-remote
