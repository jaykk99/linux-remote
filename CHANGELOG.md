# CHANGELOG — linux-remote server

Version history, newest first. Entries are one line each, taken from
the commit that shipped the version. The denylist only ever gets
stronger: a version never re-allows a command an earlier version
blocked.

## 1.33.0 — 2026-11-22
- New `GET /battery` endpoint (auth required, read-only): battery charge state from `/sys/class/power_supply` (status, capacity percent, present flag, voltage/current/power, energy now/full in Wh or charge now/full in Ah where the battery reports charge instead of energy, technology, cycle count, manufacturer/model), plus `available`, true when at least one battery is present, and `lowest`, the present battery with the lowest reported capacity; AC adapters and other non-battery supplies are skipped, a missing or malformed file yields null for that field, a missing `type` file falls back to the `BAT` directory name, and out-of-range capacity is treated as null. On hosts with no battery at all (desktops, VMs, containers) the list is empty, `available` is false, and `lowest` is null: an honest no-battery state, not an error. The phone app shows the lowest charge as a card in the stats strip and lists the batteries in the activity view, saying so where the host has no battery.

## 1.32.0 — 2026-11-20
- New `GET /temperature` endpoint (auth required, read-only): thermal zone temperatures from `/sys/class/thermal` (zone name, sensor type, temp in degrees C from millidegree `temp` files, rounded to one decimal), plus `hottest`, the warmest zone; empty list where the host has no thermal zones, malformed zones skipped, missing type falls back to the zone directory name. The phone app lists the zones in the activity view, naming the hottest one.

## 1.31.0 — 2026-11-20
- New `GET /memory` endpoint (auth required, read-only): full memory breakdown from `/proc/meminfo` (total, free, available, buffers, cached, swap total/free, used bytes and used_pct for memory and swap; used is total minus available, matching `/system`). All fields null where `/proc/meminfo` is absent or lacks MemTotal; MemAvailable falls back to MemFree, buffers/cached/swap default to 0 where absent, swap_used_pct null with no swap. The phone app shows memory and swap cards in the activity view, plus a swap card in the stats strip where the host has swap.

## 1.30.0 — 2026-11-19
- New `GET /cpu` endpoint (auth required, read-only): CPU model name, core count, and clock from `/proc/cpuinfo`, plus the aggregate and per-core CPU time counters from `/proc/stat` (user, nice, system, idle, iowait, irq, softirq, steal, total ticks) with `usage_pct`, the share of time spent working since boot (idle counts idle + iowait; a zero total is 0.0). Identity fields are null/0 where `/proc/cpuinfo` is absent; overall is null and the list empty where `/proc/stat` has no usable cpu line; malformed core rows are skipped, short rows pad missing fields to 0. The phone app shows overall CPU usage as a card in the activity view and lists per-core usage under the services list.

## 1.29.0 — 2026-11-18
- New `GET /uptime` endpoint (auth required, read-only): host uptime in seconds from `/proc/uptime` and the boot time (UTC, ISO 8601) from the `btime` line of `/proc/stat`; both null where `/proc/uptime` is absent, boot time null where the `btime` line is absent. This is host uptime, distinct from the server-process uptime `/system` and `/health` report as `uptime_s`. The phone app shows host uptime as a card in the activity view.

## 1.28.0 — 2026-11-18
- New `GET /services` endpoint (auth required, read-only): installed systemd service units (name, Description from [Unit], enabled via *.wants, masked via /dev/null symlink, active where systemd has a live cgroup, main pid from cgroup.procs), sorted by name, from the systemd unit dirs in /etc > /run > /usr/lib > /lib precedence; empty list where systemd unit directories are absent. The phone app lists services in the activity view, active first.

## 1.27.0 — 2026-11-17
- New `GET /disk` endpoint (auth required, read-only): per-mount disk usage (device, mountpoint, fstype, total/free bytes, used percent) from `/proc/mounts` and statvfs, sorted by mountpoint; `/proc/mounts` octal escapes (\040 space, \011 tab, \012 newline, \134 backslash) decoded, duplicate mountpoints deduped, mounts statvfs cannot read and zero-size filesystems skipped, empty list where `/proc/mounts` is absent. The phone app lists mounts in the activity view.

## 1.26.0 — 2026-11-16
- New `GET /network` endpoint (auth required, read-only): per-interface IPv4 address, netmask, and MAC (ioctl) plus rx/tx byte and packet counters from `/proc/net/dev`, and the default gateway and its interface from `/proc/net/route` (gateway hex decoded little-endian). Addresses are null where an interface has none; counters are 0 and the interface list empty where `/proc/net` is absent. The phone app lists interfaces in the activity view, marking the gateway interface.

## 1.25.0 — 2026-11-15
- New `GET /processes` endpoint (auth required, read-only): top processes by CPU time (`sort=cpu`, default) or resident memory (`sort=mem`), `n` clamped to 1..100; each row has pid, user, name, full command line, state, cpu_seconds, and mem_bytes, read straight from /proc (empty list where /proc is absent). The phone app lists the top 5 in the activity view.

## 1.24.0 — 2026-11-14
- New `GET /system` endpoint (auth required, read-only): load averages, CPU count, memory from /proc/meminfo, and disk usage of the workdir filesystem; the phone app shows load, memory used, and free disk as cards in the activity view. Memory/load report null where the host has no /proc/meminfo or getloadavg.

## 1.23.0 — 2026-11-12
- Heredoc input to xargs attributed by operator position (bodies follow their operators in source order; the last redirect wins on a stage), so a power command or wipe target fed to xargs from a heredoc is caught however many heredocs the command has; a dangerous body belonging to another stage's heredoc stays allowed, and a `-d` value that does not decode to exactly one char is verified refused by xargs itself, not a bypass.

## 1.22.0 — 2026-11-11
- The three remaining direct-wipe gaps are closed: `getattr(shutil, 'rmtree')(...)` dynamic lookups (literal attribute, or a bare name assigned `'rmtree'` in the same code, also via an `import shutil as` module alias), `path=` as a later keyword argument (`rmtree(ignore_errors=True, path='/')`, top-level arguments only), and node destructured wipe calls (`const {rmSync} = require('fs')` / `as` alias / `rmdirSync` / `require('node:fs')` / destructuring from an identifier bound to `require('fs')` / ESM `import {rmSync} from 'fs'` / `fs['rmSync']` bracket forms); targets resolve the same way (literal, variable from a literal assignment, home expression, or blocked as opaque).

## 1.21.0 — 2026-11-10
- Direct wipe calls reached through an import alias are caught the same way as `shutil.rmtree` itself (`from shutil import rmtree` bare / `as` alias / multi-name / parenthesised / `*`, and `import shutil as <alias>`); the target resolves the same way (literal, `path=` keyword, variable from a literal assignment, home expression, or blocked as opaque).

## 1.20.0 — 2026-11-09
- Direct wipe calls with a variable target resolved (literal assignment in the code or in the same shell command, `$name` from shell values; a variable with no visible value is blocked as opaque); the `path=` keyword form and a second wipe call after a benign first one are caught too, and perl's paren-less `rmtree $dir` form is covered.

## 1.19.0 — 2026-11-08
- Commands xargs composes from literal piped input are scanned with the full checks (echo / printf feeders simulated from their arguments, herestring / heredoc input, -I template substitution), so a wipe target or power command arriving as data is caught; a bare `echo ... | xargs` (which only ever runs echo) stays allowed.

## 1.18.0 — 2026-11-07
- Variable-valued sink arguments resolved (literal assignment in the code or in the same shell command, `$name` inside a string literal substituted from shell values); a sink argument that is a variable with no visible value is blocked as opaque.

## 1.17.0 — 2026-11-06
- env -S / --split-string split strings scanned with the full checks (they are argv, split the way env splits them), so interpreter -c / -e code behind them is caught; --split-string checked the same way and -S found inside a short-option cluster (`-iS '...'`).

## 1.16.0 — 2026-11-05
- Unshare / setpriv / runuser as power-command wrappers (command word follows their flags; runuser -c scanned as a command string).

## 1.15.0 — 2026-11-04
- Fragmented destructive name behind a power wrapper denylist bypass closed.

## 1.14.0 — 2026-11-03
- Chroot / nsenter / systemd-run as power-command wrappers.

## 1.13.0 — 2026-11-02
- Power command in any command position (behind wrappers, control keywords, brace groups, function bodies, case patterns, find -exec).

## 1.12.0 — 2026-11-01
- Power command on a later line of a multiline command.

## 1.11.0 — 2026-10-31
- Heredoc / interpreter -c / variable-only command-string denylist bypasses closed.

## 1.10.0 — 2026-10-30
- Bash -c / eval command-string denylist bypass closed.

## 1.9.0 — 2026-10-29
- Substitution / subshell denylist bypass closed.

## 1.8.0 — 2026-10-28
- Fragmented-command-name denylist bypass closed.

## 1.7.0 — 2026-10-27
- Shell-word denylist bypass closed.

## 1.6.0 — 2026-10-26
- Root-spelling denylist bypass closed.

## 1.5.0 — 2026-10-25
- Absolute-path denylist bypass closed.

## 1.4.0 — 2026-10-24
- Denylist + concurrency cap.

## 1.3.0 — 2026-10-23
- Denylist holes closed, /stats analytics endpoint.

## Before 1.3.0
- Initial linux-remote server + phone app, PWA with PIN lock, Render
  hosting, security hardening and the first test suite. No version
  numbers were recorded before 1.3.0.
