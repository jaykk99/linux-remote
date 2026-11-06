# CHANGELOG — linux-remote server

Version history, newest first. Entries are one line each, taken from
the commit that shipped the version. The denylist only ever gets
stronger: a version never re-allows a command an earlier version
blocked.

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
