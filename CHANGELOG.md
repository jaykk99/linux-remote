# CHANGELOG — linux-remote server

Version history, newest first. Entries are one line each, taken from
the commit that shipped the version. The denylist only ever gets
stronger: a version never re-allows a command an earlier version
blocked.

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
