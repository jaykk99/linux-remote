# Dataset — nn-100h / linux-remote

Task: predict whether a shell command string will be **blocked** by the
destructive-command denylist (`server.check_dangerous`) or **allowed**,
from the command text alone. Triage only: `check_dangerous()` stays the
only gate; a low score never means a command is safe.

## Provenance (real repo data only, nothing invented)

- Rows: **844** (571 blocked / 273 allowed)
- Collection date: 2026-11-14 (repo at master `0bc4d76`, server v1.24.0)
- Source 1 — parametrized denylist tests: **824** rows from
  `tests/test_server.py` (`test_dangerous_blocked*` = blocked,
  `test_benign*` = allowed), parsed with `ast`, deduplicated
  (21 exact duplicates dropped, 573 blocked /
  272 allowed raw, 0 non-string lists skipped).
  The label is the verdict the test itself asserts against the live
  denylist through `/exec`.
- Source 2 — literal commands labeled by the real denylist:
  **20** extra rows (deduped: 26 already present,
  1 blank skipped) from literal `{"command": ...}` args in
  `tests/test_server.py`, the `README.md` example, and
  `app/index.html` `DEFAULT_QUICK` shortcuts, each labeled by running
  the repo's actual `server.check_dangerous(cmd, cwd=None)`.
  Running the repo's own denylist to label real commands is real data,
  not synthetic. No command was invented; no row was padded in.

## Label cross-check

Every parametrized row was re-run through the real `check_dangerous`
(cwd=None). **0** rows disagree with the test-asserted
label; the test label stays ground truth because those cases depend on
context the bare denylist call lacks (mainly the workdir-root wipe
rules, which only fire when cwd is the workdir base, e.g. `rm -rf *`,
`find . -delete`). Full list in `build_dataset.py` output / rerun.

## Split (frozen, seed 42, test frac 0.2)

GROUPED + stratified. Group = command family (first meaningful token
after stripping wrappers sudo/doas/env/timeout/nohup/setsid/watch/exec/
command). Whole families with >=3 rows are held out into test
(11 families: -i, -n, case, cmd='reboot';, find, foo=bar, if, nice, nsenter, python3, shred); families
with <3 rows stay in train. Train 664 rows, test
180 rows. The denylist is a deterministic rule, so a random
split would mostly measure rule memorization; holding out whole
families measures generalization to unseen command families. A test
accuracy of 1.000 would mean leakage, not success, and must be
investigated, never celebrated.

## Features (train.py, built from train rows only)

First-token one-hot (top 16 first tokens in TRAIN) + 51 whole-word
token flags + 37 substring/operator/path flags + 4 length counts
= 114 features. Label never enters features.

## Limits

- The data is the denylist test suite's own cases: the model learns
  past verdicts, not shell semantics. Unseen phrasings are guesses.
- Small data (844 rows): expect noisy per-experiment metrics;
  the 100h loop exists to average over many seeds/configs, not to
  chase a single lucky run.
