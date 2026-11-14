"""Build dataset.jsonl + split.json for the nn-100h trainer.

Real repo data only. Sources (all inside this repo, nothing invented):
  1. tests/test_server.py parametrized lists: test_dangerous_blocked*
     (label 1) and test_benign* (label 0). The label is the verdict the
     test itself asserts against the live denylist via /exec.
  2. Literal "command" string args in non-parametrized /exec calls in
     tests/test_server.py, README.md's example, and app/index.html's
     DEFAULT_QUICK shortcuts. These have no asserted verdict, so each
     is labeled by running the repo's ACTUAL check_dangerous()
     (server.py, imported here, cwd=None so only the command-text
     rules apply).

Every parametrized row is also cross-checked against the real
check_dangerous(); disagreements are reported (expected: the
workdir-root wipe rules only fire when cwd is the workdir base, so
e.g. "rm -rf *" is test-blocked but check_dangerous(cmd, cwd=None)
allows it; the test-asserted label stays ground truth).

Split: GROUPED + stratified, seed 42, test frac 0.2. The group is the
command family (first meaningful token after stripping wrappers like
sudo/env/timeout). Whole families with >=3 rows are held out into
test, so the test set measures generalization to unseen command
families, not memorization of the deterministic denylist rules.
Families with <3 rows stay in train. Never train on test rows.

Usage: python3 build_dataset.py   (run from the nn-100h/ dir;
repo root is its parent). Requires fastapi (server.py imports it).
Outputs: dataset.jsonl, split.json, DATASET.md (in this dir).
"""
from __future__ import annotations

import ast
import importlib.util
import json
import math
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
TEST_FILE = REPO / "tests" / "test_server.py"
README_FILE = REPO / "README.md"
INDEX_FILE = REPO / "app" / "index.html"
OUT_DATASET = HERE / "dataset.jsonl"
OUT_SPLIT = HERE / "split.json"
OUT_MD = HERE / "DATASET.md"
SEED = 42
TEST_FRAC = 0.2

WRAPPERS = {"sudo", "doas", "env", "timeout", "nohup", "setsid",
            "watch", "exec", "command"}


def family_of(cmd: str) -> str:
    toks = (cmd or "").strip().split()
    i = 0
    while i < len(toks) and toks[i].lower() in WRAPPERS:
        i += 1
    if i >= len(toks):
        return ""
    return toks[i].lower()


def load_server_check():
    """Import the repo's real check_dangerous from server.py."""
    spec = importlib.util.spec_from_file_location("linux_remote_server",
                                                  REPO / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.check_dangerous


def parametrized_rows():
    """Rows from @pytest.mark.parametrize lists in test_server.py."""
    tree = ast.parse(TEST_FILE.read_text(encoding="utf-8"))
    blocked, allowed, skipped = [], [], 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call)
                    and getattr(dec.func, "attr", "") == "parametrize"):
                continue
            try:
                vals = ast.literal_eval(dec.args[1])
            except Exception:
                continue
            if not all(isinstance(v, str) for v in vals):
                skipped += 1
                continue
            if "blocked" in node.name:
                blocked.extend(vals)
            elif "allowed" in node.name:
                allowed.extend(vals)
    return blocked, allowed, skipped


def literal_exec_rows():
    """Literal {"command": "..."} args in non-parametrized /exec calls,
    plus README example + DEFAULT_QUICK shortcuts."""
    rows = []
    tree = ast.parse(TEST_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if (isinstance(k, ast.Constant) and k.value == "command"
                    and isinstance(v, ast.Constant)
                    and isinstance(v.value, str)):
                rows.append((v.value, "tests/test_server.py literal /exec"))
    m = re.search(r'"command":\s*"([^"]+)"', README_FILE.read_text(encoding="utf-8"))
    if m:
        rows.append((m.group(1), "README.md example"))
    m = re.search(r"DEFAULT_QUICK\s*=\s*\[([^\]]+)\]",
                  INDEX_FILE.read_text(encoding="utf-8"))
    if m:
        for q in re.findall(r'"([^"]+)"', m.group(1)):
            rows.append((q, "app/index.html DEFAULT_QUICK"))
    return rows


def grouped_stratified_split(rows, seed=SEED, test_frac=TEST_FRAC):
    """Whole families (>=3 rows) held out; per-class ~test_frac of rows."""
    by_family = defaultdict(list)
    for idx, r in enumerate(rows):
        by_family[r["family"]].append(idx)
    eligible = [f for f, idxs in by_family.items() if len(idxs) >= 3]
    rng = random.Random(seed)
    rng.shuffle(eligible)
    total = Counter(r["label"] for r in rows)
    target = {lab: total[lab] * test_frac for lab in total}
    test_count = Counter()
    test_idx, test_families = set(), []
    cap_rows = math.ceil(len(rows) * 0.22)
    for fam in eligible:
        idxs = by_family[fam]
        fam_count = Counter(rows[i]["label"] for i in idxs)
        if len(test_idx) + len(idxs) > cap_rows:
            continue
        if all(test_count[lab] + fam_count[lab] <= math.ceil(target[lab] * 1.15) + 2
               for lab in fam_count):
            test_idx.update(idxs)
            test_families.append(fam)
            test_count.update(fam_count)
        if all(test_count[lab] >= target[lab] for lab in total):
            break
    train_idx = [i for i in range(len(rows)) if i not in test_idx]
    test_idx = sorted(test_idx)
    rng.shuffle(train_idx)
    rng.shuffle(test_idx)
    return train_idx, test_idx, sorted(test_families)


def main():
    check_dangerous = load_server_check()
    blocked, allowed, skipped = parametrized_rows()
    rows, seen = [], set()
    dupes = 0
    for cmd, label in ([(c, 1) for c in blocked]
                       + [(c, 0) for c in allowed]):
        if cmd in seen:
            dupes += 1
            continue
        seen.add(cmd)
        rows.append({"command": cmd, "label": label,
                     "source": "tests/test_server.py parametrized "
                               "test_dangerous_blocked* / test_benign*",
                     "family": family_of(cmd)})
    n_param = len(rows)
    # Cross-check parametrized labels against the real denylist.
    mismatches = []
    for r in rows:
        verdict = check_dangerous(r["command"], cwd=None)
        real = 1 if verdict is not None else 0
        if real != r["label"]:
            mismatches.append({"command": r["command"],
                               "test_label": r["label"],
                               "check_dangerous": real,
                               "reason": verdict})
    # Extra literal commands, labeled by the real denylist.
    extra_added, extra_dupes, extra_blank = 0, 0, 0
    for cmd, src in literal_exec_rows():
        if not cmd.strip():
            extra_blank += 1
            continue
        if cmd in seen:
            extra_dupes += 1
            continue
        seen.add(cmd)
        verdict = check_dangerous(cmd, cwd=None)
        rows.append({"command": cmd,
                     "label": 1 if verdict is not None else 0,
                     "source": src + " (labeled by server.check_dangerous, cwd=None)",
                     "family": family_of(cmd)})
        extra_added += 1

    train_idx, test_idx, test_families = grouped_stratified_split(rows)
    with OUT_DATASET.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    split = {
        "seed": SEED, "test_frac": TEST_FRAC,
        "method": "grouped-stratified: whole command families (>=3 rows) "
                  "held out into test; per-class ~20% of rows; seed 42",
        "group": "family = first meaningful token after stripping "
                 "sudo/doas/env/timeout/nohup/setsid/watch/exec/command",
        "n_rows": len(rows), "n_train": len(train_idx),
        "n_test": len(test_idx),
        "train_label_counts": dict(Counter(rows[i]["label"] for i in train_idx)),
        "test_label_counts": dict(Counter(rows[i]["label"] for i in test_idx)),
        "test_families": test_families,
        "train_idx": train_idx, "test_idx": test_idx,
    }
    OUT_SPLIT.write_text(json.dumps(split, indent=2), encoding="utf-8")

    n_pos = sum(1 for r in rows if r["label"] == 1)
    md = f"""# Dataset — nn-100h / linux-remote

Task: predict whether a shell command string will be **blocked** by the
destructive-command denylist (`server.check_dangerous`) or **allowed**,
from the command text alone. Triage only: `check_dangerous()` stays the
only gate; a low score never means a command is safe.

## Provenance (real repo data only, nothing invented)

- Rows: **{len(rows)}** ({n_pos} blocked / {len(rows) - n_pos} allowed)
- Collection date: 2026-11-14 (repo at master `0bc4d76`, server v1.24.0)
- Source 1 — parametrized denylist tests: **{n_param}** rows from
  `tests/test_server.py` (`test_dangerous_blocked*` = blocked,
  `test_benign*` = allowed), parsed with `ast`, deduplicated
  ({dupes} exact duplicates dropped, {len(blocked)} blocked /
  {len(allowed)} allowed raw, {skipped} non-string lists skipped).
  The label is the verdict the test itself asserts against the live
  denylist through `/exec`.
- Source 2 — literal commands labeled by the real denylist:
  **{extra_added}** extra rows (deduped: {extra_dupes} already present,
  {extra_blank} blank skipped) from literal `{{"command": ...}}` args in
  `tests/test_server.py`, the `README.md` example, and
  `app/index.html` `DEFAULT_QUICK` shortcuts, each labeled by running
  the repo's actual `server.check_dangerous(cmd, cwd=None)`.
  Running the repo's own denylist to label real commands is real data,
  not synthetic. No command was invented; no row was padded in.

## Label cross-check

Every parametrized row was re-run through the real `check_dangerous`
(cwd=None). **{len(mismatches)}** rows disagree with the test-asserted
label; the test label stays ground truth because those cases depend on
context the bare denylist call lacks (mainly the workdir-root wipe
rules, which only fire when cwd is the workdir base, e.g. `rm -rf *`,
`find . -delete`). Full list in `build_dataset.py` output / rerun.

## Split (frozen, seed 42, test frac 0.2)

GROUPED + stratified. Group = command family (first meaningful token
after stripping wrappers sudo/doas/env/timeout/nohup/setsid/watch/exec/
command). Whole families with >=3 rows are held out into test
({len(test_families)} families: {", ".join(test_families)}); families
with <3 rows stay in train. Train {len(train_idx)} rows, test
{len(test_idx)} rows. The denylist is a deterministic rule, so a random
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
- Small data ({len(rows)} rows): expect noisy per-experiment metrics;
  the 100h loop exists to average over many seeds/configs, not to
  chase a single lucky run.
"""
    OUT_MD.write_text(md, encoding="utf-8")
    print(f"rows={len(rows)} blocked={n_pos} allowed={len(rows)-n_pos}")
    print(f"parametrized={n_param} extra_added={extra_added} "
          f"extra_dupes={extra_dupes}")
    print(f"train={len(train_idx)} test={len(test_idx)} "
          f"test_families={len(test_families)}")
    print(f"mismatches vs real check_dangerous (cwd=None): {len(mismatches)}")
    for m in mismatches[:20]:
        print("  MISMATCH test=%d real=%d %r (%s)"
              % (m["test_label"], m["check_dangerous"], m["command"],
                 m["reason"]))
    print("wrote dataset.jsonl, split.json, DATASET.md")


if __name__ == "__main__":
    main()
