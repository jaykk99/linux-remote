"""Training data: real labeled commands from tests/test_server.py.

The denylist test suite parametrizes hundreds of command strings and
asserts the verdict for each: test_dangerous_blocked* (label 1) and
test_benign_still_allowed* / test_benign_allowed (label 0). This
loader parses that test file with ast and collects exactly those
parametrized lists, deduplicated. No command is invented, and no
verdict is re-labeled: the label is the verdict the test itself
asserts (check_dangerous() is not None / is None, plus the /exec
403 for blocked cases).

Non-parametrized one-off cases (workdir root-wipe tests that build
paths from tmp_home, stats/log tests) are NOT included: their
commands are constructed at test time, not literal strings.
"""
from __future__ import annotations

import ast
import random
from pathlib import Path
from typing import Dict, List, Tuple

LABEL_BLOCKED = 1
LABEL_ALLOWED = 0

TEST_FILE = Path(__file__).resolve().parents[1] / "tests" / "test_server.py"


def build_dataset(test_path: str | Path = TEST_FILE) -> Dict:
    """Build the labeled training set. Returns rows + build stats."""
    tree = ast.parse(Path(test_path).read_text(encoding="utf-8"))
    blocked: List[str] = []
    allowed: List[str] = []
    skipped_nonstring = 0
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
                skipped_nonstring += 1
                continue
            if "blocked" in node.name:
                blocked.extend(vals)
            elif "allowed" in node.name:
                allowed.extend(vals)
    rows: List[Dict] = []
    seen = set()
    dupes = 0
    for cmd, label in [(c, LABEL_BLOCKED) for c in blocked] + \
            [(c, LABEL_ALLOWED) for c in allowed]:
        if cmd in seen:
            dupes += 1
            continue
        seen.add(cmd)
        rows.append({"command": cmd, "label": label})
    stats = {
        "source": "tests/test_server.py parametrized "
                  "test_dangerous_blocked* / test_benign* lists",
        "blocked_raw": len(blocked),
        "allowed_raw": len(allowed),
        "duplicate_commands_dropped": dupes,
        "skipped_nonstring_lists": skipped_nonstring,
        "train_rows": len(rows),
        "n_positive": sum(1 for r in rows if r["label"] == 1),
        "n_negative": sum(1 for r in rows if r["label"] == 0),
    }
    return {"rows": rows, "stats": stats}


def stratified_split(rows: List[Dict], test_frac: float = 0.2,
                     seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
    """Stratified train/test split (keeps the class ratio in both)."""
    rng = random.Random(seed)
    by_label: Dict[int, List[Dict]] = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)
    train: List[Dict] = []
    test: List[Dict] = []
    for label, items in by_label.items():
        items = list(items)
        rng.shuffle(items)
        n_test = max(1, round(len(items) * test_frac)) if len(items) > 1 else 0
        test.extend(items[:n_test])
        train.extend(items[n_test:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test
