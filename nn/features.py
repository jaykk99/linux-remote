"""Feature extraction: shell command string -> fixed-length vector.

Every feature comes from the command string itself: its first token,
the presence of tokens / operators / paths the denylist cares about,
and a few length counts. Labels never leak into features: whether the
command was blocked is label-side only and is never read here.
"""
from __future__ import annotations

import math
import re
from typing import Dict, List, Sequence, Tuple

TOP_K = 16

# Word tokens checked as whole tokens (split on anything that is not
# [a-z0-9_.\-/]); substring checks would false-fire, e.g. "rm" in
# "format" or "sh" in "shutil".
WORD_FLAGS = (
    "rm", "dd", "mkfs", "shred", "reboot", "shutdown", "halt", "poweroff",
    "sudo", "eval", "xargs", "find", "chmod", "chown", "mv", "cp",
    "rmtree", "rm_rf", "unlink", "shutil", "remove", "system", "popen",
    "exec", "python", "python3", "node", "perl", "ruby", "bash", "sh",
    "curl", "wget", "wipe", "fork", "kill", "killall", "pkill",
    "mount", "umount", "iptables", "useradd", "passwd", "chroot",
    "tar", "gzip", "tee", "env", "setsid", "nohup", "watch", "cron",
)

# Substring / operator patterns (checked on the raw lowercased string).
SUBSTR_FLAGS = (
    "-rf", "--recursive", "--no-preserve-root", "/dev/", "/dev/sda",
    "/dev/sdb", "/dev/zero", "/dev/null", "~", "$home", "${home}",
    "$(", "`", "||", "&&", ";", "|", ">", ">>", "<<", "..", "*",
    "/etc", "-c", "-e", "rmSync", "rm_rf", "FileUtils", "os.remove",
    "os.system", "subprocess", "shutil.rmtree", ":(){", "&",
    "expanduser", "import shutil", "import os", "require('fs')",
    'require("fs")', "heredoc", "PYEOF",
)

_TOKEN_RE = re.compile(r"[a-z0-9_.\-/]+")


def _tokens(command: str) -> set:
    return set(_TOKEN_RE.findall((command or "").lower()))


class FeatureSpec:
    """First-token vocab + layout for the feature vector."""

    def __init__(self, first_tokens: Sequence[str] = ()) -> None:
        self.first_tokens = list(first_tokens)

    @property
    def dim(self) -> int:
        return len(self.feature_names())

    def feature_names(self) -> List[str]:
        names: List[str] = []
        names += [f"first:{t}" for t in self.first_tokens] + ["first:OTHER"]
        names += [f"word:{w}" for w in WORD_FLAGS]
        names += [f"has:{s}" for s in SUBSTR_FLAGS]
        names += ["len", "ntokens", "n_special", "n_slashes"]
        return names

    def groups(self) -> Dict[str, Tuple[int, int]]:
        names = self.feature_names()
        idx = {n: i for i, n in enumerate(names)}

        def span(prefix: str) -> Tuple[int, int]:
            hits = [i for n, i in idx.items() if n.startswith(prefix)]
            return (min(hits), max(hits) + 1)

        return {
            "first_token": span("first:"),
            "word_tokens": span("word:"),
            "operators_paths": span("has:"),
            "length": (idx["len"], idx["n_slashes"] + 1),
        }

    def to_dict(self) -> Dict:
        return {"first_tokens": self.first_tokens}

    @classmethod
    def from_dict(cls, data: Dict) -> "FeatureSpec":
        return cls(data.get("first_tokens", []))


def build_vocab(rows: Sequence[Dict], top_k: int = TOP_K) -> FeatureSpec:
    """Learn the top-K first tokens from training rows."""
    from collections import Counter
    firsts = Counter()
    for row in rows:
        cmd = (row.get("command") or "").strip()
        if cmd:
            firsts[cmd.split()[0].lower()] += 1
    return FeatureSpec([t for t, _ in firsts.most_common(top_k)])


def extract(command: str, spec: FeatureSpec) -> List[float]:
    """One command string -> feature vector in spec order."""
    cmd = command or ""
    low = cmd.lower()
    toks = _tokens(cmd)
    vec: List[float] = []
    first = cmd.strip().split()[0].lower() if cmd.strip() else ""
    out = [0.0] * (len(spec.first_tokens) + 1)
    if first in spec.first_tokens:
        out[spec.first_tokens.index(first)] = 1.0
    else:
        out[-1] = 1.0
    vec += out
    vec += [1.0 if w in toks else 0.0 for w in WORD_FLAGS]
    vec += [1.0 if s in low else 0.0 for s in SUBSTR_FLAGS]
    vec.append(min(1.0, len(cmd) / 200.0))
    vec.append(min(1.0, len(cmd.split()) / 20.0))
    vec.append(min(1.0, sum(1 for c in cmd if c in ";|&$`<>*(){}[]!") / 20.0))
    vec.append(min(1.0, cmd.count("/") / 10.0))
    return vec


def top_features(command: str, spec: FeatureSpec, net,
                 k: int = 3) -> List[Dict]:
    """Top contributing features for one scored command (leave-one-out)."""
    x = extract(command, spec)
    base = net.predict_proba(x)
    names = spec.feature_names()
    deltas = []
    for i, name in enumerate(names):
        if x[i] == 0.0:
            continue
        x2 = list(x)
        x2[i] = 0.0
        d = base - net.predict_proba(x2)
        deltas.append((abs(d), d, name))
    deltas.sort(reverse=True)
    return [{"feature": name,
             "direction": "up" if d > 0 else "down",
             "delta": round(d, 4)}
            for _abs, d, name in deltas[:k]]
