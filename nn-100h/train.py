"""100-hour NN trainer for linux-remote (nn-100h).

Task: predict whether a shell command string will be BLOCKED by the
destructive-command denylist (server.check_dangerous) or ALLOWED, from
the command text alone. Triage only: check_dangerous() stays the only
gate; this model never verifies anything and must never be used to
bypass, weaken, or replace the denylist.

Pure Python stdlib, self-contained MLP (tanh hidden, sigmoid out,
SGD, mini-batches). No imports from repo code, no torch/numpy.
Runs from this directory (repo_root/nn-100h/).

Files in cwd:
  dataset.jsonl, split.json, DATASET.md   (built by build_dataset.py)
  experiments.jsonl   one line per finished experiment
  checkpoints/<exp_id>.json   {exp_id, config, epoch, weights, train_loss}
  best.json / best-metrics.json   best honest test result so far
  status.json    {repo, hours_trained, experiments_done, best, status, ...}
  heartbeat.json {pid, time, exp_id, epoch, experiments_done}

Usage:
  python3 train.py [--resume] [--max-run-hours H]   (default H = 5.5)
  --resume continues the in-progress experiment from its latest
  checkpoint (weights + epoch) instead of restarting it. Without
  --resume, finished experiments are still skipped, but an
  in-progress experiment restarts from epoch 0.

Split: FROZEN grouped+stratified split from split.json (seed 42,
test frac ~0.2, whole command families held out). NEVER train on test
rows. Best is updated only when honest test accuracy improves
(ROC AUC tiebreak). A test accuracy of 1.000 means leakage, not
success: investigate, never celebrate.

Hours: on chunk exit (wall time >= max-run-hours) the current
experiment is checkpointed, chunk hours are added to status.json,
and the process exits 0. When hours_trained >= 100, status=done.
A later chunk (or cron) reruns the same command to continue.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_NAME = "jaykk99/linux-remote"
TARGET_HOURS = 100.0
CHECKPOINT_EVERY = 20
BATCH = 32
HEARTBEAT_EVERY_S = 30.0


def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Features: command string -> fixed-length vector (PR #3 approach, copied)
# ---------------------------------------------------------------------------
TOP_K = 16

WORD_FLAGS = (
    "rm", "dd", "mkfs", "shred", "reboot", "shutdown", "halt", "poweroff",
    "sudo", "eval", "xargs", "find", "chmod", "chown", "mv", "cp",
    "rmtree", "rm_rf", "unlink", "shutil", "remove", "system", "popen",
    "exec", "python", "python3", "node", "perl", "ruby", "bash", "sh",
    "curl", "wget", "wipe", "fork", "kill", "killall", "pkill",
    "mount", "umount", "iptables", "useradd", "passwd", "chroot",
    "tar", "gzip", "tee", "env", "setsid", "nohup", "watch", "cron",
)

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


def _tokens(command: str):
    return set(_TOKEN_RE.findall((command or "").lower()))


def build_vocab(train_rows, top_k=TOP_K):
    firsts = Counter()
    for row in train_rows:
        cmd = (row.get("command") or "").strip()
        if cmd:
            firsts[cmd.split()[0].lower()] += 1
    return [t for t, _ in firsts.most_common(top_k)]


def extract(command: str, first_tokens):
    cmd = command or ""
    low = cmd.lower()
    toks = _tokens(cmd)
    vec = []
    first = cmd.strip().split()[0].lower() if cmd.strip() else ""
    out = [0.0] * (len(first_tokens) + 1)
    if first in first_tokens:
        out[first_tokens.index(first)] = 1.0
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


def feature_dim(first_tokens):
    return len(first_tokens) + 1 + len(WORD_FLAGS) + len(SUBSTR_FLAGS) + 4


# ---------------------------------------------------------------------------
# MLP: tanh hidden, sigmoid out, BCE, plain SGD (PR #3 pattern)
# ---------------------------------------------------------------------------
def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class MLP:
    def __init__(self, layers, seed=42, lr=0.05, l2=1e-4):
        self.layers = list(layers)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.seed = int(seed)
        rng = random.Random(seed)
        self.weights, self.biases = [], []
        for fan_in, fan_out in zip(self.layers[:-1], self.layers[1:]):
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            self.weights.append(
                [[rng.uniform(-limit, limit) for _ in range(fan_in)]
                 for _ in range(fan_out)])
            self.biases.append([0.0 for _ in range(fan_out)])

    def _forward(self, x):
        acts = [list(map(float, x))]
        for wi, (w, b) in enumerate(zip(self.weights, self.biases)):
            z = [sum(wij * xj for wij, xj in zip(row, acts[-1])) + bias
                 for row, bias in zip(w, b)]
            if wi == len(self.weights) - 1:
                acts.append([_sigmoid(v) for v in z])
            else:
                acts.append([math.tanh(v) for v in z])
        return acts

    def predict_proba(self, x):
        return self._forward(x)[-1][0]

    def _backward(self, acts, y):
        n_layers = len(self.weights)
        deltas = [None] * n_layers
        deltas[-1] = [acts[-1][0] - y]
        for li in range(n_layers - 2, -1, -1):
            w_next, d_next = self.weights[li + 1], deltas[li + 1]
            a = acts[li + 1]
            deltas[li] = [sum(w_next[k][j] * d_next[k]
                              for k in range(len(d_next)))
                          * (1.0 - a[j] * a[j])
                          for j in range(len(a))]
        grad_w, grad_b = [], []
        for li in range(n_layers):
            d, a_prev = deltas[li], acts[li]
            grad_w.append([[d[i] * a_prev[j] for j in range(len(a_prev))]
                           for i in range(len(d))])
            grad_b.append(list(d))
        return grad_w, grad_b

    def train_batch(self, batch):
        # Accumulate gradients over the batch, one SGD step.
        acc_w = [[[0.0] * len(row) for row in w] for w in self.weights]
        acc_b = [[0.0] * len(b) for b in self.biases]
        loss = 0.0
        for x, y in batch:
            acts = self._forward(x)
            p = min(max(acts[-1][0], 1e-12), 1 - 1e-12)
            loss += -(y * math.log(p) + (1 - y) * math.log(1 - p))
            gw, gb = self._backward(acts, y)
            for li in range(len(self.weights)):
                for i in range(len(gw[li])):
                    for j in range(len(gw[li][i])):
                        acc_w[li][i][j] += gw[li][i][j]
                    acc_b[li][i] += gb[li][i]
        n = float(len(batch))
        for li in range(len(self.weights)):
            for i in range(len(self.weights[li])):
                for j in range(len(self.weights[li][i])):
                    g = acc_w[li][i][j] / n + self.l2 * self.weights[li][i][j]
                    self.weights[li][i][j] -= self.lr * g
                self.biases[li][i] -= self.lr * (acc_b[li][i] / n)
        return loss / n

    def state(self):
        return {"weights": self.weights, "biases": self.biases}

    def load_state(self, state):
        self.weights = state["weights"]
        self.biases = state["biases"]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def auc_rank(scores, labels):
    # Mann-Whitney U with tie-averaged ranks.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    return (sum(r for r, y in zip(ranks, labels) if y == 1)
            - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def evaluate(net, X, y):
    scores = [net.predict_proba(x) for x in X]
    preds = [1 if s >= 0.5 else 0 for s in scores]
    tp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(preds, y) if p == 1 and t == 0)
    tn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 0)
    fn = sum(1 for p, t in zip(preds, y) if p == 0 and t == 1)
    acc = (tp + tn) / max(1, len(y))
    return {
        "test_acc": round(acc, 4),
        "auc": round(auc_rank(scores, y), 4),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "per_class_recall": {
            "blocked": round(tp / max(1, tp + fn), 4),
            "allowed": round(tn / max(1, tn + fp), 4),
        },
    }


# ---------------------------------------------------------------------------
# Experiment grid
# ---------------------------------------------------------------------------
def phase1_grid():
    grid = []
    for hidden in [(16, 8), (32, 16), (8,), (16,), (32,), (64, 32)]:
        for lr in (0.05, 0.02, 0.1):
            for l2 in (1e-4, 1e-3):
                for epochs in (60, 120):
                    for seed in (42, 1):
                        grid.append({"hidden": list(hidden), "lr": lr,
                                     "l2": l2, "epochs": epochs,
                                     "seed": seed})
    return grid


def refine_config(best_config, index):
    """Deterministic refinement around the best config so far."""
    rng = random.Random(1000 + index)
    base_hidden = list(best_config["hidden"])
    choice = rng.choice(["hidden", "lr", "l2", "seed", "epochs"])
    cfg = {"hidden": list(base_hidden), "lr": best_config["lr"],
           "l2": best_config["l2"], "epochs": best_config["epochs"],
           "seed": 2 + index}
    if choice == "hidden":
        scale = rng.choice([0.5, 2.0])
        cfg["hidden"] = [max(4, int(round(h * scale))) for h in base_hidden]
    elif choice == "lr":
        cfg["lr"] = best_config["lr"] * rng.choice([0.5, 2.0])
    elif choice == "l2":
        cfg["l2"] = best_config["l2"] * rng.choice([0.1, 10.0])
    elif choice == "epochs":
        cfg["epochs"] = rng.choice([90, 180, 240])
    return cfg


# ---------------------------------------------------------------------------
# State files
# ---------------------------------------------------------------------------
def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2), encoding="utf-8")


def load_experiments():
    rows = []
    p = HERE / "experiments.jsonl"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


class Trainer:
    def __init__(self, max_run_hours, resume):
        self.max_run_seconds = max_run_hours * 3600.0
        self.resume = resume
        self.chunk_start = time.time()
        self.last_heartbeat = 0.0
        self.rows = [json.loads(l) for l in
                     (HERE / "dataset.jsonl").read_text(encoding="utf-8")
                     .splitlines() if l.strip()]
        self.split = load_json(HERE / "split.json", {})
        if not self.split:
            raise SystemExit("split.json missing: run build_dataset.py first")
        train_idx = self.split["train_idx"]
        test_idx = self.split["test_idx"]
        # Guard: train/test index sets must not overlap.
        assert not set(train_idx) & set(test_idx), "split overlap!"
        train_rows = [self.rows[i] for i in train_idx]
        test_rows = [self.rows[i] for i in test_idx]
        self.first_tokens = build_vocab(train_rows)  # train only: no leakage
        self.dim = feature_dim(self.first_tokens)
        self.X_train = [extract(r["command"], self.first_tokens)
                        for r in train_rows]
        self.y_train = [r["label"] for r in train_rows]
        self.X_test = [extract(r["command"], self.first_tokens)
                       for r in test_rows]
        self.y_test = [r["label"] for r in test_rows]
        self.status = load_json(HERE / "status.json", {})
        self.base_hours = float(self.status.get("hours_trained", 0.0))
        self.experiments_done = int(
            self.status.get("experiments_done",
                            len(load_experiments())))
        self.best = self.status.get("best") or load_json(
            HERE / "best.json", None)
        self.next_exp_num = int(self.status.get("next_exp_num",
                                                self.experiments_done + 1))
        self.grid_index = int(self.status.get("grid_index", 0))
        self.refine_index = int(self.status.get("refine_index", 0))
        self.current_exp_id = self.status.get("current_exp_id")
        self.current_config = self.status.get("current_config")
        self._ckpt_dir = HERE / "checkpoints"
        self._ckpt_dir.mkdir(exist_ok=True)

    # -- time / status ------------------------------------------------------
    def chunk_elapsed(self):
        return time.time() - self.chunk_start

    def hours_total(self):
        return self.base_hours + self.chunk_elapsed() / 3600.0

    def write_status(self, status_str):
        self.status = {
            "repo": REPO_NAME,
            "hours_trained": round(self.hours_total(), 4),
            "experiments_done": self.experiments_done,
            "best": self.best,
            "status": status_str,
            "next_exp_num": self.next_exp_num,
            "grid_index": self.grid_index,
            "refine_index": self.refine_index,
            "current_exp_id": self.current_exp_id,
            "current_config": self.current_config,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        save_json(HERE / "status.json", self.status)

    def heartbeat(self, exp_id, epoch):
        now = time.time()
        if now - self.last_heartbeat < HEARTBEAT_EVERY_S:
            return
        self.last_heartbeat = now
        save_json(HERE / "heartbeat.json", {
            "pid": os.getpid(), "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "exp_id": exp_id, "epoch": epoch,
            "experiments_done": self.experiments_done,
        })

    def time_left(self):
        return self.max_run_seconds - self.chunk_elapsed() >= 0

    # -- checkpoints --------------------------------------------------------
    def checkpoint_path(self, exp_id):
        return self._ckpt_dir / f"{exp_id}.json"

    def save_checkpoint(self, exp_id, config, epoch, net, train_loss):
        save_json(self.checkpoint_path(exp_id), {
            "exp_id": exp_id, "config": config, "epoch": epoch,
            "weights": net.state()["weights"],
            "biases": net.state()["biases"],
            "train_loss": train_loss,
        })
        # Keep status hours fresh so a kill loses at most one
        # checkpoint interval of time accounting.
        self.write_status("training")

    def find_in_progress(self):
        """Latest checkpoint whose experiment never finished."""
        done = {r["exp_id"] for r in load_experiments()}
        ckpts = sorted(self._ckpt_dir.glob("*.json"),
                       key=lambda p: p.stat().st_mtime)
        for p in reversed(ckpts):
            exp_id = p.stem
            if exp_id not in done:
                try:
                    return json.loads(p.read_text(encoding="utf-8"))
                except ValueError:
                    continue
        return None

    # -- one experiment -----------------------------------------------------
    def run_experiment(self, exp_id, config, start_epoch=0, net=None):
        if net is None:
            net = MLP([self.dim] + list(config["hidden"]) + [1],
                      seed=config["seed"], lr=config["lr"], l2=config["l2"])
        epochs = config["epochs"]
        n = len(self.X_train)
        train_loss = None
        exp_start = time.time()
        for epoch in range(start_epoch + 1, epochs + 1):
            rng = random.Random(config["seed"] * 100003 + epoch)
            order = list(range(n))
            rng.shuffle(order)
            tot, nb = 0.0, 0
            for s in range(0, n, BATCH):
                batch = [(self.X_train[i], self.y_train[i])
                         for i in order[s:s + BATCH]]
                tot += net.train_batch(batch)
                nb += 1
            train_loss = tot / max(1, nb)
            self.heartbeat(exp_id, epoch)
            if epoch % CHECKPOINT_EVERY == 0 or epoch == epochs:
                self.save_checkpoint(exp_id, config, epoch, net, train_loss)
                log(f"{exp_id} epoch {epoch}/{epochs} "
                    f"train_loss={train_loss:.4f}")
            if not self.time_left():
                # Always checkpoint at the stopping epoch, even
                # mid-interval, so --resume has something to load.
                self.save_checkpoint(exp_id, config, epoch, net, train_loss)
                log(f"{exp_id} chunk time reached at epoch "
                    f"{epoch}/{epochs}; checkpointed, exiting 0")
                self.current_exp_id = exp_id
                self.current_config = config
                self.write_status("training")
                return None  # chunk over, not finished
        metrics = evaluate(net, self.X_test, self.y_test)
        seconds = round(time.time() - exp_start, 1)
        rec = {"exp_id": exp_id, "config": config,
               "test_acc": metrics["test_acc"], "auc": metrics["auc"],
               "confusion": metrics["confusion"],
               "per_class_recall": metrics["per_class_recall"],
               "seconds": seconds}
        with (HERE / "experiments.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        self.experiments_done += 1
        self.next_exp_num += 1
        self.current_exp_id = None
        self.current_config = None
        improved = (self.best is None
                    or metrics["test_acc"] > self.best["test_acc"]
                    or (metrics["test_acc"] == self.best["test_acc"]
                        and metrics["auc"] > self.best["auc"]))
        if improved:
            self.best = {"exp_id": exp_id, "config": config,
                         "test_acc": metrics["test_acc"],
                         "auc": metrics["auc"],
                         "confusion": metrics["confusion"],
                         "per_class_recall": metrics["per_class_recall"]}
            save_json(HERE / "best.json", self.best)
            save_json(HERE / "best-metrics.json", {
                "test_acc": metrics["test_acc"], "auc": metrics["auc"],
                "confusion": metrics["confusion"],
                "per_class_recall": metrics["per_class_recall"],
                "exp_id": exp_id})
            log(f"{exp_id} NEW BEST test_acc={metrics['test_acc']} "
                f"auc={metrics['auc']}")
        log(f"{exp_id} done test_acc={metrics['test_acc']} "
            f"auc={metrics['auc']} conf={metrics['confusion']} "
            f"recall={metrics['per_class_recall']} cfg={config}")
        if metrics["test_acc"] >= 1.0:
            log(f"WARNING {exp_id} test_acc=1.000: treat as suspected "
                f"leakage, investigate before trusting it")
        self.write_status("training")
        return rec

    # -- main loop ----------------------------------------------------------
    def run(self):
        if self.status.get("status") == "done":
            # Terminal state: touch NOTHING (no status/heartbeat writes),
            # so the CircleCI commit step finds no changes and the chain
            # stops instead of looping on empty checkpoint commits.
            log("already done, nothing to do")
            return 0
        log(f"start resume={self.resume} max_run_hours="
            f"{self.max_run_seconds / 3600.0} hours_trained_so_far="
            f"{self.base_hours:.3f} experiments_done={self.experiments_done} "
            f"dim={self.dim} train={len(self.X_train)} "
            f"test={len(self.X_test)}")
        grid = phase1_grid()
        resumed = False
        if self.resume:
            ckpt = self.find_in_progress()
            if ckpt and self.current_exp_id == ckpt["exp_id"]:
                exp_id, config = ckpt["exp_id"], ckpt["config"]
                net = MLP([self.dim] + list(config["hidden"]) + [1],
                          seed=config["seed"], lr=config["lr"],
                          l2=config["l2"])
                net.load_state({"weights": ckpt["weights"],
                                "biases": ckpt["biases"]})
                log(f"RESUMED {exp_id} from checkpoint epoch "
                    f"{ckpt['epoch']}/{config['epochs']} "
                    f"(train_loss={ckpt.get('train_loss')})")
                res = self.run_experiment(exp_id, config,
                                          start_epoch=ckpt["epoch"],
                                          net=net)
                resumed = True
                if res is None:
                    return 0  # chunk time ran out mid-resume
            elif ckpt:
                log(f"resume: checkpoint {ckpt['exp_id']} found but "
                    f"status points at {self.current_exp_id}; "
                    f"restarting {ckpt['exp_id']} fresh")
        if self.hours_total() >= TARGET_HOURS:
            self.write_status("done")
            log("100h target reached, status=done")
            return 0
        while self.time_left():
            if self.hours_total() >= TARGET_HOURS:
                break
            if self.grid_index < len(grid):
                config = grid[self.grid_index]
                self.grid_index += 1
                phase = "grid"
            else:
                if self.best is None:
                    log("grid exhausted but no best yet; stopping")
                    break
                config = refine_config(self.best["config"], self.refine_index)
                self.refine_index += 1
                phase = "refine"
            exp_id = f"exp-{self.next_exp_num:04d}"
            self.current_exp_id = exp_id
            self.current_config = config
            self.write_status("training")
            log(f"starting {exp_id} ({phase}) cfg={config}")
            res = self.run_experiment(exp_id, config)
            if res is None:
                return 0  # chunk time out, checkpointed
        done = self.hours_total() >= TARGET_HOURS
        self.write_status("done" if done else "training")
        log(f"chunk exit hours_trained={self.hours_total():.3f} "
            f"experiments_done={self.experiments_done} status="
            f"{'done' if done else 'training'}")
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--max-run-hours", type=float, default=5.5)
    args = ap.parse_args()
    if args.max_run_hours <= 0:
        raise SystemExit("--max-run-hours must be > 0")
    t = Trainer(args.max_run_hours, args.resume)
    try:
        return t.run()
    except KeyboardInterrupt:
        log("interrupted; status hours kept up to last checkpoint")
        t.write_status("training")
        return 0


if __name__ == "__main__":
    sys.exit(main())
