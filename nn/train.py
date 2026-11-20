"""Train the denylist triage network on the real labeled commands.

    python -m nn.train [--out DIR] [--epochs N] [--hidden 16,8]

Trains an MLP to predict whether a shell command will be blocked by
the destructive-command denylist (label 1) or allowed (label 0).
Writes weights.json + viewer-data.json into the out dir (default:
this package dir) and refreshes the embedded metrics block in
viewer.html.

Honest limits, printed with the metrics and baked into the viewer:
- the data is the denylist test suite's own parametrized cases, so
  the model learns the denylist's past verdicts, not shell semantics.
  A command phrased in a way the tests never covered is a guess.
- the model ranks commands by how much they look like past blocked
  ones. It never verifies a command is safe and must never be used
  to bypass or replace the denylist: check_dangerous() stays the
  only gate, this score is triage only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
from pathlib import Path

from .data import build_dataset, stratified_split
from .features import FeatureSpec, build_vocab, extract
from .mlp import MLP, metrics_for, roc_auc

LIMITS = [
    "Triage only. The model ranks commands by how much they look like "
    "past commands the denylist blocked. It does not verify anything.",
    "The denylist (server.check_dangerous) stays the only gate. A low "
    "score never means a command is safe, and this model must never be "
    "used to bypass, weaken, or replace the denylist.",
    # Index 2 is replaced at train time with the real label skew.
    "Label skew: see the dataset stats.",
    "Commands using constructs unseen in training fall into the OTHER "
    "bucket; the model has no opinion about them beyond the generic "
    "token/operator features.",
]

VIEWER_START = "<!-- NN-DATA-START -->"
VIEWER_END = "<!-- NN-DATA-END -->"


def permutation_importance(net: MLP, spec: FeatureSpec,
                           X_test, y_test, seed: int = 42):
    """Grouped permutation importance: AUC drop when a feature group
    is shuffled in the test set. Positive drop = the group matters."""
    base_scores = [net.predict_proba(x) for x in X_test]
    base_auc = roc_auc(base_scores, y_test)
    rng = random.Random(seed)
    out = []
    for group, (a, b) in sorted(spec.groups().items()):
        Xp = [list(x) for x in X_test]
        col_vals = [x[a:b] for x in Xp]
        rng.shuffle(col_vals)
        for row, vals in zip(Xp, col_vals):
            row[a:b] = vals
        auc = roc_auc([net.predict_proba(x) for x in Xp], y_test)
        out.append({"group": group, "auc_drop": round(base_auc - auc, 4)})
    out.sort(key=lambda d: d["auc_drop"], reverse=True)
    return out


def train(out_dir: str, epochs: int = 80, hidden: str = "16,8",
          lr: float = 0.05, seed: int = 42,
          test_frac: float = 0.2) -> dict:
    dataset = build_dataset()
    rows = dataset["rows"]
    stats = dataset["stats"]
    if len(rows) < 20:
        raise ValueError(f"only {len(rows)} training rows; refusing")
    train_rows, test_rows = stratified_split(rows, test_frac, seed)
    spec = build_vocab(train_rows)
    X_train = [extract(r["command"], spec) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract(r["command"], spec) for r in test_rows]
    y_test = [r["label"] for r in test_rows]

    n_pos = sum(y_train) + sum(y_test)
    n_neg = len(rows) - n_pos
    pos_pct = 100.0 * n_pos / max(1, len(rows))
    limits = list(LIMITS)
    limits[2] = (
        f"Label skew: the training set is {pos_pct:.0f}% blocked "
        f"/ {100.0 - pos_pct:.0f}% allowed "
        f"({n_pos} blocked / {n_neg} allowed of {len(rows)} commands). "
        "Accuracy near the majority baseline means the model learned "
        "nothing; judge it by minority-class recall and ROC AUC instead.")

    layers = [spec.dim] + [int(h) for h in hidden.split(",") if h] + [1]
    net = MLP(layers, seed=seed, lr=lr)
    history = net.fit(X_train, y_train, epochs=epochs, batch_size=32,
                      X_val=X_test, y_val=y_test, seed=seed)
    train_scores = [net.predict_proba(x) for x in X_train]
    test_scores = [net.predict_proba(x) for x in X_test]
    train_metrics = metrics_for(y_train, train_scores)
    test_metrics = metrics_for(y_test, test_scores)
    importance = permutation_importance(net, spec, X_test, y_test, seed)

    result = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "layers": layers,
        "n_features": spec.dim,
        "feature_names": spec.feature_names(),
        "dataset": stats,
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "history": history,
        "feature_importance": importance,
        "limits": limits,
        "seed": seed,
        "epochs": epochs,
        "lr": lr,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    weights = {
        "format": "linux-remote-nn-weights/1",
        "trained_at": result["trained_at"],
        "mlp": net.to_dict(),
        "features": spec.to_dict(),
        "metrics": {"train": train_metrics, "test": test_metrics},
        "dataset": stats,
        "limits": limits,
    }
    (out / "weights.json").write_text(json.dumps(weights, indent=2),
                                      encoding="utf-8")
    (out / "viewer-data.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    _refresh_viewer(out / "viewer.html", result)
    return result


def _refresh_viewer(viewer_path: Path, result: dict) -> None:
    """Replace the embedded metrics JSON block in viewer.html so the
    file shows the real numbers even when opened as file://."""
    if not viewer_path.exists():
        return
    text = viewer_path.read_text(encoding="utf-8")
    if VIEWER_START not in text or VIEWER_END not in text:
        return
    block = (VIEWER_START + "\n<script type=\"application/json\" "
             "id=\"nn-data\">\n" + json.dumps(result, indent=2) +
             "\n</script>\n" + VIEWER_END)
    before, _sep, rest = text.partition(VIEWER_START)
    _mid, _sep2, after = rest.partition(VIEWER_END)
    viewer_path.write_text(before + block + after, encoding="utf-8")


def _print_report(result: dict) -> None:
    tm = result["test_metrics"]
    tr = result["train_metrics"]
    print(f"rows: train={result['train_rows']} test={result['test_rows']} "
          f"(blocked {result['dataset']['n_positive']} / "
          f"allowed {result['dataset']['n_negative']})")
    print(f"features: {result['n_features']}  layers: {result['layers']}")
    print(f"train acc {tr['accuracy']:.3f}  test acc {tm['accuracy']:.3f}  "
          f"majority baseline {tm['majority_baseline_accuracy']:.3f}")
    print(f"test ROC AUC {tm['roc_auc']:.3f}")
    print(f"blocked: precision {tm['precision_worth_validating']:.3f} "
          f"recall {tm['recall_worth_validating']:.3f}")
    print(f"allowed: precision {tm['precision_likely_fp']:.3f} "
          f"recall {tm['recall_likely_fp']:.3f}")
    cm = tm["confusion"]
    print(f"confusion (test): tp={cm['tp']} fp={cm['fp']} "
          f"fn={cm['fn']} tn={cm['tn']}")
    print("feature importance (AUC drop): " + ", ".join(
        f"{d['group']}={d['auc_drop']:.3f}"
        for d in result["feature_importance"][:6]))
    print("LIMITS: triage only; the denylist stays the only gate.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Train the linux-remote denylist triage network.")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--epochs", type=int, default=80)
    ap.add_argument("--hidden", default="16,8")
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-frac", type=float, default=0.2)
    args = ap.parse_args(argv)
    result = train(args.out, epochs=args.epochs, hidden=args.hidden,
                   lr=args.lr, seed=args.seed, test_frac=args.test_frac)
    _print_report(result)
    print(f"weights: {os.path.join(args.out, 'weights.json')}")
    print(f"viewer data: {os.path.join(args.out, 'viewer-data.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
