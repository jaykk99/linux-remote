"""Score one shell command with the trained denylist triage network.

    python -m nn.score --command "rm -rf /"
    python -m nn.score --command "ls -la /tmp" --json

Triage only: the score ranks the command by how much it looks like
past commands the denylist blocked. It never verifies a command is
safe and must never be used to bypass or replace the denylist
(server.check_dangerous stays the only gate).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .features import FeatureSpec, extract, top_features
from .mlp import MLP


def load_model(weights_path: str | None = None):
    path = Path(weights_path) if weights_path else Path(
        os.path.dirname(os.path.abspath(__file__))) / "weights.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    net = MLP.from_dict(data["mlp"])
    spec = FeatureSpec.from_dict(data["features"])
    return net, spec


def score_command(command: str, model=None, threshold: float = 0.5) -> dict:
    if model is None:
        model = load_model()
    if model is None:
        raise FileNotFoundError(
            "no trained weights found. Train first: python -m nn.train")
    net, spec = model
    x = extract(command, spec)
    score = net.predict_proba(x)
    return {
        "command": command,
        "nn_score": round(score, 4),
        "nn_label": "likely-blocked" if score >= threshold else "likely-allowed",
        "threshold": threshold,
        "nn_top_features": top_features(command, spec, net),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Score a shell command with the denylist NN.")
    ap.add_argument("--command", required=True,
                    help="shell command string to score")
    ap.add_argument("--weights", default=None,
                    help="weights.json path (default: nn/weights.json)")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    model = load_model(args.weights)
    if model is None:
        print("no trained weights found. Train first:\n"
              "  python -m nn.train", file=sys.stderr)
        return 2
    record = score_command(args.command, model=model,
                           threshold=args.threshold)
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"score: {record['nn_score']:.3f}  "
              f"label: {record['nn_label']}")
        for tf in record["nn_top_features"]:
            print(f"  {tf['direction']} {tf['feature']} ({tf['delta']:+.3f})")
        print("triage only: check_dangerous() stays the only gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
