"""A small multilayer perceptron in pure Python stdlib.

No torch, no sklearn, no numpy: the backend venv does not have them,
and this network has to run on Jay's Linux box and in Termux with zero
new dependencies. Lists of floats, tanh hidden units, sigmoid output,
binary cross-entropy, plain SGD with mini-batches.

This is a triage scorer, not a verifier. It ranks plugin findings by
how much they look like the candidates that survived triage in the past.
It never stamps VERIFIED_REAL: there are zero verified-real positives
in the training data, so the model has never seen one and must never
claim one.
"""
from __future__ import annotations

import json
import math
import random
from typing import Dict, List, Optional, Sequence, Tuple


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _tanh(z: float) -> float:
    return math.tanh(z)


def _tanh_deriv(a: float) -> float:
    # a is tanh(z); d/dz = 1 - tanh(z)^2
    return 1.0 - a * a


class MLP:
    """Feed-forward network: layers e.g. [n_in, 32, 16, 1].

    Hidden layers use tanh, the output layer uses sigmoid, so
    predict_proba returns a number in (0, 1): the model's estimated
    probability that a finding is worth validating.
    """

    def __init__(self, layers: Sequence[int], seed: int = 42,
                 lr: float = 0.05, l2: float = 1e-4) -> None:
        if len(layers) < 2:
            raise ValueError("need at least [n_in, n_out]")
        if any(n < 1 for n in layers):
            raise ValueError("layer sizes must be >= 1")
        self.layers = list(layers)
        self.lr = float(lr)
        self.l2 = float(l2)
        self.seed = int(seed)
        rng = random.Random(seed)
        self.weights: List[List[List[float]]] = []
        self.biases: List[List[float]] = []
        for fan_in, fan_out in zip(self.layers[:-1], self.layers[1:]):
            # Xavier uniform: keeps tanh units out of saturation at init.
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            self.weights.append(
                [[rng.uniform(-limit, limit) for _ in range(fan_in)]
                 for _ in range(fan_out)])
            self.biases.append([0.0 for _ in range(fan_out)])

    # -- forward ---------------------------------------------------------
    def _forward(self, x: Sequence[float]):
        """Return (activations, pre-activations); activations[0] is x."""
        acts = [list(map(float, x))]
        pres = []
        for w, b in zip(self.weights, self.biases):
            z = []
            for row, bias in zip(w, b):
                z.append(sum(wi * xi for wi, xi in zip(row, acts[-1])) + bias)
            pres.append(z)
            if w is self.weights[-1]:
                acts.append([_sigmoid(v) for v in z])
            else:
                acts.append([_tanh(v) for v in z])
        return acts, pres

    def predict_proba(self, x: Sequence[float]) -> float:
        acts, _ = self._forward(x)
        return acts[-1][0]

    def predict(self, x: Sequence[float], threshold: float = 0.5) -> int:
        return 1 if self.predict_proba(x) >= threshold else 0

    # -- training --------------------------------------------------------
    def _backward(self, acts, pres, y: float):
        """Gradients of the BCE loss for one example.

        Returns (grad_weights, grad_biases) in the same shapes as
        self.weights / self.biases. Output layer: with sigmoid + BCE
        the delta is simply (p - y). Hidden layers: tanh derivative.
        """
        n_layers = len(self.weights)
        deltas: List[Optional[List[float]]] = [None] * n_layers
        # Output layer.
        p = acts[-1][0]
        deltas[-1] = [p - y]
        # Hidden layers, walking backwards.
        for li in range(n_layers - 2, -1, -1):
            w_next = self.weights[li + 1]
            d_next = deltas[li + 1]
            a = acts[li + 1]  # tanh activations of this layer
            delta = []
            for j in range(len(a)):
                s = sum(w_next[k][j] * d_next[k] for k in range(len(d_next)))
                delta.append(s * _tanh_deriv(a[j]))
            deltas[li] = delta
        grad_w = []
        grad_b = []
        for li in range(n_layers):
            d = deltas[li]
            a_prev = acts[li]
            grad_w.append([[d[i] * a_prev[j] for j in range(len(a_prev))]
                           for i in range(len(d))])
            grad_b.append(list(d))
        return grad_w, grad_b

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int],
            epochs: int = 60, batch_size: int = 32,
            X_val: Optional[Sequence[Sequence[float]]] = None,
            y_val: Optional[Sequence[int]] = None,
            seed: int = 42) -> Dict[str, List[float]]:
        """Train with mini-batch SGD. Returns per-epoch history.

        history = {"loss": [...], "train_acc": [...], "val_acc": [...]}
        (val_acc present only when a validation set is given). Loss is
        mean binary cross-entropy over the training set.
        """
        X = [list(map(float, row)) for row in X]
        y = [float(v) for v in y]
        if not X:
            raise ValueError("empty training set")
        n_in = len(X[0])
        if n_in != self.layers[0]:
            raise ValueError(
                f"feature dim {n_in} != network input {self.layers[0]}")
        rng = random.Random(seed)
        history: Dict[str, List[float]] = {
            "loss": [], "train_acc": [], "val_acc": []}
        n = len(X)
        for _epoch in range(int(epochs)):
            order = list(range(n))
            rng.shuffle(order)
            for start in range(0, n, max(1, int(batch_size))):
                idxs = order[start:start + int(batch_size)]
                gw_acc = [[[0.0] * len(row) for row in w]
                          for w in self.weights]
                gb_acc = [[0.0] * len(b) for b in self.biases]
                for i in idxs:
                    acts, _ = self._forward(X[i])
                    gw, gb = self._backward(acts, [], y[i])
                    for li in range(len(gw)):
                        for r in range(len(gw[li])):
                            for c in range(len(gw[li][r])):
                                gw_acc[li][r][c] += gw[li][r][c]
                        for r in range(len(gb[li])):
                            gb_acc[li][r] += gb[li][r]
                m = float(len(idxs))
                for li in range(len(self.weights)):
                    for r in range(len(self.weights[li])):
                        for c in range(len(self.weights[li][r])):
                            g = gw_acc[li][r][c] / m
                            g += self.l2 * self.weights[li][r][c]
                            self.weights[li][r][c] -= self.lr * g
                    for r in range(len(self.biases[li])):
                        self.biases[li][r] -= self.lr * (gb_acc[li][r] / m)
            history["loss"].append(self._bce(X, y))
            history["train_acc"].append(self.accuracy(X, y))
            if X_val is not None and y_val is not None:
                history["val_acc"].append(self.accuracy(X_val, y_val))
        return history

    def _bce(self, X, y) -> float:
        eps = 1e-12
        total = 0.0
        for xi, yi in zip(X, y):
            p = min(max(self.predict_proba(xi), eps), 1.0 - eps)
            total += -(yi * math.log(p) + (1.0 - yi) * math.log(1.0 - p))
        return total / max(1, len(X))

    def accuracy(self, X, y, threshold: float = 0.5) -> float:
        if not X:
            return 0.0
        ok = sum(1 for xi, yi in zip(X, y)
                 if self.predict(xi, threshold) == yi)
        return ok / len(X)

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "format": "recon-nn-mlp/1",
            "layers": self.layers,
            "lr": self.lr,
            "l2": self.l2,
            "seed": self.seed,
            "weights": self.weights,
            "biases": self.biases,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "MLP":
        if data.get("format") != "recon-nn-mlp/1":
            raise ValueError("not a recon-nn-mlp/1 weights file")
        net = cls(data["layers"], seed=int(data.get("seed", 42)),
                  lr=float(data.get("lr", 0.05)),
                  l2=float(data.get("l2", 1e-4)))
        net.weights = [[[float(v) for v in row] for row in mat]
                       for mat in data["weights"]]
        net.biases = [[float(v) for v in b] for b in data["biases"]]
        return net

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> "MLP":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Rank-based ROC AUC (Mann-Whitney). 0.5 = chance, 1.0 = perfect.

    Pure python: sort by score, count correctly ordered pairs.
    """
    pairs = sorted(zip(scores, labels), key=lambda t: t[0])
    n_pos = sum(1 for _, lab in pairs if lab == 1)
    n_neg = len(pairs) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    # Average ranks with ties.
    rank_sum = 0.0
    i = 0
    ranks = [0.0] * len(pairs)
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # 1-based average rank
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    for r, (_, lab) in zip(ranks, pairs):
        if lab == 1:
            rank_sum += r
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def confusion_matrix(y_true: Sequence[int],
                     y_pred: Sequence[int]) -> Dict[str, int]:
    """Positive class = worth-validating (1)."""
    tn = fp = fn = tp = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 1 and p == 0:
            fn += 1
        else:
            tn += 1
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def prf(cm: Dict[str, int]) -> Dict[str, float]:
    """Precision / recall / F1 for both classes from a confusion matrix."""
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    pos_prec = tp / (tp + fp) if tp + fp else 0.0
    pos_rec = tp / (tp + fn) if tp + fn else 0.0
    neg_prec = tn / (tn + fn) if tn + fn else 0.0
    neg_rec = tn / (tn + fp) if tn + fp else 0.0

    def f1(p: float, r: float) -> float:
        return 2 * p * r / (p + r) if p + r else 0.0

    return {
        "precision_worth_validating": pos_prec,
        "recall_worth_validating": pos_rec,
        "f1_worth_validating": f1(pos_prec, pos_rec),
        "precision_likely_fp": neg_prec,
        "recall_likely_fp": neg_rec,
        "f1_likely_fp": f1(neg_prec, neg_rec),
    }


def metrics_for(y_true: Sequence[int], scores: Sequence[float],
                threshold: float = 0.5) -> Dict:
    """Full honest metric set for one scored set."""
    preds = [1 if s >= threshold else 0 for s in scores]
    cm = confusion_matrix(list(y_true), preds)
    out = {
        "n": len(y_true),
        "n_positive": sum(1 for t in y_true if t == 1),
        "n_negative": sum(1 for t in y_true if t == 0),
        "threshold": threshold,
        "accuracy": sum(1 for t, p in zip(y_true, preds) if t == p) / max(1, len(y_true)),
        "majority_baseline_accuracy": max(
            sum(1 for t in y_true if t == 1),
            sum(1 for t in y_true if t == 0)) / max(1, len(y_true)),
        "roc_auc": roc_auc(list(scores), list(y_true)),
        "confusion": cm,
    }
    out.update(prf(cm))
    return out
