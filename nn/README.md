# linux-remote NN — denylist triage scorer

A small pure-Python-stdlib neural network in the style of the
ReconAnything NN scorer (`mlp.py` reused as-is: tanh hidden, sigmoid
output, SGD, zero dependencies). It lives in `nn/` and is **triage
only**.

## Prediction task

Predict whether a shell command string will be **blocked** by the
destructive-command denylist (`server.check_dangerous`) or **allowed**,
from the command text alone.

## Data (real repo data only, nothing invented)

Source: the parametrized denylist cases in `tests/test_server.py` —
`test_dangerous_blocked*` (label 1 = blocked) and `test_benign*`
(label 0 = allowed). `nn/data.py` parses that file with `ast` and
collects exactly those lists, deduplicated. Non-parametrized one-off
cases (workdir root-wipe tests that build paths from `tmp_home`) are
not included: their commands are constructed at test time, not
literal strings.

## Train / score

```sh
python -m nn.train            # writes nn/weights.json + nn/viewer-data.json
python -m nn.score --command "rm -rf /"
open nn/viewer.html           # metrics viewer (embedded real metrics)
```

## Metrics

See `nn/viewer-data.json` (and `nn/viewer.html`) for the real numbers
from the last training run: train/test accuracy vs the majority
baseline, ROC AUC, confusion counts, and per-class
precision/recall/F1 on the held-out test split (stratified 80/20).
Nothing here is tuned on the test set.

## Limits (triage only)

- The model ranks commands by how much they look like past commands
  the denylist blocked. It does not verify anything.
- The denylist (`server.check_dangerous`) stays the only gate. A low
  score never means a command is safe, and this model must never be
  used to bypass, weaken, or replace the denylist.
- The training data is the denylist test suite's own cases, so the
  model learns the denylist's past verdicts, not shell semantics. A
  command phrased in a way the tests never covered is a guess.
