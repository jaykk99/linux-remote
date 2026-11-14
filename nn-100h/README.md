# nn-100h — 100-hour neural network trainer (linux-remote)

Predicts whether a shell command string will be **blocked** by the
destructive-command denylist (`server.check_dangerous`) or **allowed**,
from the command text alone. **Triage only:** `check_dangerous()` stays
the only gate. A low score never means a command is safe; this must
never be used to bypass, weaken, or replace the denylist.

Pure Python stdlib, self-contained MLP (tanh hidden, sigmoid out, SGD,
mini-batches). No torch/numpy, no imports from repo code. Runs from
this directory, on this VM and in GitHub Actions alike.

## Files

| file | what it is |
|---|---|
| `train.py` | the trainer (this is the contract) |
| `build_dataset.py` | rebuilds `dataset.jsonl` + `split.json` from the repo (needs fastapi, only for regeneration; the committed dataset is what training uses) |
| `dataset.jsonl` | 844 real labeled commands (571 blocked / 273 allowed) |
| `split.json` | frozen grouped+stratified split, seed 42, test frac ~0.2 |
| `DATASET.md` | provenance, label cross-check, split method, limits |
| `experiments.jsonl` | one line per finished experiment |
| `checkpoints/<exp_id>.json` | weights + epoch every 20 epochs |
| `best.json` / `best-metrics.json` | best honest test result so far |
| `status.json` | cumulative hours, experiments done, status |
| `heartbeat.json` | liveness, rewritten every <=60s while training |

## Run

```sh
cd nn-100h
python3 train.py [--resume] [--max-run-hours H]   # default H = 5.5
```

Each chunk trains until wall time reaches `--max-run-hours`, then
checkpoints, adds the chunk hours to `status.json`, and exits 0.
Rerun the same command to continue. `--resume` continues the
in-progress experiment from its latest checkpoint instead of
restarting it. When `hours_trained >= 100`, status becomes `done`.

## Split and leakage audit

The denylist is a deterministic rule, so a random split would mostly
measure rule memorization. The frozen split is **grouped**:
whole command families (first meaningful token, e.g. `python3`,
`find`, `nsenter`) are held out into test — 11 families, 180 rows —
so test accuracy measures generalization to unseen families.
A test accuracy of 1.000 means leakage, not success.

Baseline (grouped split, PR #3's random-split 0.830 does not apply
here): see `best-metrics.json` / `experiments.jsonl` after the
first experiments finish.

## Experiment loop

Phase 1: grid over hidden sizes {(16,8), (32,16), (8,), (16,), (32,),
(64,32)} x lr {0.05, 0.02, 0.1} x L2 {1e-4, 1e-3} x epochs {60, 120}
x seeds {42, 1} = 144 experiments. Phase 2: deterministic refinement
around the best config (new seeds, scaled hidden/lr/L2/epochs).
Best updates only when honest test accuracy improves (ROC AUC
tiebreak). Test rows are never trained on.
