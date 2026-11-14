# Resume test — 2026-11-14

Required check: run `train.py` briefly, kill it mid-run, rerun with
`--resume`, confirm it continues from the checkpoint epoch rather
than restarting.

## Evidence (log lines, verbatim)

Run 1 — fresh, `--max-run-hours 0.02` (~72s):

```text
[2026-11-14 22:40:31] starting exp-0001 (grid) cfg={'hidden': [16, 8], 'lr': 0.05, 'l2': 0.0001, 'epochs': 60, 'seed': 42}
[2026-11-14 22:41:26] exp-0001 epoch 20/60 train_loss=0.4763
[2026-11-14 22:41:47] exp-0001 chunk time reached at epoch 26/60; checkpointed, exiting 0
```

Run 2 — `kill` after ~55s, then `--resume --max-run-hours 5.5`:

```text
[2026-11-14 22:41:58] RESUMED exp-0001 from checkpoint epoch 26/60 (train_loss=0.4565704935406327)
[2026-11-14 22:42:47] exp-0001 epoch 40/60 train_loss=0.4241
```

(killed again mid-run; checkpoint at epoch 40 on disk.)

Run 3 — `--resume --max-run-hours 0.03`:

```text
[2026-11-14 22:43:02] RESUMED exp-0001 from checkpoint epoch 40/60 (train_loss=0.4240978350403581)
[2026-11-14 22:43:51] exp-0001 epoch 60/60 train_loss=0.4018
[2026-11-14 22:43:52] exp-0001 NEW BEST test_acc=0.6889 auc=0.7061
[2026-11-14 22:43:52] exp-0001 done test_acc=0.6889 auc=0.7061 conf={'tp': 86, 'fp': 17, 'tn': 38, 'fn': 39} recall={'blocked': 0.688, 'allowed': 0.6909}
```

## Result: PASS

The trainer resumed from checkpoint epoch 26, then from epoch 40,
and finished exp-0001 at epoch 60 without restarting. Hours in
`status.json` accumulated across the kills (0.065h after run 3).
