# TriageMate

TriageMate sorts Java static-analysis warnings.
Semgrep finds candidate bugs; a fine-tuned Qwen2.5-Coder-7B decides which alerts are real, gives a one-sentence reason and a one-sentence fix, and puts the real bugs first.

The job is triage, not detection.
A finder that flags everything has perfect recall and poor precision.
On the labelled set in this repo, Semgrep alone is right about half the time: 51.0% of its alerts are real bugs.

Status: working experiment with measured numbers.
It is not a product, not a SOTA claim, and not a replacement for a human reviewer.

## What it looks like

```
$ triagemate path/to/project
 41 warnings, real bugs first

  1. BUG  p=0.96  src/ExportServlet.java:72  java.lang.security.httpservlet-path-traversal
     why: The request parameter reaches a File constructor without a path check.
     fix: Resolve the path and reject it unless it stays inside the intended directory.
  2. BUG  p=0.88  src/ReportJob.java:31  java.lang.security.audit.command-injection
     ...
 38. noise p=0.04  src/AdminServlet.java:19  java.lang.security.audit.xss.no-direct-response-writer
```

Every row carries the model's probability, so a reviewer can stop reading when the probability drops.

## Results

The headline set is 2,249 Semgrep alerts from five bug families the model never trained on.
Semgrep alone keeps every alert, so its precision is the base rate.

| Scorer | n | Precision | Recall | F1 | Precision @ 90% recall | ROC-AUC |
|---|---|---|---|---|---|---|
| Semgrep alone | 2,249 | 0.510 | 1.000 | 0.676 | 0.510 | 0.500 |
| CodeBERT 125M, 3 epochs | 2,249 | 0.681 | 0.999 | 0.810 | 0.718 | 0.865 |
| Qwen2.5-Coder-7B, 1 epoch QLoRA | 2,249 | 0.652 | 1.000 | 0.789 | 0.675 | 0.825 |

QLoRA beats the untrained model by 15.2 points of precision, but it does not beat the 125M CodeBERT baseline.
It is 2.9 points behind CodeBERT at the 0.5 threshold and 4.3 points behind at 90% recall.
The Phase 3 gate asked for a 5-point gain over the untrained model and a 3-point gain over CodeBERT.
It passed the first half and failed the second, so no extra epochs were run.
The wider product target - beat Semgrep by 10 points at 90% recall - passes: 0.675 vs 0.510 is +16.5 points.
The result is published as it stands: a 125M classifier is the better triage model on unseen Java bug families.

On the leak-free Juliet set, the fine-tuned model is strong:

| Scorer | n | Accuracy | Precision | Recall |
|---|---|---|---|---|
| Old 7B adapter, original prompt | 1,000 | 0.735 | 1.000 | 0.470 |
| QLoRA, triage prompt | 1,000 | 0.988 | 1.000 | 0.976 |

The QLoRA row is `juliet-heldout-1000-neutral-v2.csv`, where method names are randomised per row.
It makes 12 false negatives and no false positives.
The old adapter misses 265 of the 500 vulnerable cases.

Calibration is imperfect: expected calibration error is 0.085 on the test split.
Below 0.1 the model is never wrong; in the 0.9-1.0 bin the mean confidence is 0.996 and the accuracy is 0.849.
Treat the top of the range as "very likely", not "certain".
`evaluation/calibration.json` has the bins.

Cost on one T4 at $0.40/h: training 4.7 h ($1.86), scoring 4,401 warnings 0.9 h ($0.35).
Amortised over the 10,345 labelled alerts, that is $0.21 per 1,000 warnings; scoring alone is $0.08.
Kaggle's free quota covered the runs.

The untrained 7B with a 3-shot prompt collapses at the default threshold: on a balanced 200-alert sample it called every alert a true positive (precision 0.500, recall 1.000).
Its ranking still carries signal (ROC-AUC 0.700, precision @ 90% recall 0.608), which is why fine-tuning helps, but the prompt alone cannot triage.

All 613 test mistakes are false positives; the model missed no real bug.
They cluster in LDAP injection (156), path traversal (127), XSS (100), XPath injection (98) and command injection (81).
[`notes/errors.md`](notes/errors.md) lists the 30 most confident.

## What the test measures

- **Unseen bug families.** The test split holds out five CWE families: path traversal, OS command injection, XSS, LDAP injection and XPath injection.
  The model never sees those families in training, so the score measures transfer, not memorisation.
- **A frozen Juliet set.** `model-evaluation/juliet-heldout-1000-neutral-v2.csv` is 1,000 Juliet cases, 500 vulnerable and 500 safe, with method names neutralised so the name cannot leak the label.
  No training row shares a normalised code window with it.
- **Calibration.** The confidence is the model's probability at the verdict token, so "80% sure" can be checked against reality.
  See `evaluation/calibration.json`.

## Data

10,345 labelled Semgrep alerts: 5,326 true positives and 5,019 false positives.

| Split | Rows | Families | Purpose |
|---|---|---|---|
| train | 7,797 | 8 | fitting |
| val | 299 | 3 | model selection |
| test | 2,249 | 5 unseen | headline number |

Sources are OWASP Benchmark 1.2 (2,740 servlets, GPLv2) and the NIST Juliet Java suite 1.3 (46,803 files, public domain).
The full counts, scan settings, split policy and known limits are in [`notes/data-sheet.md`](notes/data-sheet.md).
Phase 0 counts and the Semgrep-only baseline are in [`notes/phase0.md`](notes/phase0.md).

The WHY and FIX sentences are templated from the Semgrep rule message and a per-CWE mitigation table.
They are style supervision for the verdict, not expert explanations.
That is stated in the data sheet too.

## The leak we found

The old project reported 979/1000 = 97.90% on a Juliet set.
That number was mostly name reading.
Juliet marks vulnerable methods `bad*` and safe ones `good*`, and the first "neutral" set replaced those with a fixed `funcA`/`funcB` mapping.
The prefix became the label: `funcA` was safe 500 times out of 500, `funcB` vulnerable 461 times out of 461.

`juliet-heldout-1000-neutral-v2.csv` flips the mapping per row.
The prefix now carries nothing: 249 safe and 231 vulnerable rows start with `funcA`.

The old training set had the same disease: 79.6% of its rows had a class name that stated the verdict.
[`notes/leak-audit.md`](notes/leak-audit.md) has the counts.

The old 7B model, run on `juliet-heldout-1000-neutral-v2.csv` with its original prompt, scores 735/1000 = 73.50%.
It calls no safe case vulnerable and misses 265 of the 500 vulnerable cases.
The 97.90% was the method names.
`training/eval_legacy.py` reproduces it.

## Install

```bash
uv venv
uv sync
uv tool install semgrep   # or: pipx install semgrep
```

Java source only; Semgrep does the parsing.

## Run

```bash
triagemate path/to/project --adapter path/to/adapter
triagemate path/to/project --scorer heuristic   # no GPU, ranks by Semgrep severity
triagemate path/to/project --json               # machine-readable
```

The model scorer needs a CUDA GPU and the Python extras: `uv sync --extra model`.
The adapter is published at [barryallen16/all-tmp/qlora-adapter.zip](https://huggingface.co/datasets/barryallen16/all-tmp/resolve/main/qlora-adapter.zip).
Unzip it and pass the `adapter/` directory to `--adapter`.

## Reproduce

```bash
bash scripts/scan_benchmarks.sh          # download and scan both suites
uv run python -m triage.dataset --suite all
uv run python -m triage.data_sheet
bash scripts/make_release.sh             # package data and upload to the HF dataset repo

uv run --env-file .env python training/launch.py training/train_qlora.py \
  --title triage-full --args "--epochs 1" --dest /tmp/adapter
uv run --env-file .env python training/launch.py training/evaluate_llm.py \
  --title triage-eval --args "--adapter-url https://huggingface.co/datasets/barryallen16/all-tmp/resolve/main/qlora-adapter.zip --set test --set juliet-frozen --no-gen" \
  --dest /tmp/eval
uv run python training/report.py --pred model=/tmp/eval/predictions.jsonl
```

Training and evaluation run on a Kaggle T4 through a small launcher (`training/runner.py`).
The token is read from `KAGGLE_RUNNER_TOKEN`; nothing secret is committed.

## Limits

- Both benchmarks are synthetic. Juliet pairs a bad method with a safe one in the same file, and OWASP is a fixed set of servlets.
  A real-repo check (Vul4J) was downloaded but not run, because most of its 129 entries pin old Maven and Java versions.
- Semgrep's rule coverage defines the label set. Bug types it cannot express produce no rows.
- The 328 Juliet files Semgrep could not parse are dropped, not guessed at.
- No paid frontier-model baseline. There was no API key in the environment, so the comparison uses CodeBERT and the untrained 7B model.
- `eval-clean-152` was also scored (accuracy 0.711), but its class names still state the verdict (`SecureServlet`, `VulnerableServlet`).
  It is a continuity check with the old project, not a leak-free test.
- The model writes a reason and a fix, but the fix is not compiled or tested.
  `triage/verify.py` is the compile-and-rescan checker for a future patch model.
- The training set is 75% SQL injection, the largest family. The test families are held out, so this imbalance shows up as weaker transfer, not as leakage.
- QLoRA trains for one epoch, not two. At about 46 seconds per optimizer step on a T4, two epochs on 7,797 rows would pass Kaggle's 12-hour session cap.

## Repo map

- `triage/` - dataset builder, prompt format, metrics, CLI, patch verifier.
- `training/` - QLoRA training, CodeBERT baseline, evaluation, reporting, Kaggle launcher.
- `scripts/` - benchmark scans, Juliet neutralisation, release packaging.
- `notes/` - data sheet, Phase 0 counts, leak audit, error analysis.
- `model-evaluation/` - frozen sets and the old evaluation notebooks.
- `datasets/`, `finetuning/`, `misc/` - the old experiment, kept for provenance.
  See [`notes/legacy-experiment.md`](notes/legacy-experiment.md).

## Licence

Code is Apache-2.0.
OWASP Benchmark is GPLv2 and Juliet is public domain; the derived data keeps the source licences.
