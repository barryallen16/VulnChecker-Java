# TriageMate

TriageMate sorts Java static-analysis warnings.
Semgrep finds candidate bugs; a fine-tuned Qwen2.5-Coder-7B decides which alerts are real, gives a one-sentence reason and a one-sentence fix, and puts the real bugs first.

The job is triage, not detection.
A finder that flags everything has perfect recall and poor precision.
On the labelled set in this repo, Semgrep alone is right about half the time: 51.5% of its alerts are real bugs.

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

RESULTS_TBD

Semgrep alone is the floor: it keeps every alert, so recall is 1.0 and precision equals the base rate.
The triage model is judged on the same alerts, plus a frozen Juliet set it never trained on.

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
The adapter is published as a release asset: ADAPTER_TBD.

## Reproduce

```bash
bash scripts/scan_benchmarks.sh          # download and scan both suites
uv run python -m triage.dataset --suite all
uv run python -m triage.data_sheet
bash scripts/make_release.sh             # package data and upload to the HF dataset repo

uv run --env-file .env python training/launch.py training/train_qlora.py \
  --title triage-full --args "--epochs 1" --dest /tmp/adapter
uv run --env-file .env python training/launch.py training/evaluate_llm.py \
  --title triage-eval --args "--adapter-url <zip> --set test --set juliet-frozen --no-gen" \
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
