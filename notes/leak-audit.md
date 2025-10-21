# Leak audit

The old project reported 979/1000 = 97.90% on a NIST Juliet held-out set.
That number does not measure vulnerability detection. This note records why,
and what replaced it.

## 1. The frozen "neutral" set still leaked the answer

`model-evaluation/juliet-heldout-1000.csv` keeps Juliet method names. A row is
either a `bad()` method (vulnerable) or a `good*()` method (not vulnerable), so
the method name is the label.

`scripts/neutralize_juliet.py` rewrote `good*` to `funcA*` and `bad*` to
`funcB*`. It kept one fixed mapping for every row, so the prefix became the new
label. Measured on the 961 rows that contain a single method family:

| Prefix | NOT_VULNERABLE | VULNERABLE |
|---|---|---|
| `funcA` | 500 | 0 |
| `funcB` | 0 | 461 |

That is a perfect predictor. A model can score 100% by reading three characters.

## 2. The replacement set

`model-evaluation/juliet-heldout-1000-neutral-v2.csv` flips the mapping per
row: on half the rows `good*` becomes `funcA*`, on the other half it becomes
`funcB*`. Flaw and fix comments are removed. The result:

| Prefix | NOT_VULNERABLE | VULNERABLE |
|---|---|---|
| `funcA` | 249 | 231 |
| `funcB` | 251 | 230 |

The prefix now carries no label. All TriageMate evaluations use v2. The v1 file
stays in the repo so the old number can be reproduced and compared.

## 3. The old training set had the same disease

`finetuning_dataset_v4_train.jsonl` (61,182 rows):

- 48,705 rows (79.6%) had a class name that states the verdict, such as
  `PathTraversalVulnerability` or `SecurePathTraversal`.
- 16,854 rows had comments that state the verdict.
- 9,782 rows (16.0%) were fix-explanation prose, not Java.
- 18,078 rows were duplicates of an earlier row (29.5%).
- 58 rows had a class name that contradicted the label.

The old model was trained on this set, so its score is a name-reading score.

## 4. The honest comparison

The cleaned set (`training/clean_legacy.py`) removes the prose rows, strips
comments, renames verdict-bearing identifiers with a per-row random map, drops
contradictions and duplicates. The cleaned binary classifier is trained once
and scored on the v2 frozen set. The result is reported next to 97.90% in the
main README. A large drop is the expected and useful outcome.
