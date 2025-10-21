# Phase 0: does the labelled data exist?

Short answer: yes, enough for training and for an honest held-out test.
This note records what was downloaded, what the scanner produced, and how many alerts ended up labelled.

## Tooling

- Semgrep 1.182.1, installed with `uv tool install semgrep`.
- Java 21 and Maven 3.9.16, installed with `mise`.
- Python 3.13 in `.venv`, managed with `uv`.

## Sources

| Suite | Files | Licence | Ground truth |
|---|---|---|---|
| OWASP Benchmark 1.2 | 2,740 Java servlets | GPLv2 | `expectedresults-1.2.csv` |
| Juliet Java 1.3 (snyk mirror) | 46,803 Java files | public domain | method names `bad*` / `good*` |

OWASP has 1,415 vulnerable test cases and 1,325 safe ones.
Juliet has 21,629 files that contain a `void bad()` method; the rest are helpers, good variants and support code.

## Scan

```
semgrep --config p/default --config p/security-audit --config p/owasp-top-ten \
  --json --timeout 30 --max-target-bytes 2000000 --jobs 8 <target>
```

| Suite | Findings | Parse or timeout errors |
|---|---|---|
| OWASP | 2,404 | 0 |
| Juliet | 25,593 | 328 |

The 328 Juliet errors are files Semgrep could not parse, mostly very large generated sources.
They are dropped, not guessed at.

## Join

An alert is kept only when the rule's CWE metadata matches the test case's CWE.
This removes the cross-category noise that makes naive joins look better than they are.

- OWASP: match the file stem against `expectedresults-1.2.csv`.
- Juliet: match `CWE(\d+)_` in the file name against the rule metadata.
- Juliet label: a finding inside a `bad*` method is TP, inside a `good*` method is FP.
- The window is the enclosing method plus class declaration and imports, never a fixed line range.
- Juliet method names are neutralised with a per-row random prefix so the name carries no label.
- `POTENTIAL FLAW` and `FIX` comments are stripped.

## Labelled alerts

| Suite | Alerts | TP | FP | Files |
|---|---|---|---|---|
| OWASP | 1,957 | 1,293 | 664 | 1,670 |
| Juliet | 8,388 | 4,033 | 4,355 | 5,980 |
| Total | 10,345 | 5,326 | 5,019 | 7,650 |

The full split, the leakage checks and the per-family counts are in `notes/data-sheet.md`.

## What Semgrep alone scores

Semgrep is a finder, not a triage tool, so "precision" here means the share of its alerts that are real bugs.

- Alert-level precision on the labelled set: 5,326 / 10,345 = 51.5%.
- Alert-level recall: 100%, because every alert it emits is treated as a bug. This is the baseline the triage model has to beat.
- OWASP file-level recall: 1,118 of 1,415 vulnerable test cases got at least one matching-CWE alert (79.0%).
- OWASP false-alarm rate: 552 of 1,325 safe test cases got a matching-CWE alert (41.7%).
- Juliet file-level recall is not reported. Juliet mixes good and bad methods in one file, so file-level recall would measure the finder's CWE coverage more than its accuracy. Alert-level precision above is the fair number.

## Vul4J

Vul4J was downloaded and counted: 129 entries across 87 repositories.
The build check was not run.
Most entries pin old Maven and Java versions, and the plan explicitly allows a Juliet-only patch check if the build check fails.
Any patch verification in this repo is therefore Juliet-only, and the write-up says so.
Vul4J remains the right next step for a real-project check.
