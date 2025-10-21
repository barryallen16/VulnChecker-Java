# TriageMate data sheet

## What this is

Labelled static-analysis alerts for Java, used to train and evaluate a triage model. Each row is one Semgrep alert with the enclosing method, a TP/FP label, a short reason and a short fix. The task is sorting alerts, not finding them.

## Sources

- **OWASP Benchmark v1.2** (2,740 Java servlets, `expectedresults-1.2.csv`). GPLv2. Alerts are labelled only when the rule's CWE matches the test case's category; secondary alerts on unrelated rules are dropped.
- **Juliet Java Test Suite 1.3** (46,803 files, snyk mirror of the NIST suite). Public domain. Alerts inside `bad*` methods are TP, inside `good*` methods are FP, and only when the rule CWE matches the file's CWE.
- Scans: Semgrep 1.182.1 with `p/default`, `p/security-audit` and `p/owasp-top-ten`, 30s per-file timeout, 2 MB target cap.

## Rows

| Split | Rows | TP | FP | Families |
|---|---|---|---|---|
| train | 7797 | 3986 | 3811 | 8 |
| val | 299 | 192 | 107 | 3 |
| test | 2249 | 1148 | 1101 | 5 |
| all | 10345 | 5326 | 5019 | 16 |

## Split policy

- Split by CWE family, never at random: the test families are unseen bug types.
- Test families: CWE-22 (path traversal), CWE-78 (OS command injection), CWE-79 (XSS), CWE-90 (LDAP injection), CWE-643 (XPath injection).
- Validation families: CWE-327 (broken crypto), CWE-328 (broken hash), CWE-601 (open redirect).
- Training uses every other family. SQL injection (CWE-89) stays in train because it is by far the largest family; it is covered by the frozen set.
- Files in the frozen eval sets (`juliet-heldout-1000.csv` and its neutral versions, `eval-clean-152.csv`) are excluded from training.
- Identical normalized windows that appear in both train and test are dropped.

## Window construction

The window is the enclosing method plus the class declaration and imports, not a fixed +/- N line window. In Juliet the `bad()` and `good()` methods sit next to each other, so a line window would leak the answer. Juliet method names are renamed with a per-row random prefix (`funcA`/`funcB`) and POTENTIAL FLAW / FIX comments are removed. The random prefix is what makes the name useless as a label.

## Labels and supervision

The TP/FP label is grounded in the benchmark ground truth. The WHY and FIX sentences are templated from the Semgrep rule message and a per-CWE mitigation table, not written by a human or a frontier model. Treat them as style supervision for the verdict, not as expert explanations.

## Known limits

- Semgrep coverage defines the label set. Bug types Semgrep cannot express produce no rows.
- OWASP Benchmark is public and likely in frontier-model training data. The main generalization claim rests on held-out CWE families and Juliet.
- Juliet is synthetic. Real-project sanity checks need Vul4J or a live repo.
- Alerts were not individually audited by a human; the benchmark's own ground truth is the authority.

## Per-family counts (all splits)

| Family | Rows |
|---|---|
| CWE-89 | 5868 |
| CWE-90 | 1120 |
| CWE-470 | 965 |
| CWE-319 | 614 |
| CWE-78 | 364 |
| CWE-79 | 310 |
| CWE-22 | 288 |
| CWE-330 | 218 |
| CWE-643 | 167 |
| CWE-328 | 145 |
| CWE-601 | 90 |
| CWE-327 | 64 |
| CWE-501 | 61 |
| CWE-614 | 53 |
| CWE-329 | 16 |
| CWE-113 | 2 |
