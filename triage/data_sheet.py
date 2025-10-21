"""Generate the TriageMate data sheet from the built splits."""
import argparse
import json
from collections import Counter
from pathlib import Path


def load(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def table(counter, top=40):
    lines = ["| Family | Rows |", "|---|---|"]
    for k, v in counter.most_common(top):
        lines.append(f"| {k} | {v} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/triage")
    ap.add_argument("--out", default="notes/data-sheet.md")
    args = ap.parse_args()
    d = Path(args.data)
    splits = {s: load(d / f"triage_{s}.jsonl") for s in ("train", "val", "test")}
    all_rows = sum(splits.values(), [])
    lines = [
        "# TriageMate data sheet",
        "",
        "## What this is",
        "",
        "Labelled static-analysis alerts for Java, used to train and evaluate a triage "
        "model. Each row is one Semgrep alert with the enclosing method, a TP/FP label, "
        "a short reason and a short fix. The task is sorting alerts, not finding them.",
        "",
        "## Sources",
        "",
        "- **OWASP Benchmark v1.2** (2,740 Java servlets, `expectedresults-1.2.csv`). "
        "GPLv2. Alerts are labelled only when the rule's CWE matches the test case's "
        "category; secondary alerts on unrelated rules are dropped.",
        "- **Juliet Java Test Suite 1.3** (46,803 files, snyk mirror of the NIST suite). "
        "Public domain. Alerts inside `bad*` methods are TP, inside `good*` methods are "
        "FP, and only when the rule CWE matches the file's CWE.",
        "- Scans: Semgrep 1.182.1 with `p/default`, `p/security-audit` and "
        "`p/owasp-top-ten`, 30s per-file timeout, 2 MB target cap.",
        "",
        "## Rows",
        "",
        "| Split | Rows | TP | FP | Families |",
        "|---|---|---|---|---|",
    ]
    for name, rows in splits.items():
        labels = Counter(r["label"] for r in rows)
        lines.append(f"| {name} | {len(rows)} | {labels.get('TP', 0)} | "
                     f"{labels.get('FP', 0)} | {len({r['family'] for r in rows})} |")
    lines += [
        f"| all | {len(all_rows)} | "
        f"{sum(r['label'] == 'TP' for r in all_rows)} | "
        f"{sum(r['label'] == 'FP' for r in all_rows)} | "
        f"{len({r['family'] for r in all_rows})} |",
        "",
        "## Split policy",
        "",
        "- Split by CWE family, never at random: the test families are unseen bug types.",
        "- Test families: CWE-22 (path traversal), CWE-78 (OS command injection), "
        "CWE-79 (XSS), CWE-90 (LDAP injection), CWE-643 (XPath injection).",
        "- Validation families: CWE-327 (broken crypto), CWE-328 (broken hash), "
        "CWE-601 (open redirect).",
        "- Training uses every other family. SQL injection (CWE-89) stays in train "
        "because it is by far the largest family; it is covered by the frozen set.",
        "- Files in the frozen eval sets (`juliet-heldout-1000.csv` and its neutral "
        "versions, `eval-clean-152.csv`) are excluded from training.",
        "- Identical normalized windows that appear in both train and test are dropped.",
        "",
        "## Window construction",
        "",
        "The window is the enclosing method plus the class declaration and imports, "
        "not a fixed +/- N line window. In Juliet the `bad()` and `good()` methods sit "
        "next to each other, so a line window would leak the answer. Juliet method "
        "names are renamed with a per-row random prefix (`funcA`/`funcB`) and "
        "POTENTIAL FLAW / FIX comments are removed. The random prefix is what makes "
        "the name useless as a label.",
        "",
        "## Labels and supervision",
        "",
        "The TP/FP label is grounded in the benchmark ground truth. The WHY and FIX "
        "sentences are templated from the Semgrep rule message and a per-CWE "
        "mitigation table, not written by a human or a frontier model. Treat them as "
        "style supervision for the verdict, not as expert explanations.",
        "",
        "## Known limits",
        "",
        "- Semgrep coverage defines the label set. Bug types Semgrep cannot express "
        "produce no rows.",
        "- OWASP Benchmark is public and likely in frontier-model training data. The "
        "main generalization claim rests on held-out CWE families and Juliet.",
        "- Juliet is synthetic. Real-project sanity checks need Vul4J or a live repo.",
        "- Alerts were not individually audited by a human; the benchmark's own "
        "ground truth is the authority.",
        "",
        "## Per-family counts (all splits)",
        "",
        table(Counter(r["family"] for r in all_rows)),
        "",
    ]
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
