"""Build the Phase 2/3 comparison table from prediction files.

Usage: python training/report.py --pred semgrep=... --pred codebert=... 
A prediction file is JSONL with id, label, p_tp.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from triage.metrics import labels, semgrep_row, summarize


def read(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def calibration_bins(y, score, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    out = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (score >= lo) & (score < hi if hi < 1 else score <= hi)
        if m.sum():
            out.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": int(m.sum()),
                        "mean_conf": round(float(score[m].mean()), 3),
                        "accuracy": round(float(y[m].mean()), 3)})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", action="append", required=True,
                    help="name=path to predictions.jsonl")
    ap.add_argument("--out", default="evaluation")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    calib = {}
    per_set = {}
    all_rows = {}
    for spec in args.pred:
        name, _, path = spec.partition("=")
        rows = read(path)
        all_rows[name] = rows
        for set_name in sorted({r.get("set", "all") for r in rows}):
            sub = [r for r in rows if r.get("set", "all") == set_name]
            y = labels(sub)
            score = np.array([r["p_tp"] for r in sub])
            per_set.setdefault(set_name, []).append(summarize(y, score, name))
            calib.setdefault(set_name, {})[name] = calibration_bins(y, score)
            if name == "semgrep":
                per_set[set_name][-1] = semgrep_row(y)
    header = ("| Model | n | Precision | Recall | F1 | Precision @ 90% recall | "
              "ROC-AUC | ECE |")
    sections = []
    for set_name, table in per_set.items():
        # Semgrep alone is implied by the labels, always include it.
        if not any(r["model"] == "semgrep alone" for r in table):
            base = next((rows for rows in all_rows.values()
                         if any(r.get("set", "all") == set_name for r in rows)), [])
            table.insert(0, semgrep_row(labels(
                [r for r in base if r.get("set", "all") == set_name])))
        lines = [f"## {set_name}", "", header, "|---|---|---|---|---|---|---|---|"]
        for r in table:
            lines.append(
                f"| {r['model']} | {r['n']} | {r['precision']:.3f} | {r['recall']:.3f} | "
                f"{r['f1']:.3f} | {r['precision_at_90_recall']:.3f} | "
                f"{r['roc_auc']:.3f} | {r['ece']:.3f} |")
        sections.append("\n".join(lines))
    md = "\n\n".join(sections) + "\n"
    (out / "comparison.md").write_text(md, encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(per_set, indent=2), encoding="utf-8")
    (out / "calibration.json").write_text(json.dumps(calib, indent=2), encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
