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
    table, calib = [], {}
    for spec in args.pred:
        name, _, path = spec.partition("=")
        rows = read(path)
        y = labels(rows)
        score = np.array([r["p_tp"] for r in rows])
        table.append(summarize(y, score, name))
        calib[name] = calibration_bins(y, score)
        if name == "semgrep":
            table[-1] = semgrep_row(y)
    # Semgrep alone is implied by the labels, always include it.
    if not any(r["model"] == "semgrep alone" for r in table):
        y = labels(read(args.pred[0].partition("=")[2]))
        table.insert(0, semgrep_row(y))

    header = ("| Model | n | Precision | Recall | F1 | Precision @ 90% recall | "
              "ROC-AUC | ECE |")
    lines = [header, "|---|---|---|---|---|---|---|---|"]
    for r in table:
        lines.append(
            f"| {r['model']} | {r['n']} | {r['precision']:.3f} | {r['recall']:.3f} | "
            f"{r['f1']:.3f} | {r['precision_at_90_recall']:.3f} | "
            f"{r['roc_auc']:.3f} | {r['ece']:.3f} |")
    md = "\n".join(lines) + "\n"
    (out / "comparison.md").write_text(md, encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(table, indent=2), encoding="utf-8")
    (out / "calibration.json").write_text(json.dumps(calib, indent=2), encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
