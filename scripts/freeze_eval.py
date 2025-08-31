"""Freeze a clean eval set: drop the 31 prose rows that duplicate training data.

Reads the 200-case CSV (downloads it if missing), removes rows whose `code`
is fix-explanation prose instead of Java (the audit's `To fix the` heuristic),
checks the remainder against the v3 training set, writes eval-fixed-169.csv.
Usage: python scripts/freeze_eval.py
"""
import csv
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_URL = ("https://huggingface.co/datasets/barryallen16/"
           "java_vulnerability_dataset/resolve/main/java_vul_dataset.csv")
RAW = ROOT / "model-evaluation" / "java_vul_dataset.csv"
OUT = ROOT / "model-evaluation" / "eval-clean-152.csv"
V3 = ROOT / "datasets" / "final-dataset" / "finetuning_dataset_v3.jsonl"


def norm(s):
    return " ".join(s.split())


def main():
    if not RAW.exists():
        print("downloading 200-case csv")
        urllib.request.urlretrieve(CSV_URL, RAW)
    rows = list(csv.DictReader(RAW.open(encoding="utf-8")))
    print(f"raw rows: {len(rows)}")
    prose = [r for r in rows if "To fix the" in r["code"]]
    kept = [r for r in rows if "To fix the" not in r["code"]]
    print(f"prose rows dropped: {len(prose)}")
    train_codes = set()
    for line in V3.open(encoding="utf-8"):
        try:
            m = json.loads(line)["messages"]
            train_codes.add(norm(m[1]["content"]))
        except (KeyError, IndexError, json.JSONDecodeError):
            continue
    leaked = sum(1 for r in prose if norm(r["code"]) in train_codes)
    print(f"dropped rows verbatim in v3: {leaked}/{len(prose)}")
    overlap = [r for r in kept if norm(r["code"]) in train_codes]
    print(f"kept rows overlapping v3: {len(overlap)}/{len(kept)}")
    clean = [r for r in kept if norm(r["code"]) not in train_codes]
    with OUT.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["code", "expected"])
        w.writeheader()
        w.writerows(clean)
    print(f"wrote {OUT.name}: {len(clean)} rows")


if __name__ == "__main__":
    main()
