"""Build a frozen Juliet set whose neutral names cannot be used as a label.

The first neutral set (scripts/neutralize_juliet.py) maps good* -> funcA and
bad* -> funcB consistently, so funcA/funcB are a perfect label proxy. This
version shuffles the mapping per row and strips flaw/fix comments.
"""
import csv
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "model-evaluation" / "juliet-heldout-1000.csv"
OUT = ROOT / "model-evaluation" / "juliet-heldout-1000-neutral-v2.csv"
NAMES = re.compile(r"\b(good\w*|bad\w*)", re.I)
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
LEAK = re.compile(r"POTENTIAL FLAW|FIX:|FLAW", re.I)


def neutralize(code, rng):
    code = COMMENTS.sub(lambda m: "" if LEAK.search(m.group(0)) else m.group(0), code)
    found = sorted({m.group(0) for m in NAMES.finditer(code)})
    good = [n for n in found if n.lower().startswith("good")]
    bad = [n for n in found if n.lower().startswith("bad")]
    # Flip which neutral prefix means "good" per row, so the prefix carries no label.
    if rng.random() < 0.5:
        good_prefix, bad_prefix = "funcA", "funcB"
    else:
        good_prefix, bad_prefix = "funcB", "funcA"
    mapping = {}
    for i, n in enumerate(good, 1):
        mapping[n.lower()] = f"{good_prefix}{i}"
    for i, n in enumerate(bad, 1):
        mapping[n.lower()] = f"{bad_prefix}{i}"

    return NAMES.sub(lambda m: mapping[m.group(0).lower()], code)


def main():
    rng = random.Random(1611)
    rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
    for r in rows:
        r["code"] = neutralize(r["code"], rng)
    with OUT.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["code", "expected", "cwe", "source"])
        w.writeheader()
        w.writerows(rows)
    leak = sum(1 for r in rows if re.search(r"\b(good\w*|bad\w*)|POTENTIAL FLAW|FIX:", r["code"], re.I))
    print(f"wrote {OUT.name}: {len(rows)} rows, leaky markers left: {leak}")


if __name__ == "__main__":
    main()
