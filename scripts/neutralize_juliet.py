"""Neutralize Juliet label leaks: good/bad identifiers and FLAW/FIX comments.

Juliet method names (bad, goodG2B, bad_source ...) encode the expected verdict,
so a model can score by reading names instead of code. This rewrites them to
neutral names and strips POTENTIAL FLAW / FIX comments. Package and class names
(CWE type info, no verdict) are kept.
Usage: python scripts/neutralize_juliet.py
"""
import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "model-evaluation" / "juliet-heldout-1000.csv"
OUT = ROOT / "model-evaluation" / "juliet-heldout-1000-neutral.csv"

COUNTER = [0]


def fresh(prefix):
    COUNTER[0] += 1
    return f"{prefix}{COUNTER[0]}"


def neutralize(code):
    mapping = {}

    def sub_name(m):
        name = m.group(0)
        key = name.lower()
        if key not in mapping:
            mapping[key] = fresh("funcA" if key.startswith("good") else "funcB")
        return mapping[key]

    code = re.sub(r"\b(good\w*|bad\w*)", sub_name, code, flags=re.I)
    def sub_comment(m):
        return "" if re.search(r"POTENTIAL FLAW|FIX:", m.group(0)) else m.group(0)

    code = re.sub(r"/\*.*?\*/", sub_comment, code, flags=re.S)
    return code


def main():
    rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
    for r in rows:
        r["code"] = neutralize(r["code"])
    with OUT.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["code", "expected", "cwe", "source"])
        w.writeheader()
        w.writerows(rows)
    left = sum(1 for r in rows
               if re.search(r"\b(good\w*|bad\w*)|POTENTIAL FLAW|FIX:",
                            r["code"], re.I))
    print(f"wrote {OUT.name}: {len(rows)} rows, leaky markers left: {left}")


if __name__ == "__main__":
    main()
