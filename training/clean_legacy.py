"""Section 6: clean the v4 binary classifier set for the honest before/after run.

Removes prose rows, verdict-bearing identifiers and comments, contradictory
labels, and duplicates. Names are renamed per row so no fixed mapping leaks.
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

LEAK = re.compile(r"\b\w*(?:Vulnerab|Insecure|Secure|Fixed|Safe|Unsafe|Exploit)\w*\b", re.I)
WHITELIST = {
    "SecureRandom", "SecureClassLoader", "SecureCacheResponse", "SecureConnection",
    "SecureSocket", "SafeVarargs", "SafePoint", "FixedDelay",
}
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
CLASS = re.compile(r"\bclass\s+(\w+)")
LABEL = re.compile(r"Classification:\s*(VULNERABLE|NOT_VULNERABLE)\b")


def strip_comments(code):
    return COMMENT.sub("", code)


def neutralize(code):
    """Rename every verdict-bearing identifier with a per-row random map."""
    mapping = {}

    def sub(m):
        name = m.group(0)
        if name in WHITELIST:
            return name
        key = name.lower()
        if key not in mapping:
            mapping[key] = f"ident{len(mapping) + 1}"
        return mapping[key]

    return LEAK.sub(sub, code)


def name_verdict(name):
    low = name.lower()
    if "insecure" in low or "unsafe" in low or "vulnerab" in low:
        return "VULNERABLE"
    if "secure" in low or "safe" in low or "fixed" in low:
        return "NOT_VULNERABLE"
    return None


def clean_row(row):
    msgs = row["messages"]
    code, answer = msgs[1]["content"], msgs[2]["content"]
    if "{" not in code or "To fix the" in code:
        return None, "prose"
    m = LABEL.search(answer)
    if not m:
        return None, "malformed"
    label = m.group(1)
    cls = CLASS.search(code)
    if cls and name_verdict(cls.group(1)) and name_verdict(cls.group(1)) != label:
        return None, "contradiction"
    msgs[1]["content"] = neutralize(strip_comments(code))
    msgs[2]["content"] = f"Classification: {label}"
    return row, label


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/legacy/finetuning_dataset_v4_train.jsonl")
    ap.add_argument("--val", default="data/legacy/finetuning_dataset_v4_val.jsonl")
    ap.add_argument("--out", default="data/legacy")
    args = ap.parse_args()
    out = Path(args.out)
    stats = Counter()
    seen = set()
    for split, path in (("train", args.train), ("val", args.val)):
        kept = []
        for line in open(path, encoding="utf-8"):
            row = json.loads(line)
            cleaned, why = clean_row(row)
            if not cleaned:
                stats[f"{split} {why}"] += 1
                continue
            h = hashlib.sha256(
                re.sub(r"\s+", "", cleaned["messages"][1]["content"]).encode()).hexdigest()
            if h in seen:
                stats[f"{split} duplicate"] += 1
                continue
            seen.add(h)
            kept.append(cleaned)
            stats[f"{split} {why}"] += 1
        with (out / f"legacy_clean_{split}.jsonl").open("w", encoding="utf-8") as fh:
            for row in kept:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(dict(stats))


if __name__ == "__main__":
    main()
