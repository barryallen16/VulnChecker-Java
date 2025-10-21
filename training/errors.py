"""Pick the most confident mistakes for the error write-up."""
import argparse
import json
from pathlib import Path


def load(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", required=True)
    ap.add_argument("--data", default="data/triage/triage_test.jsonl")
    ap.add_argument("--out", default="notes/errors.md")
    ap.add_argument("--n", type=int, default=30)
    args = ap.parse_args()
    rows = {r["id"]: r for r in load(args.data)}
    preds = load(args.pred)
    wrong = [p for p in preds if p["verdict"] != p["label"]]
    wrong.sort(key=lambda p: -abs(p["p_tp"] - 0.5))
    lines = [f"# {len(wrong)} mistakes out of {len(preds)}", "",
             "Sorted by confidence. Every row is a test-family alert the model "
             "never trained on.", ""]
    for i, p in enumerate(wrong[:args.n], 1):
        r = rows.get(p["id"], {})
        lines += [
            f"## {i}. {r.get('cwe', '?')} {r.get('rule', '?')}",
            "",
            f"- file: `{r.get('file', '?')}`",
            f"- truth: {p['label']}, model: {p['verdict']} (p_tp {p['p_tp']:.3f})",
            f"- why: {p.get('why', '')}",
            f"- fix: {p.get('fix', '')}",
            "",
            "```java",
            (r.get("code_window", "") or "")[:1200],
            "```",
            "",
        ]
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    print(f"{len(wrong)} wrong, wrote {args.out}")


if __name__ == "__main__":
    main()
