"""Score vul4j findings with CodeBERT (base model, zero-shot, CPU)."""
import json
import sys
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from triage.metrics import summarize, labels

ROOT = Path(__file__).resolve().parent.parent
LABELED = ROOT / "data" / "vul4j-eval" / "labeled.jsonl"
OUT = ROOT / "data" / "vul4j-eval" / "vul4j_codebert_results.jsonl"


def text_of(r):
    return f"{r['rule']} {r['cwe']}\n{r.get('sink_line', '')}\n{r['code_window']}"


def main():
    rows = [json.loads(line) for line in open(LABELED, encoding="utf-8")]
    print(f"Loaded {len(rows)} vul4j findings")

    model_name = "microsoft/codebert-base"
    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    model.eval()

    results = []
    with torch.no_grad():
        for i, r in enumerate(rows):
            enc = tok(text_of(r), truncation=True, max_length=512,
                      padding="max_length", return_tensors="pt")
            logits = model(**enc).logits[0]
            exp = np.exp(logits - logits.max())
            p_tp = float(exp[1] / exp.sum())
            results.append({
                "id": r["id"],
                "vul_id": r["vul_id"],
                "label": r["label"],
                "p_tp": p_tp,
                "rule": r["rule"],
                "cwe": r["cwe"],
                "heuristic_p_tp": r["p_tp"],
            })
            if i % 10 == 0:
                print(f"  {i}/{len(rows)} p_tp={p_tp:.3f}", flush=True)

    y = np.array([1 if r["label"] == "TP" else 0 for r in results])
    cb_scores = np.array([r["p_tp"] for r in results])
    heur_scores = np.array([r["heuristic_p_tp"] for r in results])

    print("\n=== CODEBERT (base, zero-shot) on vul4j ===")
    m = summarize(y, cb_scores, "codebert-base")
    for k, v in m.items():
        print(f"  {k}: {v}")

    print("\n=== HEURISTIC on vul4j ===")
    h = summarize(y, heur_scores, "heuristic")
    for k, v in h.items():
        print(f"  {k}: {v}")

    print("\n=== QLORA on vul4j (from Colab) ===")
    qlora_path = ROOT / "data" / "vul4j-eval" / "vul4j_model_results.jsonl"
    if qlora_path.exists():
        qlora_rows = [json.loads(line) for line in open(qlora_path, encoding="utf-8")]
        qlora_scores = np.array([r["p_tp"] for r in qlora_rows])
        q = summarize(y, qlora_scores, "qlora")
        for k, v in q.items():
            print(f"  {k}: {v}")
    else:
        print("  QLoRA results not found")

    print("\n=== Per-finding comparison ===")
    for r in sorted(results, key=lambda x: -x["p_tp"]):
        mark = "TP" if r["label"] == "TP" else "FP"
        print(f"  {r['vul_id']:10s} {mark:3s} cb={r['p_tp']:.3f} heur={r['heuristic_p_tp']:.3f} {r['rule'][:45]}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    print(f"\nResults saved to {OUT}")


if __name__ == "__main__":
    main()
