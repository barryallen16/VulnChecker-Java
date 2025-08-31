"""GPU eval runner: same harness as java_eval_new.ipynb, as a script.

Runs one LoRA checkpoint against one CSV (code,expected) and writes a
per-case JSON like misc/eval-res1.txt. Colab GPU: 200 cases ~30-60 min on T4.
Usage:
  python scripts/run_eval.py <repo_id> <cases.csv> <out.json> [--max N]
"""
import argparse
import csv
import json
import sys

SYSTEM = ("You are a code vulnerability classifier. Analyze the provided Java "
          "code and classify it as either 'VULNERABLE' or 'NOT_VULNERABLE'. "
          "Reply with exactly one line: Classification: <label>.")


def classify(model, tok, code):
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": code}]
    text = tok.apply_chat_template(msgs, tokenize=False,
                                   add_generation_prompt=True)
    ids = tok(text, return_tensors="pt").to(model.device)
    out = model.generate(**ids, max_new_tokens=64, do_sample=False)
    gen = tok.decode(out[0][ids["input_ids"].shape[1]:])
    up = gen.upper()
    if "NOT_VULNERABLE" in up or "NOT VULNERABLE" in up:
        return "NOT_VULNERABLE", gen.strip()
    return "VULNERABLE", gen.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_id")
    ap.add_argument("cases_csv")
    ap.add_argument("out_json")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--seq", type=int, default=2048)
    a = ap.parse_args()

    from unsloth import FastLanguageModel
    model, tok = FastLanguageModel.from_pretrained(
        model_name=a.repo_id, max_seq_length=a.seq,
        dtype=None, load_in_4bit=True)
    FastLanguageModel.for_inference(model)

    cases = list(csv.DictReader(open(a.cases_csv, encoding="utf-8")))
    if a.max:
        cases = cases[:a.max]
    detail, correct = [], 0
    for i, t in enumerate(cases):
        pred, raw = classify(model, tok, t["code"])
        ok = pred == t["expected"].strip()
        correct += ok
        detail.append({"test_case": i + 1, "expected": t["expected"],
                       "predicted": pred, "correct": ok,
                       "model_output": raw})
        print(f"{i + 1}/{len(cases)} {'ok' if ok else 'MISS'}", flush=True)
    summary = {"total_test_cases": len(cases),
               "correct_predictions": correct,
               "accuracy": correct / len(cases),
               "checkpoint": a.repo_id, "cases": a.cases_csv}
    json.dump({"summary": summary, "detailed_results": detail},
              open(a.out_json, "w", encoding="utf-8"), indent=2)
    print(json.dumps(summary))


if __name__ == "__main__":
    sys.exit(main())
