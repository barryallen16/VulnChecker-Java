"""Score a base or fine-tuned model on the triage sets.

Confidence is P(TP) at the verdict token, so calibration is measured on the
same decision the model actually makes. Runs on Kaggle GPU.
"""
import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import torch


def ensure_deps():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "unsloth", "peft", "accelerate", "datasets",
                           "bitsandbytes"])

SYSTEM = ("You are a Java security reviewer. You triage static analysis "
          "warnings. Answer in exactly three lines and nothing else.")
INSTRUCTIONS = ("Decide whether this warning is a true positive (a real "
                "exploitable bug) or a false positive (noise). Then give a "
                "one-sentence reason and a one-sentence fix.\n\n"
                "VERDICT: TP or FP\nWHY: one sentence\nFIX: one sentence")


def user_prompt(row):
    window = row["code_window"][:18000]
    return (f"RULE: {row['rule']}\nCWE: {row['cwe']}\n"
            f"FILE: {row['file'].split('/')[-1]}\n"
            f"CODE:\n```java\n{window}\n```\n\n{INSTRUCTIONS}")


DATA_URL = ("https://github.com/barryallen16/VulnChecker-Java/releases/download/"
            "triage-v1/triage-v1.tar.gz")


def fetch_data(dest):
    import tarfile
    import urllib.request
    dest = Path(dest)
    if (dest / "triage_test.jsonl").exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / "triage-v1.tar.gz"
    if not tgz.exists():
        urllib.request.urlretrieve(DATA_URL, tgz)
    with tarfile.open(tgz) as t:
        t.extractall(dest)
    return dest


def load_set(name, data_dir):
    if name in ("test", "sample200"):
        fname = "triage_test.jsonl" if name == "test" else "triage_sample200.jsonl"
        return [json.loads(line) for line in
                open(Path(data_dir) / fname, encoding="utf-8")]
    rows = []
    if name in ("juliet-frozen", "juliet-frozen-v1"):
        fname = ("juliet-heldout-1000-neutral-v2.csv" if name == "juliet-frozen"
                 else "juliet-heldout-1000-neutral.csv")
        src = Path(data_dir) / fname
        for i, r in enumerate(csv.DictReader(open(src, encoding="utf-8"))):
            m = re.search(r"CWE(\d+)", r["cwe"])
            rows.append({
                "id": f"{name}:{i}",
                "rule": "juliet.frozen",
                "cwe": f"CWE-{m.group(1)}" if m else "CWE-000",
                "file": r["cwe"] + ".java",
                "code_window": r["code"],
                "label": "TP" if r["expected"] == "VULNERABLE" else "FP",
            })
    elif name == "eval-clean":
        src = Path(data_dir) / "eval-clean-152.csv"
        for i, r in enumerate(csv.DictReader(open(src, encoding="utf-8"))):
            rows.append({
                "id": f"eval-clean:{i}",
                "rule": "legacy.binary-classifier",
                "cwe": "CWE-000",
                "file": f"eval_{i}.java",
                "code_window": r["code"],
                "label": "TP" if r["expected"].lower().startswith(("vuln", "1", "true"))
                         else "FP",
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit")
    ap.add_argument("--adapter", default="")
    ap.add_argument("--adapter-url", default="",
                    help="zip URL for the adapter; downloaded and extracted first")
    ap.add_argument("--data-dir", default="/kaggle/working/triage-data")
    ap.add_argument("--set", action="append", default=[])
    ap.add_argument("--shots", type=int, default=0)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-new", type=int, default=96)
    ap.add_argument("--out", default="/kaggle/working/predictions.jsonl")
    args = ap.parse_args()
    sets = args.set or ["test"]
    ensure_deps()
    args.data_dir = str(fetch_data(args.data_dir))
    if args.adapter_url:
        import io
        import urllib.request
        import zipfile
        dest = Path("/kaggle/working/adapter")
        dest.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(args.adapter_url, timeout=600) as r:
            with zipfile.ZipFile(io.BytesIO(r.read())) as z:
                z.extractall(dest)
        args.adapter = str(dest)

    from unsloth import FastLanguageModel
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=8192, dtype=None, load_in_4bit=True)
    if args.adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, args.adapter)
    FastLanguageModel.for_inference(model)

    shots = []
    if args.shots:
        train = [json.loads(line) for line in
                 open(Path(args.data_dir) / "triage_train.jsonl", encoding="utf-8")]
        tp = next((r for r in train if r["label"] == "TP"
                   and len(r["code_window"]) < 2500), None)
        fp = next((r for r in train if r["label"] == "FP"
                   and len(r["code_window"]) < 2500), None)
        shots = [r for r in (tp, fp, tp) if r]

    tok_tp = tokenizer(" TP", add_special_tokens=False).input_ids[0]
    tok_fp = tokenizer(" FP", add_special_tokens=False).input_ids[0]
    out = open(args.out, "w", encoding="utf-8")
    for set_name in sets:
        rows = load_set(set_name, args.data_dir)
        if args.limit:
            rows = rows[:args.limit]
        for i, row in enumerate(rows):
            msgs = [{"role": "system", "content": SYSTEM}]
            for s in shots:
                msgs.append({"role": "user", "content": user_prompt(s)})
                msgs.append({"role": "assistant",
                             "content": f"VERDICT: {s['label']}\nWHY: {s.get('reason', '')}\n"
                                        f"FIX: {s.get('fix', '')}"})
            msgs.append({"role": "user", "content": user_prompt(row)})
            prefix = tokenizer.apply_chat_template(
                msgs, tokenize=False, add_generation_prompt=True) + "VERDICT:"
            ids = tokenizer(prefix, return_tensors="pt").to(model.device)
            start = time.time()
            with torch.no_grad():
                logits = model(**ids).logits[0, -1]
                p_tp = torch.softmax(
                    torch.stack([logits[tok_tp], logits[tok_fp]]), dim=0)[0].item()
                gen = model.generate(**ids, max_new_tokens=args.max_new, do_sample=False,
                                     pad_token_id=tokenizer.eos_token_id)
            text = tokenizer.decode(gen[0][ids.input_ids.shape[1]:],
                                    skip_special_tokens=True)
            verdict = "TP" if p_tp >= 0.5 else "FP"
            why = re.search(r"WHY:\s*(.+)", text)
            fix = re.search(r"FIX:\s*(.+)", text)
            out.write(json.dumps({
                "id": row["id"], "set": set_name, "label": row["label"],
                "p_tp": p_tp, "verdict": verdict,
                "why": why.group(1).strip() if why else "",
                "fix": fix.group(1).strip() if fix else "",
                "raw": ("VERDICT:" + text)[:600],
                "seconds": round(time.time() - start, 2),
            }, ensure_ascii=False) + "\n")
            if i % 25 == 0:
                print(f"{set_name} {i}/{len(rows)} p_tp={p_tp:.3f}", flush=True)
    out.close()


if __name__ == "__main__":
    main()
