"""Score the old legacy adapter on the leak-free frozen Juliet set.

The old 97.9% number came from a set whose method names leaked the label. This
runs the same model with its original prompt on the v2 neutral set, so the
number is comparable to the old one without the leak.
"""
import argparse
import csv
import io
import json
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

DATA_URL = ("https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/"
            "triage-v1.tar.gz")

SYSTEM = ("You are a code vulnerability classifier. Analyze the provided Java "
          "code and classify it as either 'VULNERABLE' or 'NOT_VULNERABLE'. "
          "Reply with exactly one line: Classification: <label>.")


def ensure_deps():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "unsloth", "peft", "accelerate", "bitsandbytes"])


def fetch_data(dest):
    dest = Path(dest)
    if (dest / "juliet-heldout-1000-neutral-v2.csv").exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / "triage-v1.tar.gz"
    if not tgz.exists():
        urllib.request.urlretrieve(DATA_URL, tgz)
    with tarfile.open(tgz) as t:
        t.extractall(dest)
    return dest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/kaggle/tmp/triage-data")
    ap.add_argument("--adapter-url", required=True)
    ap.add_argument("--model", default="unsloth/qwen2.5-7b-instruct-bnb-4bit")
    ap.add_argument("--max-seq", type=int, default=4096)
    ap.add_argument("--out", default="/kaggle/working/legacy_eval.json")
    args = ap.parse_args()

    ensure_deps()
    import torch
    if not torch.cuda.is_available():
        sys.exit("no GPU")
    from unsloth import FastLanguageModel
    from peft import PeftModel

    data_dir = fetch_data(args.data_dir)
    adapter_dir = Path("/kaggle/tmp/adapter")
    adapter_dir.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(args.adapter_url, timeout=600) as r:
        with zipfile.ZipFile(io.BytesIO(r.read())) as z:
            z.extractall(adapter_dir)
    found = list(adapter_dir.rglob("adapter_config.json"))
    if not found:
        sys.exit("adapter_config.json not found in the zip")

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=args.max_seq,
        dtype=torch.float16, load_in_4bit=True)
    model = PeftModel.from_pretrained(model, str(found[0].parent))
    FastLanguageModel.for_inference(model)

    rows = list(csv.DictReader(
        open(data_dir / "juliet-heldout-1000-neutral-v2.csv", encoding="utf-8")))
    correct = 0
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for i, r in enumerate(rows):
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": r["code"]}]
        prefix = tokenizer.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True)
        ids = tokenizer(prefix, return_tensors="pt").to(model.device)
        with torch.no_grad():
            gen = model.generate(**ids, max_new_tokens=16, do_sample=False,
                                 pad_token_id=tokenizer.eos_token_id)
        text = tokenizer.decode(gen[0][ids.input_ids.shape[1]:],
                                skip_special_tokens=True)
        pred = "VULNERABLE" if "NOT_VULNERABLE" not in text else "NOT_VULNERABLE"
        truth = r["expected"]
        correct += pred == truth
        key = ("tp" if pred == "VULNERABLE" else "fn") if truth == "VULNERABLE" \
            else ("fp" if pred == "VULNERABLE" else "tn")
        confusion[key] += 1
        if i % 100 == 0:
            print(f"{i}/{len(rows)} correct={correct}", flush=True)

    result = {"n": len(rows), "correct": correct,
              "accuracy": round(correct / len(rows), 4), "confusion": confusion}
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
