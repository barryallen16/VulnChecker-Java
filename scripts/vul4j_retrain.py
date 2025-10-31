"""Retrain the QLoRA adapter on real-world Java functions, then score vul4j.

The adapter in the README is trained on synthetic benchmarks (OWASP + Juliet) and
scores worse than random on vul4j. This script tests whether the training data is
the reason. It takes 2,000 functions from the megavul dataset (1,000 with
`is_vulnerable=1`, 1,000 with 0), converts them to the VERDICT/WHY/FIX format,
trains one epoch of QLoRA, and scores the same 66 vul4j findings as the other
scorers in the README table.

No vul4j row is used for training: `vul4j-labeled.jsonl` holds findings from four
entries and the split holds out the last four entry ids, which is all of them, so
the vul4j side of the training set comes out empty.

Needs a CUDA GPU. It ran on a Colab T4 through google-colab-cli:

  colab new --gpu T4 --session vul4j-retrain
  colab exec --session vul4j-retrain --file scripts/vul4j_retrain.py --timeout 3600
  colab download --session vul4j-retrain /tmp/vul4j_megavul_results.jsonl \\
      data/vul4j-eval/vul4j_megavul_results.jsonl

That run scored precision 0.156, recall 0.909, F1 0.267, ROC-AUC 0.656. The
results file it wrote is `data/vul4j-eval/vul4j_megavul_results.jsonl`.
"""
import json
import os
import random
import urllib.request
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
LABELED = ROOT / "data" / "vul4j-eval" / "labeled.jsonl"
LABELS_URL = ("https://huggingface.co/datasets/barryallen16/triagemate/"
              "resolve/main/vul4j-labeled.jsonl")
OUT = ROOT / "data" / "vul4j-eval" / "vul4j_megavul_results.jsonl"

MODEL = "unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit"
MEGAVUL_URL = ("https://huggingface.co/datasets/athrv/"
               "megavul-vulnerability-detection-java/resolve/main/data/"
               "{split}-00000-of-00001.parquet")
MAX_PER_CLASS = 1000

SYSTEM = ("You are a Java security reviewer. You triage static analysis "
          "warnings. Answer in exactly three lines and nothing else.")
INSTRUCTIONS = ("Decide whether this warning is a true positive (a real "
                "exploitable bug) or a false positive (noise). Then give a "
                "one-sentence reason and a one-sentence fix.\n\n"
                "VERDICT: TP or FP\nWHY: one sentence\nFIX: one sentence")

FIXES = {
    "CWE-22": "resolve the path and reject it unless it stays inside the intended directory",
    "CWE-78": "avoid the shell; pass arguments as a list to ProcessBuilder and validate them",
    "CWE-79": "HTML-encode the value before writing it into the response",
    "CWE-611": "disable DOCTYPE declarations and external entity processing in XML parsers",
    "CWE-74": "neutralize special elements in output before use",
    "CWE-77": "avoid the shell; pass arguments as a list",
}
GENERIC_FIX = "validate or sanitize the untrusted value before it reaches the sink"


def cwe_of(cwe_ids):
    if isinstance(cwe_ids, list):
        return cwe_ids[0] if cwe_ids else "CWE-000"
    return str(cwe_ids)


def megavul_row(row):
    """One megavul example as a triage training row.

    megavul rows carry no Semgrep rule, so the rule field is synthesised from the
    CWE. The scoring prompt carries a real rule id, which the model never sees
    during this training.
    """
    cwe = cwe_of(row["cwe_ids"])
    return {
        "id": f"megavul:{row.get('cve_id', 'unknown')}:{str(row.get('commit_hash', ''))[:8]}",
        "vul_id": f"megavul:{row.get('cve_id', 'unknown')}",
        "label": "TP" if int(row["is_vulnerable"]) == 1 else "FP",
        "rule": f"{cwe.lower().replace('-', '_')}.{cwe.lower().replace('-', '_')}",
        "cwe": cwe,
        "file": row.get("file_path", "unknown.java"),
        "line": 1,
        "code_window": str(row["input"])[:18000],
        "reason": str(row["output"])[:220] or f"The {cwe} pattern is present in the code.",
        "fix": FIXES.get(cwe, GENERIC_FIX),
    }


def load_megavul():
    import pandas as pd

    rows, counts = [], {"TP": 0, "FP": 0}
    for split in ("train", "validation", "test"):
        path = Path(f"/tmp/megavul_{split}.parquet")
        if not path.exists():
            print(f"downloading megavul {split}")
            urllib.request.urlretrieve(MEGAVUL_URL.format(split=split), path)
        for _, record in pd.read_parquet(path).iterrows():
            if counts["TP" if int(record["is_vulnerable"]) == 1 else "FP"] >= MAX_PER_CLASS:
                continue
            row = megavul_row(record)
            rows.append(row)
            counts[row["label"]] += 1
        if all(count >= MAX_PER_CLASS for count in counts.values()):
            break
    print(f"megavul rows: {len(rows)} (TP {counts['TP']}, FP {counts['FP']})")
    return rows


def load_labels():
    path = LABELED if LABELED.exists() else Path("/tmp/vul4j-labeled.jsonl")
    if not path.exists():
        urllib.request.urlretrieve(LABELS_URL, path)
    rows = [json.loads(line) for line in open(path, encoding="utf-8")]
    print(f"vul4j findings: {len(rows)}")
    return rows


def prompt(row):
    return (f"RULE: {row['rule']}\nCWE: {row['cwe']}\n"
            f"FILE: {Path(row['file']).name}\n"
            f"CODE:\n```java\n{row['code_window'][:18000]}\n```\n\n{INSTRUCTIONS}")


def train(model, tokenizer, rows):
    """One epoch of QLoRA over the rendered rows; returns the trained model."""
    import torch
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    texts = []
    for row in rows:
        answer = f"VERDICT: {row['label']}\nWHY: {row['reason']}\nFIX: {row['fix']}"
        texts.append(tokenizer.apply_chat_template(
            [{"role": "system", "content": SYSTEM},
             {"role": "user", "content": prompt(row)},
             {"role": "assistant", "content": answer}], tokenize=False))

    max_steps = min(1000, len(texts) // 16 + 1)
    print(f"training on {len(texts)} rows, {max_steps} steps")
    trainer = SFTTrainer(
        model=model,
        train_dataset=Dataset.from_list([{"text": t} for t in texts]),
        args=SFTConfig(
            output_dir="/tmp/adapter", per_device_train_batch_size=1,
            gradient_accumulation_steps=8, warmup_steps=50, max_steps=max_steps,
            learning_rate=1e-4, fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(), logging_steps=20,
            save_strategy="no", optim="adamw_8bit", weight_decay=0.01,
            lr_scheduler_type="cosine", seed=1611, dataset_text_field="text",
            report_to=[], run_name="vul4j-megavul-triage", max_length=4096),
        processing_class=tokenizer)
    trainer.train()
    model.save_pretrained("/tmp/adapter")
    tokenizer.save_pretrained("/tmp/adapter")
    print("adapter saved to /tmp/adapter")
    return model


def score(model, tokenizer, rows):
    """p_tp from the TP/FP logits at the verdict token, as triage/cli.py does."""
    import torch

    tok_tp = tokenizer(" TP", add_special_tokens=False).input_ids[0]
    tok_fp = tokenizer(" FP", add_special_tokens=False).input_ids[0]
    results = []
    for i, row in enumerate(rows):
        prefix = tokenizer.apply_chat_template(
            [{"role": "system", "content": SYSTEM},
             {"role": "user", "content": prompt(row)}],
            tokenize=False, add_generation_prompt=True) + "VERDICT:"
        ids = tokenizer(prefix, return_tensors="pt").to(model.device)
        with torch.no_grad():
            logits = model(**ids).logits[0, -1]
            p_tp = torch.softmax(
                torch.stack([logits[tok_tp], logits[tok_fp]]), 0)[0].item()
        results.append({"id": row["id"], "vul_id": row["vul_id"],
                        "label": row["label"], "p_tp": p_tp,
                        "rule": row["rule"], "cwe": row["cwe"]})
        if i % 10 == 0:
            print(f"  {i}/{len(rows)} p_tp={p_tp:.3f}", flush=True)
    return results


def report(results):
    from sklearn.metrics import roc_auc_score

    y = np.array([1 if r["label"] == "TP" else 0 for r in results])
    scores = np.array([r["p_tp"] for r in results])
    pred = scores >= 0.5
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    auc = float(roc_auc_score(y, scores)) if len(set(y)) > 1 else float("nan")
    print("\n=== QLoRA retrained on megavul, scored on vul4j ===")
    print(f"  n: {len(results)} (base rate {y.mean():.3f})")
    print(f"  TP: {tp}, FP: {fp}, FN: {fn}")
    print(f"  Precision: {precision:.4f}  Recall: {recall:.4f}  F1: {f1:.4f}")
    print(f"  ROC-AUC: {auc:.4f}")
    print(f"  mean p_tp: TP {scores[y == 1].mean():.3f}, FP {scores[y == 0].mean():.3f}")


def main():
    os.system("pip install -q unsloth peft transformers bitsandbytes datasets "
              "javalang pandas pyarrow scikit-learn")
    from unsloth import FastLanguageModel

    labels = load_labels()
    held_out = set(sorted({r["vul_id"] for r in labels})[-4:])
    test_rows = [r for r in labels if r["vul_id"] in held_out]
    train_rows = [r for r in labels if r["vul_id"] not in held_out]
    print(f"held-out entries: {sorted(held_out)} ({len(test_rows)} findings)")
    print(f"vul4j training rows: {len(train_rows)}")

    rows = load_megavul() + train_rows
    random.Random(1611).shuffle(rows)

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL, max_seq_length=4096, dtype=None, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=32, lora_alpha=64, lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing=True, random_state=1611)
    model = train(model, tokenizer, rows)
    FastLanguageModel.for_inference(model)

    results = score(model, tokenizer, test_rows)
    report(results)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")
    print(f"results written to {OUT}")


if __name__ == "__main__":
    main()
