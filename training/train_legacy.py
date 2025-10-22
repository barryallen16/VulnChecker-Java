"""Section 6: one honest run of the old binary classifier on the cleaned v4 set.

Same base model family as the published adapter, 1 epoch, 8k context, answer-only
loss. Evaluates accuracy on the frozen neutral Juliet set.
"""
import argparse
import json
import os
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

DATA_URL = os.environ.get(
    "LEGACY_DATA_URL",
    "https://huggingface.co/datasets/barryallen16/all-tmp/resolve/main/"
    "legacy-v1.tar.gz",
)


def ensure_deps():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "unsloth", "trl", "peft", "accelerate", "datasets",
                           "bitsandbytes"])


def fetch(url, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        urllib.request.urlretrieve(url, dest)
    return dest


def load_jsonl(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/kaggle/tmp/legacy")
    ap.add_argument("--out", default="/kaggle/working/legacy-adapter")
    ap.add_argument("--model", default="unsloth/qwen2.5-7b-instruct-bnb-4bit")
    ap.add_argument("--max-seq", type=int, default=2048)
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()

    ensure_deps()
    import torch
    if not torch.cuda.is_available():
        sys.exit("no GPU")
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import train_on_responses_only
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    d = Path(args.data_dir)
    tgz = fetch(DATA_URL, d / "legacy-v1.tar.gz")
    with tarfile.open(tgz) as t:
        t.extractall(d)
    train = load_jsonl(d / "legacy_clean_train.jsonl")
    val = load_jsonl(d / "legacy_clean_val.jsonl")
    if args.smoke:
        train, val = train[:100], val[:20]

    # T4: standard checkpointing, since Unsloth's offload path produced bf16
    # gradient buffers that broke fp16 AMP.
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=args.max_seq,
        dtype=torch.float16, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=32, lora_alpha=64, lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing=True, random_state=1611)

    def render(row):
        return tokenizer.apply_chat_template(row["messages"], tokenize=False)

    cfg_kwargs = dict(
        output_dir=args.out, per_device_train_batch_size=1,
        gradient_accumulation_steps=16, warmup_steps=50, num_train_epochs=1,
        learning_rate=1e-4, fp16=True, bf16=False, logging_steps=10,
        save_strategy="no", optim="adamw_8bit", weight_decay=0.01,
        lr_scheduler_type="cosine", seed=1611, dataset_text_field="text",
        report_to="none")
    try:
        cfg = SFTConfig(max_length=args.max_seq, **cfg_kwargs)
    except TypeError:
        cfg = SFTConfig(max_seq_length=args.max_seq, **cfg_kwargs)
    trainer_kwargs = dict(
        model=model,
        train_dataset=Dataset.from_list([{"text": render(r)} for r in train]),
        eval_dataset=Dataset.from_list([{"text": render(r)} for r in val]),
        args=cfg)
    try:
        trainer = SFTTrainer(processing_class=tokenizer, **trainer_kwargs)
    except TypeError:  # trl < 0.12
        trainer = SFTTrainer(tokenizer=tokenizer, **trainer_kwargs)
    trainer = train_on_responses_only(
        trainer, instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n")
    trainer.train()
    model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)

    # Honest score on the frozen neutral Juliet set (v2: no name-prefix leak).
    import csv
    csv_path = d / "juliet-heldout-1000-neutral-v2.csv"
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    FastLanguageModel.for_inference(model)
    correct = 0
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for r in rows:
        msgs = [
            {"role": "system", "content": "You are a code vulnerability classifier. "
             "Analyze the provided Java code and classify it as either 'VULNERABLE' "
             "or 'NOT_VULNERABLE'. Reply with exactly one line: "
             "Classification: <label>."},
            {"role": "user", "content": r["code"]},
        ]
        prefix = tokenizer.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True)
        ids = tokenizer(prefix, return_tensors="pt").to(model.device)
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
    result = {"n": len(rows), "correct": correct,
              "accuracy": round(correct / len(rows), 4), "confusion": confusion,
              "train_rows": len(train)}
    Path(args.out, "legacy_eval.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
