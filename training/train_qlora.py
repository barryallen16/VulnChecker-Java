"""Phase 3: QLoRA triage training on Qwen2.5-Coder-7B-Instruct.

Runs on a single Kaggle T4 through the kaggle-automation runner. Downloads the
released triage dataset, trains with answer-only loss, saves the adapter.
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
    "TRIAGE_DATA_URL",
    "https://huggingface.co/datasets/barryallen16/all-tmp/resolve/main/"
    "triage-v1.tar.gz",
)


def ensure_deps():
    pkgs = ["unsloth", "trl", "peft", "accelerate", "datasets", "bitsandbytes"]
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", *pkgs])


def fetch_data(dest):
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / "triage-v1.tar.gz"
    if not tgz.exists():
        urllib.request.urlretrieve(DATA_URL, tgz)
    with tarfile.open(tgz) as t:
        t.extractall(dest)
    return dest


def load_jsonl(path):
    rows = [json.loads(line) for line in open(path, encoding="utf-8")]
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/kaggle/tmp/triage-data")
    ap.add_argument("--out", default="/kaggle/working/adapter")
    ap.add_argument("--model", default="unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit")
    ap.add_argument("--max-seq", type=int, default=4096)
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--seed", type=int, default=1611)
    args = ap.parse_args()

    ensure_deps()
    import torch
    if not torch.cuda.is_available():
        sys.exit("no GPU")
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import train_on_responses_only
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    data_dir = fetch_data(Path(args.data_dir))
    train = load_jsonl(data_dir / "triage_train.jsonl")
    val = load_jsonl(data_dir / "triage_val.jsonl")
    if args.smoke:
        train, val = train[:100], val[:20]

    use_bf16 = (torch.cuda.is_bf16_supported()
                and torch.cuda.get_device_capability()[0] >= 8)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq,
        dtype=torch.bfloat16 if use_bf16 else torch.float16,
        load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=32,
        lora_alpha=64,
        lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing=True,
        random_state=args.seed,
    )

    system = ("You are a Java security reviewer. You triage static analysis "
              "warnings. Answer in exactly three lines and nothing else.")
    instructions = ("Decide whether this warning is a true positive (a real "
                    "exploitable bug) or a false positive (noise). Then give a "
                    "one-sentence reason and a one-sentence fix.\n\n"
                    "VERDICT: TP or FP\nWHY: one sentence\nFIX: one sentence")

    def render(row):
        window = row["code_window"][:18000]
        user = (f"RULE: {row['rule']}\nCWE: {row['cwe']}\n"
                f"FILE: {row['file'].split('/')[-1]}\n"
                f"CODE:\n```java\n{window}\n```\n\n{instructions}")
        answer = f"VERDICT: {row['label']}\nWHY: {row['reason']}\nFIX: {row['fix']}"
        msgs = [{"role": "system", "content": system},
                {"role": "user", "content": user},
                {"role": "assistant", "content": answer}]
        return tokenizer.apply_chat_template(msgs, tokenize=False)

    ds_train = Dataset.from_list([{"text": render(r)} for r in train])
    ds_val = Dataset.from_list([{"text": render(r)} for r in val])

    report = "none"
    if os.environ.get("WANDB_API_KEY"):
        os.environ["WANDB_PROJECT"] = "triagemate-triage"
        report = "wandb"

    cfg_kwargs = dict(
        output_dir=args.out,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=16,
        warmup_steps=50,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        learning_rate=1e-4,
        fp16=not use_bf16,
        bf16=use_bf16,
        logging_steps=10,
        # Only the final adapter is published; checkpoints would triple the
        # output size and the pull cache is what fills the server's disk.
        save_strategy="no",
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=args.seed,
        dataset_text_field="text",
        report_to=report,
        run_name="triagemate-triage",
    )
    try:
        cfg = SFTConfig(max_length=args.max_seq, **cfg_kwargs)
    except TypeError:
        cfg = SFTConfig(max_seq_length=args.max_seq, **cfg_kwargs)
    trainer_kwargs = dict(model=model, train_dataset=ds_train,
                          eval_dataset=ds_val, args=cfg)
    try:
        trainer = SFTTrainer(processing_class=tokenizer, **trainer_kwargs)
    except TypeError:  # trl < 0.12
        trainer = SFTTrainer(tokenizer=tokenizer, **trainer_kwargs)
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )
    trainer.train()
    model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)
    summary = {
        "train_rows": len(train), "val_rows": len(val),
        "epochs": args.epochs, "smoke": args.smoke,
        "train_runtime": trainer.state.log_history[-1].get("train_runtime"),
    }
    Path(args.out, "train_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
