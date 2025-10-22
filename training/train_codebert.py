"""Phase 2 baseline: 125M CodeBERT classifier on the same triage windows."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import roc_auc_score
from torch.utils.data import Dataset
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)


def ensure_deps():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "transformers", "accelerate", "scikit-learn"])


def load(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def text_of(r):
    return f"{r['rule']} {r['cwe']}\n{r.get('sink_line', '')}\n{r['code_window']}"


class Rows(Dataset):
    def __init__(self, rows, tok):
        self.rows = rows
        self.tok = tok

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, i):
        r = self.rows[i]
        enc = self.tok(text_of(r), truncation=True, max_length=512,
                       padding="max_length", return_tensors="pt")
        return {"input_ids": enc.input_ids[0],
                "attention_mask": enc.attention_mask[0],
                "labels": torch.tensor(1 if r["label"] == "TP" else 0)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/kaggle/working/triage-data")
    ap.add_argument("--out", default="/kaggle/working/codebert")
    ap.add_argument("--model", default="microsoft/codebert-base")
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--data-url", default=(
        "https://huggingface.co/datasets/barryallen16/all-tmp/resolve/main/"
        "triage-v1.tar.gz"))
    args = ap.parse_args()
    ensure_deps()
    if not torch.cuda.is_available():
        sys.exit("no GPU")
    d = Path(args.data_dir)
    if args.data_url:
        import tarfile
        import urllib.request
        d.mkdir(parents=True, exist_ok=True)
        tgz = d / "triage-v1.tar.gz"
        if not tgz.exists():
            urllib.request.urlretrieve(args.data_url, tgz)
        with tarfile.open(tgz) as t:
            t.extractall(d)
    train, val, test = (load(d / f"triage_{s}.jsonl") for s in ("train", "val", "test"))
    if args.limit:
        train, val, test = train[:args.limit], val[:args.limit // 5], test[:args.limit // 5]

    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)
    import inspect
    train_kwargs = dict(
        output_dir=args.out, num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        learning_rate=args.lr, warmup_ratio=0.06,
        eval_strategy="epoch", save_strategy="no",
        logging_steps=50, seed=1611, report_to=[],
        fp16=torch.cuda.is_available(),
    )
    valid = set(inspect.signature(TrainingArguments.__init__).parameters)
    train_kwargs = {k: v for k, v in train_kwargs.items() if k in valid}
    trainer = Trainer(
        model=model,
        args=TrainingArguments(**train_kwargs),
        train_dataset=Rows(train, tok),
        eval_dataset=Rows(val, tok),
    )
    trainer.train()
    pred = trainer.predict(Rows(test, tok))
    logits = pred.predictions
    exp = np.exp(logits - logits.max(axis=1, keepdims=True))
    p_tp = exp[:, 1] / exp.sum(axis=1)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "predictions.jsonl").open("w", encoding="utf-8") as fh:
        for r, p in zip(test, p_tp):
            fh.write(json.dumps({"id": r["id"], "set": "test", "label": r["label"],
                                 "p_tp": float(p)}) + "\n")
    auc = roc_auc_score([1 if r["label"] == "TP" else 0 for r in test], p_tp)
    print(f"test rows {len(test)} roc_auc {auc:.4f}")
    trainer.save_model(args.out)


if __name__ == "__main__":
    main()
