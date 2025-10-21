#!/usr/bin/env bash
# Package the triage dataset and the cleaned legacy set as GitHub release assets.
# Kaggle kernels download these by URL; no Hugging Face token is needed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TAG="triage-v1"

stage="$(mktemp -d)"
cp data/triage/triage_train.jsonl data/triage/triage_val.jsonl \
   data/triage/triage_test.jsonl data/triage/triage_all.jsonl \
   data/triage/triage_sample200.jsonl "$stage/"
cp model-evaluation/juliet-heldout-1000-neutral-v2.csv \
   model-evaluation/juliet-heldout-1000-neutral.csv \
   model-evaluation/eval-clean-152.csv "$stage/"
cp notes/data-sheet.md "$stage/" 2>/dev/null || true
tar -czf /tmp/triage-v1.tar.gz -C "$stage" .
rm -rf "$stage"

stage="$(mktemp -d)"
cp data/legacy/legacy_clean_train.jsonl data/legacy/legacy_clean_val.jsonl "$stage/"
cp model-evaluation/juliet-heldout-1000-neutral-v2.csv "$stage/"
tar -czf /tmp/legacy-v1.tar.gz -C "$stage" .
rm -rf "$stage"

gh release create "$TAG" /tmp/triage-v1.tar.gz /tmp/legacy-v1.tar.gz \
  --title "TriageMate data v1" \
  --notes "Labelled Semgrep alerts from OWASP Benchmark and Juliet, plus the cleaned legacy classifier set. See data-sheet.md." \
  || gh release upload "$TAG" /tmp/triage-v1.tar.gz /tmp/legacy-v1.tar.gz --clobber
