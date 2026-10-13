#!/usr/bin/env bash
# Pull the seven JSONL stages (~1.1 GB) from the HF dataset repo into datasets/.
set -e
cd "$(dirname "$0")/.."
hf download barryallen16/VulnChecker-Java --repo-type dataset --local-dir datasets
