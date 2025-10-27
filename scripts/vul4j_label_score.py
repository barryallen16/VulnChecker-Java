"""Label Semgrep findings on vul4j and score them with the triage model/heuristic.

Labeling heuristic: a finding is TP if its CWE metadata matches the vul4j
entry's known CWE and it's in a .java file; otherwise FP.

Output: JSONL with id, label, p_tp, rule, cwe, file, line, code_window.
"""
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.cli import heuristic_score
from triage.dataset import build_window

CSV = ROOT / "benchmarks" / "vul4j" / "dataset" / "vul4j_dataset.csv"
SCANS = ROOT / "data" / "vul4j-eval" / "scans"
OUT = ROOT / "data" / "vul4j-eval" / "labeled.jsonl"

# Extract CWE number from metadata like "CWE-611: Improper Restriction..."
CWE_RE = re.compile(r"CWE-(\d+)")


def load_entry(vul_id):
    with open(CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["vul_id"] == vul_id:
                m = CWE_RE.search(r["cwe_id"])
                return {"cwe": f"CWE-{m.group(1)}" if m else None, "file": r["repo_slug"]}
    return None


def cwe_match(finding_cwe, entry_cwe):
    if not entry_cwe or not finding_cwe:
        return False
    entry_num = CWE_RE.search(entry_cwe)
    if not entry_num:
        return False
    for c in finding_cwe:
        m = CWE_RE.search(str(c))
        if m and m.group(1) == entry_num.group(1):
            return True
    return False


def main():
    entries = {}
    meta_files = list(SCANS.glob("*.meta.json"))
    if not meta_files:
        print("No scan metadata found. Run vul4j_eval.py first.")
        return 1

    for mf in meta_files:
        entry = json.loads(mf.read_text())
        entries[entry["vul_id"]] = entry

    rows = []
    for mf in sorted(meta_files):
        entry = json.loads(mf.read_text())
        vul_id = entry["vul_id"]
        entry_cwe = entry["cwe"]
        scan_file = SCANS / f"{vul_id}.json"
        if not scan_file.exists():
            print(f"  {vul_id}: no scan file, skipping")
            continue
        scan = json.loads(scan_file.read_text())
        print(f"  {vul_id} ({entry_cwe}): {len(scan.get('results', []))} findings")

        for r in scan.get("results", []):
            path = r["path"]
            if not path.endswith(".java"):
                continue
            line = r["start"]["line"]
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            finding_cwe = meta.get("cwe", [])
            label = "TP" if cwe_match(finding_cwe, entry_cwe) else "FP"

            # Read source and extract code window
            src_path = Path(path)
            if not src_path.exists():
                continue
            src = src_path.read_text(encoding="utf-8", errors="replace")
            got = build_window(src, line, None, juliet=False)
            if not got:
                continue
            method_name, window = got

            # Heuristic score
            p_tp, _ = heuristic_score({
                "severity": extra.get("severity", "WARNING"),
                "message": extra.get("message", ""),
            })

            rows.append({
                "id": f"{vul_id}:{r['check_id']}:{line}",
                "vul_id": vul_id,
                "label": label,
                "p_tp": p_tp,
                "rule": r["check_id"],
                "cwe": entry_cwe,
                "file": path,
                "line": line,
                "method": method_name,
                "code_window": window,
                "message": extra.get("message", ""),
            })

    # Write JSONL
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Summary
    tp = sum(1 for r in rows if r["label"] == "TP")
    fp = sum(1 for r in rows if r["label"] == "FP")
    print(f"\nTotal: {len(rows)} findings ({tp} TP, {fp} FP) across {len(entries)} entries")
    print(f"Written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
