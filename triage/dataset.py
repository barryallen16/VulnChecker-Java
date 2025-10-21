"""Phase 0/1: join Semgrep alerts to benchmark ground truth and build triage rows.

The window is the enclosing method plus the class declaration and imports, not a
fixed line window: in Juliet the bad() and good() methods sit next to each other,
so a +/- N line window would leak the answer.
"""
import argparse
import csv
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

import javalang

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
DATA = ROOT / "data"

# Phase 1 split: test/val get whole CWE families the model never trains on.
# SQL injection (CWE-89) stays in train because it is by far the largest family;
# the test claim rests on five other families instead.
TEST_FAMILIES = {"CWE-22", "CWE-78", "CWE-79", "CWE-90", "CWE-643"}
VAL_FAMILIES = {"CWE-327", "CWE-328", "CWE-601"}

# Per-CWE mitigation text for the FIX line. Falls back to generic advice.
FIXES = {
    "CWE-22": "resolve the path and reject it unless it stays inside the intended directory",
    "CWE-78": "avoid the shell; pass arguments as a list to ProcessBuilder and validate them",
    "CWE-79": "HTML-encode the value before writing it into the response",
    "CWE-89": "use a PreparedStatement with bound parameters instead of building SQL text",
    "CWE-90": "escape the value with an LDAP encoder before adding it to the filter",
    "CWE-113": "strip CR and LF from the value before it reaches the response header",
    "CWE-327": "replace the broken cipher with AES/GCM and a random IV",
    "CWE-328": "use SHA-256 or stronger instead of the broken hash",
    "CWE-330": "use java.security.SecureRandom instead of java.util.Random",
    "CWE-501": "do not store untrusted data in the session trust boundary",
    "CWE-614": "set the Secure flag on the cookie",
    "CWE-643": "escape the value with an XPath encoder before building the expression",
}
GENERIC_FIX = "validate or sanitize the untrusted value before it reaches the sink"

COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
VERDICT_WORD_RE = re.compile(r"\b(good\w*|bad\w*)", re.I)
LEAK_COMMENT_RE = re.compile(r"POTENTIAL FLAW|FIX:|FLAW", re.I)
MODIFIERS = (
    "public|private|protected|static|final|synchronized|abstract|native|strictfp|default"
)
SIG_RE = re.compile(
    r"^[ \t]*(?:(?:" + MODIFIERS + r")\s+)*[\w.$<>\[\],? ]+?\s+(\w+)\s*"
    r"\([^;{}]*\)\s*(?:throws [\w., ]+)?\s*\{",
    re.M,
)


def line_offsets(src):
    offs = [0]
    for line in src.splitlines(keepends=True):
        offs.append(offs[-1] + len(line))
    return offs


def scan_to(src, pos, target):
    """Return the index of `target` at/after pos, skipping strings and comments."""
    i, n = pos, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif c == "'":
            i += 1
            while i < n and src[i] != "'":
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == target:
            return i
        else:
            i += 1
    return -1


def match_brace(src, open_idx):
    depth, i, n = 0, open_idx, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif c == "'":
            i += 1
            while i < n and src[i] != "'":
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == "{":
            depth += 1
            i += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
            i += 1
        else:
            i += 1
    return -1


def method_ranges(src):
    """[(name, start_line, end_line)] for every method, innermost last."""
    out = []
    try:
        tree = javalang.parse.parse(src)
        for _, node in tree.filter(javalang.tree.MethodDeclaration):
            if not node.position:
                continue
            out.append((node.name, node.position.line, node.position.column))
    except Exception:
        out = []
    if not out:
        for m in SIG_RE.finditer(src):
            out.append((m.group(1), src.count("\n", 0, m.start()) + 1, 1))
    offs = line_offsets(src)
    ranges = []
    for name, line, col in out:
        start = offs[line - 1] + (col - 1)
        brace = scan_to(src, start, "{")
        if brace < 0:
            continue
        end = match_brace(src, brace)
        if end < 0:
            continue
        ranges.append((name, line, src.count("\n", 0, end) + 1, start, end))
    return ranges


def enclosing_method(ranges, line):
    hits = [r for r in ranges if r[1] <= line <= r[2]]
    return min(hits, key=lambda r: r[2] - r[1]) if hits else None


def neutralize(code, rng):
    """Rename good*/bad* identifiers with a per-row random prefix.

    All good names share one prefix and all bad names the other, but which
    prefix means good is flipped per row, so the name cannot be used as a label.
    """
    names = sorted({m.group(0) for m in VERDICT_WORD_RE.finditer(code)})
    good = [n for n in names if n.lower().startswith("good")]
    bad = [n for n in names if n.lower().startswith("bad")]
    if rng.random() < 0.5:
        good_prefix, bad_prefix = "funcA", "funcB"
    else:
        good_prefix, bad_prefix = "funcB", "funcA"
    mapping = {}
    for i, n in enumerate(good, 1):
        mapping[n.lower()] = f"{good_prefix}{i}"
    for i, n in enumerate(bad, 1):
        mapping[n.lower()] = f"{bad_prefix}{i}"

    def sub(m):
        return mapping[m.group(0).lower()]

    code = VERDICT_WORD_RE.sub(sub, code)

    def strip_leak(m):
        return "" if LEAK_COMMENT_RE.search(m.group(0)) else m.group(0)

    return COMMENT_RE.sub(strip_leak, code)


def class_decl(src):
    m = re.search(r"^[ \t]*(?:public\s+)?(?:final\s+|abstract\s+)?class\s+\w+[^{]*\{",
                  src, re.M)
    return m.group(0).strip() if m else ""


def build_window(src, finding_line, rng, juliet):
    ranges = method_ranges(src)
    hit = enclosing_method(ranges, finding_line)
    if not hit:
        return None
    name, start_line, end_line, _, _ = hit
    lines = src.splitlines()
    body = "\n".join(lines[start_line - 1:end_line])
    imports = "\n".join(
        line for line in lines if line.strip().startswith(("package ", "import "))
    )
    window = "\n\n".join(x for x in (imports, class_decl(src), body) if x)
    if juliet:
        window = neutralize(window, rng)
    return name, window


def rule_cwes(meta):
    raw = meta.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    out = set()
    for item in raw:
        m = re.search(r"CWE-(\d+)", item)
        if m:
            out.add(f"CWE-{m.group(1)}")
    return out


def reason_fix(rule, cwes, label, message):
    vuln = rule.split(".")[-1].replace("-", " ")
    cwe = sorted(cwes)[0] if cwes else ""
    fix = FIXES.get(cwe, GENERIC_FIX)
    if label == "TP":
        why = re.split(r"(?<=[.!?])\s", (message or "").strip())[0][:220]
        why = why or f"The {vuln} pattern is reached by untrusted input without validation."
    else:
        why = (f"The rule matched the {vuln} pattern, but the flagged value is "
               f"not attacker-controlled or is validated before the sink.")
    return why, fix


def load_owasp_expected():
    path = BENCH / "owasp" / "expectedresults-1.2.csv"
    rows = {}
    for r in csv.DictReader(path.open(encoding="utf-8")):
        name = r["# test name"].strip()
        rows[name] = {
            "category": r[" category"].strip(),
            "cwe": f"CWE-{r[' cwe'].strip()}",
            "vulnerable": r[" real vulnerability"].strip() == "true",
        }
    return rows


def frozen_juliet_files():
    path = ROOT / "model-evaluation" / "juliet-heldout-1000-neutral.csv"
    if not path.exists():
        return set()
    names = set()
    for r in csv.DictReader(path.open(encoding="utf-8")):
        names.add(Path(r["source"].replace("\\", "/")).name)
    return names


def juliet_cwe(path):
    m = re.search(r"CWE(\d+)_", path.name)
    return f"CWE-{m.group(1)}" if m else None


def load_scan(path):
    p = Path(path)
    if p.is_dir():
        results = []
        for f in sorted(p.glob("*.json")):
            results.extend(json.loads(f.read_text()).get("results", []))
        return {"results": results}
    return json.loads(p.read_text())


def build(scan_path, suite, out, test_families, val_families, seed=1611):
    scan = load_scan(scan_path)
    expected = load_owasp_expected() if suite == "owasp" else None
    frozen = frozen_juliet_files() if suite == "juliet" else set()
    rng = random.Random(seed)
    rows, stats = [], Counter()
    seen = set()
    for f in scan["results"]:
        path = Path(f["path"])
        if suite == "owasp":
            test = expected.get(path.stem)
            if not test:
                stats["unknown file"] += 1
                continue
            truth_cwe, vulnerable = test["cwe"], test["vulnerable"]
        else:
            if path.name in frozen:
                stats["frozen heldout file"] += 1
                continue
            truth_cwe, vulnerable = juliet_cwe(path), None
            if not truth_cwe:
                stats["no cwe in path"] += 1
                continue
        cwes = rule_cwes(f["extra"].get("metadata", {}))
        if not cwes:
            stats["rule without cwe"] += 1
            continue
        if truth_cwe not in cwes:
            stats["category mismatch"] += 1
            continue
        line = f["start"]["line"]
        key = (str(path), line, f["check_id"])
        if key in seen:
            stats["duplicate finding"] += 1
            continue
        seen.add(key)
        src = (BENCH / suite / path).read_text(encoding="utf-8", errors="replace")
        got = build_window(src, line, rng, juliet=(suite == "juliet"))
        if not got:
            stats["no enclosing method"] += 1
            continue
        method, window = got
        if suite == "juliet":
            low = method.lower()
            if low.startswith("bad"):
                label = "TP"
            elif low.startswith("good"):
                label = "FP"
            else:
                stats["method not labelled"] += 1
                continue
        else:
            label = "TP" if vulnerable else "FP"
        why, fix = reason_fix(f["check_id"], cwes, label, f["extra"].get("message", ""))
        family = truth_cwe
        rows.append({
            "id": f"{suite}:{path.stem}:{line}:{f['check_id']}",
            "suite": suite,
            "rule": f["check_id"],
            "cwe": family,
            "file": str(path),
            "line": line,
            "label": label,
            "code_window": window,
            "sink_line": src.splitlines()[line - 1].strip()[:300],
            "reason": why,
            "fix": fix,
            "family": family,
            "split": ("test" if family in test_families else
                      "val" if family in val_families else "train"),
        })
        stats[label] += 1

    # Leak check: identical normalized windows must not straddle train/test.
    hashes = defaultdict(set)
    for r in rows:
        h = hashlib.sha256(re.sub(r"\s+", "", r["code_window"]).encode()).hexdigest()
        r["code_hash"] = h
        hashes[h].add(r["split"])
    leaks = {h for h, s in hashes.items() if "train" in s and "test" in s}
    if leaks:
        rows = [r for r in rows if r["code_hash"] not in leaks]
        stats["cross-split leak dropped"] += len(leaks)

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    stats["rows"] = len(rows)
    stats["train"] = sum(r["split"] == "train" for r in rows)
    stats["val"] = sum(r["split"] == "val" for r in rows)
    stats["test"] = sum(r["split"] == "test" for r in rows)
    stats["families train"] = len({r["family"] for r in rows if r["split"] == "train"})
    stats["families test"] = len({r["family"] for r in rows if r["split"] == "test"})
    return rows, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owasp-scan", default=str(DATA / "scans" / "owasp.json"))
    ap.add_argument("--juliet-scan", default=str(DATA / "scans" / "juliet.json"))
    ap.add_argument("--out", default=str(DATA / "triage"))
    ap.add_argument("--test-families", default=",".join(sorted(TEST_FAMILIES)))
    ap.add_argument("--val-families", default=",".join(sorted(VAL_FAMILIES)))
    args = ap.parse_args()
    out = Path(args.out)
    test = set(args.test_families.split(","))
    val = set(args.val_families.split(","))
    all_rows = []
    for suite, scan in (("owasp", args.owasp_scan), ("juliet", args.juliet_scan)):
        if not Path(scan).exists():
            print(f"{suite}: scan missing at {scan}, skipped")
            continue
        rows, stats = build(scan, suite, out / f"{suite}.jsonl", test, val)
        print(f"{suite}: {dict(stats)}")
        all_rows += rows
    with (out / "triage_all.jsonl").open("w", encoding="utf-8") as fh:
        for r in all_rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    by_split = defaultdict(list)
    for r in all_rows:
        by_split[r["split"]].append(r)
    for split, rows in by_split.items():
        with (out / f"triage_{split}.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{split}: {len(rows)} rows, labels {dict(Counter(r['label'] for r in rows))}, "
              f"families {dict(Counter(r['family'] for r in rows).most_common())}")
    # Fixed 200-row stratified sample for the paid/untrained baselines.
    test = by_split["test"]
    rng = random.Random(1611)
    tp = [r for r in test if r["label"] == "TP"]
    fp = [r for r in test if r["label"] == "FP"]
    sample = rng.sample(tp, min(100, len(tp))) + rng.sample(fp, min(100, len(fp)))
    rng.shuffle(sample)
    with (out / "triage_sample200.jsonl").open("w", encoding="utf-8") as fh:
        for r in sample:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"sample200: {len(sample)} rows")


if __name__ == "__main__":
    main()
