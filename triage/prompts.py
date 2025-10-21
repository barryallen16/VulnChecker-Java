"""Prompt format and output parsing shared by baselines, training and the CLI."""
import re

SYSTEM = (
    "You are a Java security reviewer. You triage static analysis warnings. "
    "Answer in exactly three lines and nothing else."
)
INSTRUCTIONS = (
    "Decide whether this warning is a true positive (a real exploitable bug) "
    "or a false positive (noise). Then give a one-sentence reason and a "
    "one-sentence fix.\n\n"
    "VERDICT: TP or FP\nWHY: one sentence\nFIX: one sentence"
)
MAX_CHARS = 18000


def user_prompt(row):
    window = row["code_window"]
    if len(window) > MAX_CHARS:
        window = window[:MAX_CHARS] + "\n// ... truncated ..."
    return (
        f"RULE: {row['rule']}\n"
        f"CWE: {row['cwe']}\n"
        f"FILE: {row['file'].split('/')[-1]}\n"
        f"CODE:\n```java\n{window}\n```\n\n"
        f"{INSTRUCTIONS}"
    )


def target(row):
    return f"VERDICT: {row['label']}\nWHY: {row['reason']}\nFIX: {row['fix']}"


VERDICT_RE = re.compile(r"VERDICT:\s*(TP|FP)", re.I)
WHY_RE = re.compile(r"WHY:\s*(.+)", re.I)
FIX_RE = re.compile(r"FIX:\s*(.+)", re.I)


def parse(text):
    v = VERDICT_RE.search(text or "")
    w = WHY_RE.search(text or "")
    f = FIX_RE.search(text or "")
    return {
        "verdict": v.group(1).upper() if v else None,
        "why": w.group(1).strip() if w else "",
        "fix": f.group(1).strip() if f else "",
    }


def to_messages(row, shots=()):
    messages = [{"role": "system", "content": SYSTEM}]
    for s in shots:
        messages.append({"role": "user", "content": user_prompt(s)})
        messages.append({"role": "assistant", "content": target(s)})
    messages.append({"role": "user", "content": user_prompt(row)})
    return messages
