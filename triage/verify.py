"""Phase 4 checker: does a patch compile, kill the warning, and add no new ones?

Usage:
  python -m triage.verify --project . --file src/Foo.java \
      --rule java.lang.security.audit.sqli.jdbc-sqli --mode maven

The patched file must already be in place. `--mode javac` takes a classpath.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

RULES = ["--config", "p/default", "--config", "p/security-audit",
         "--config", "p/owasp-top-ten"]


def compile_maven(project):
    p = subprocess.run(["mvn", "-q", "-o", "test-compile"], cwd=project,
                       capture_output=True, text=True)
    return p.returncode == 0, (p.stdout + p.stderr)[-2000:]


def compile_javac(files, classpath):
    cmd = ["javac", "-cp", classpath, *files]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode == 0, (p.stdout + p.stderr)[-2000:]


def scan(path):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "f.json"
        subprocess.run(["semgrep", *RULES, "--json", "--quiet", "--metrics", "off",
                        "-o", str(out), str(path)], check=False)
        data = json.loads(out.read_text()) if out.exists() else {"results": []}
    return [r["check_id"] for r in data.get("results", [])]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--file", required=True, help="patched file, relative to project")
    ap.add_argument("--original", default="", help="unpatched copy, relative to project")
    ap.add_argument("--rule", required=True, help="the warning the patch should remove")
    ap.add_argument("--mode", choices=["maven", "javac"], default="maven")
    ap.add_argument("--classpath", default="")
    args = ap.parse_args()
    project = Path(args.project).resolve()
    target = project / args.file
    if not target.exists():
        sys.exit(f"no such file: {target}")

    if args.mode == "maven":
        ok, log = compile_maven(project)
    else:
        ok, log = compile_javac([str(target)], args.classpath)
    after = set(scan(target))
    before = set(scan(project / args.original)) if args.original else {args.rule}
    result = {
        "compiles": ok,
        "compile_log": log if not ok else "",
        "rule_before": args.rule in before,
        "rule_after": args.rule in after,
        "new_rules": sorted(after - before - {args.rule}),
        "ok": bool(ok and args.rule in before and args.rule not in after
                   and not (after - before - {args.rule})),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
