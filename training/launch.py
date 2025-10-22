"""Launch a local Python script on the Kaggle runner, wait, download outputs."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runner import Runner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--title", required=True)
    ap.add_argument("--accelerator", default="nvidia-tesla-t4")
    ap.add_argument("--timeout", type=int, default=43200)
    ap.add_argument("--account", default="")
    ap.add_argument("--dest", default="")
    ap.add_argument("--args", default="", help="extra CLI args for the remote script")
    ap.add_argument("--no-wait", action="store_true")
    args = ap.parse_args()
    r = Runner()
    r.cleanup()  # free the server's output/log/notebook cache before a new push
    code = Path(args.script).read_text(encoding="utf-8")
    if args.args:
        import shlex
        argv = [Path(args.script).name] + shlex.split(args.args)
        code = f"import sys\nsys.argv = {json.dumps(argv)}\n" + code
    res = r.launch(args.title, code, accelerator=args.accelerator,
                   timeout=args.timeout, account=args.account or None)
    print(json.dumps(res, indent=2)[:2000])
    run = res.get("run") or res
    run_id = run.get("run_id") or run.get("id")
    if not run_id:
        sys.exit("no run id in launch response")
    if args.no_wait:
        print(f"run_id={run_id}")
        return
    state = r.wait(run_id)
    print("final:", state.get("status"))
    print(r.logs(run_id)[-8000:])
    if args.dest:
        r.download_all(run_id, Path(args.dest))
        print(f"downloaded to {args.dest}")
        r.cleanup()


if __name__ == "__main__":
    main()
