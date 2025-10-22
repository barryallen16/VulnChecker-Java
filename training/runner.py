"""Thin client for the hosted kaggle-automation runner.

The service authenticates with a shared secret and a signed cookie, not a
bearer token. Launch code as a plain .py string; the service wraps it.
"""
import io
import os
import time
import zipfile
from pathlib import Path

import requests

DEFAULT_URL = "https://kabila-aws.isroot.in"


def _retry(fn, attempts=5):
    """Retry a call that failed with a network error or a non-JSON response."""
    for i in range(attempts):
        try:
            return fn()
        except (requests.RequestException, ValueError) as e:
            if i == attempts - 1:
                raise
            delay = 2 ** (i + 1)
            print(f"runner: {type(e).__name__}: {e}; retry in {delay}s", flush=True)
            time.sleep(delay)


def _token():
    value = os.environ.get("KAGGLE_RUNNER_TOKEN", "").strip()
    if not value:
        raise RuntimeError("set KAGGLE_RUNNER_TOKEN (see .env)")
    return value


class Runner:
    def __init__(self, url=DEFAULT_URL, token=None):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        def login():
            r = self.session.post(
                f"{self.url}/login",
                data={"access_token": token or _token()},
                allow_redirects=False,
                timeout=30,
            )
            if r.status_code not in (303, 200):
                raise requests.HTTPError(f"login failed: {r.status_code}")
            return r

        _retry(login)

    def accounts(self):
        return _retry(
            lambda: self.session.get(f"{self.url}/api/accounts", timeout=30).json()["accounts"]
        )

    def launch(self, title, code, accelerator="nvidia-tesla-t4-x2", timeout=43200,
               env=None, is_trial=False, account=None):
        account = account or self._pick_account(accelerator)
        payload = {
            "account_username": account,
            "title": title,
            "code_content": code,
            "filename": title.replace(" ", "_") + ".py",
            "accelerator": accelerator,
            "enable_internet": True,
            "is_trial": is_trial,
            "timeout_seconds": timeout,
            "env_vars": env or {},
        }
        data = _retry(
            lambda: self.session.post(
                f"{self.url}/api/runs/launch-json", json=payload, timeout=180
            ).json()
        )
        if not data.get("success", True) or data.get("status") in ("error", "session_cap"):
            raise RuntimeError(f"launch failed: {data}")
        return data

    def _pick_account(self, accelerator):
        # The service's own kaggle_* accounts are off limits for our runs.
        accounts = [a for a in self.accounts()
                    if not a["username"].startswith("kaggle_")]
        if not accounts:
            raise RuntimeError("no kaggle accounts configured")
        if accelerator == "none":
            return accounts[0]["username"]
        for a in accounts:
            if not a.get("active_runs"):
                return a["username"]
        return accounts[0]["username"]

    def status(self, run_id):
        return _retry(
            lambda: self.session.get(
                f"{self.url}/api/runs/{run_id}/refresh-status", timeout=60
            ).json()
        )

    def wait(self, run_id, poll=60, timeout=12 * 3600):
        start = time.time()
        while time.time() - start < timeout:
            st = self.status(run_id)
            state = st.get("status", "unknown")
            print(f"[{int(time.time() - start)}s] {state}", flush=True)
            if state in ("complete", "error", "stopped", "canceled", "failed"):
                return st
            time.sleep(poll)
        raise TimeoutError(f"run {run_id} still going after {timeout}s")

    def logs(self, run_id, remote=True):
        return _retry(
            lambda: self.session.get(
                f"{self.url}/api/runs/{run_id}/logs",
                params={"fetch_remote": str(remote).lower()},
                timeout=120,
            ).text
        )

    def files(self, run_id):
        return _retry(
            lambda: self.session.get(f"{self.url}/api/runs/{run_id}/files", timeout=60).json()
        )

    def pull(self, run_id):
        return _retry(
            lambda: self.session.post(
                f"{self.url}/api/runs/{run_id}/files/pull", timeout=600
            ).json()
        )

    def download_all(self, run_id, dest):
        """Pull outputs from Kaggle and extract them under dest."""
        self.pull(run_id)

        def fetch():
            r = self.session.get(
                f"{self.url}/api/runs/{run_id}/files/download-zip", timeout=1800
            )
            r.raise_for_status()
            return r.content

        content = _retry(fetch)
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            z.extractall(dest)
        return dest

    def download_file(self, run_id, filename, dest):
        """Fetch one output file, pulling the run's outputs first if needed."""
        def fetch():
            r = self.session.get(
                f"{self.url}/api/runs/{run_id}/files/download/{filename}",
                timeout=1800)
            r.raise_for_status()
            return r.content

        content = _retry(fetch)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        return dest

    def cleanup(self):
        """Drop cached outputs, logs and notebook payloads from the server."""
        for path in ("/api/runs/files/clear-all",
                     "/api/runs/files/clear-all-notebooks"):
            try:
                print(_retry(lambda: self.session.delete(
                    self.url + path, timeout=120).json())["message"], flush=True)
            except (requests.RequestException, ValueError) as e:
                print(f"cleanup skipped: {e}", flush=True)
