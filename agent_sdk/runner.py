"""Minimal agent runner for attack/defense containers.

The coordinator starts this module from the agent Docker image. For defense
runs, it clones the target service repo, exposes it as `SERVICE_REPO_PATH`, and
then executes `defense_agent.main:main`.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SDK_DIR = Path(__file__).resolve().parent


def _auth_header() -> str | None:
    team_id = os.getenv("TEAM_ID", "")
    team_token = os.getenv("TEAM_TOKEN", "")
    if team_id and team_token:
        raw = f"{team_id}:{team_token}".encode("utf-8")
        return "Authorization: Basic " + base64.b64encode(raw).decode("ascii")

    run_token = os.getenv("AGENT_RUN_TOKEN", "")
    if run_token:
        return f"Authorization: Bearer {run_token}"
    return None


def _run(args: list[str], *, cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, text=True, check=check)


def _git_authed(*args: str, cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess:
    header = _auth_header()
    cmd = ["git"]
    if header:
        cmd.extend(["-c", f"http.extraHeader={header}"])
    cmd.extend(args)
    return _run(cmd, cwd=cwd, check=check)


def _clone_target_repo() -> Path:
    existing = os.getenv("SERVICE_REPO_PATH", "")
    if existing and Path(existing).exists():
        return Path(existing).resolve()

    target_url = os.getenv("TARGET_REPO_URL", "")
    if not target_url:
        return ROOT

    workdir = Path(tempfile.mkdtemp(prefix="hspace-target-repo-")) / "repo"
    _git_authed("clone", "--branch", "main", "--single-branch", target_url, str(workdir))
    _run(["git", "config", "user.email", "hspace-defense-agent@example.invalid"], cwd=workdir)
    _run(["git", "config", "user.name", "HSPACE Defense Agent"], cwd=workdir)
    return workdir


def _entrypoint() -> str:
    mode = os.getenv("MODE", "defense").lower()
    override = os.getenv(f"{mode.upper()}_AGENT_ENTRYPOINT", "")
    if override:
        return override
    if mode == "attack":
        return "attack_agent.main:main"
    return "defense_agent.main:main"


def _run_entrypoint(spec: str) -> None:
    if ":" in spec:
        module_name, func_name = spec.split(":", 1)
    else:
        module_name, func_name = spec, "main"
    module = importlib.import_module(module_name)
    func = getattr(module, func_name)
    func()


def _finish(status: str, error: str = "") -> None:
    base_url = os.getenv("HSPACE_AGENT_BASE_URL", "").rstrip("/")
    run_token = os.getenv("AGENT_RUN_TOKEN", "")
    if not base_url or not run_token:
        return
    body = json.dumps({"status": status, "error": error[:500]}).encode("utf-8")
    req = urllib.request.Request(
        base_url + "/finish",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {run_token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:
        print(f"[agent_sdk.runner] finish 전송 실패: {exc}", file=sys.stderr)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(SDK_DIR))

    spec = _entrypoint()
    if "--print-plan" in sys.argv:
        print(f"mode={os.getenv('MODE', 'defense')}")
        print(f"entrypoint={spec}")
        print(f"target_repo_url={'set' if os.getenv('TARGET_REPO_URL') else 'unset'}")
        return 0

    try:
        if os.getenv("MODE", "defense").lower() == "defense":
            service_repo = _clone_target_repo()
            os.environ["SERVICE_REPO_PATH"] = str(service_repo)
            print(f"[agent_sdk.runner] SERVICE_REPO_PATH={service_repo}")
        _run_entrypoint(spec)
    except Exception as exc:
        _finish("failed", str(exc))
        raise

    _finish("completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
