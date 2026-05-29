"""Git helper used inside official agent runs.

The defense agent edits the checked-out target service repository, then calls
`commit_patch()`. This module commits those changes with the `Agent-Run-ID`
trailer required by the coordinator and pushes them back to the target repo.
"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path


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


def _run(repo: Path, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=repo,
        text=True,
        capture_output=True,
        check=check,
    )


def _run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return _run(repo, ["git", *args], check=check)


def _run_git_authed(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    header = _auth_header()
    cmd = ["git"]
    if header:
        cmd.extend(["-c", f"http.extraHeader={header}"])
    cmd.extend(args)
    return _run(repo, cmd, check=check)


def commit_patch(repo_path: str, message: str) -> bool:
    """Commit and push service repo changes made by the defense agent."""
    repo = Path(repo_path).resolve()
    if not (repo / ".git").exists():
        raise RuntimeError(f"not a git repository: {repo}")

    _run_git(repo, "config", "user.email", "hspace-defense-agent@example.invalid")
    _run_git(repo, "config", "user.name", "HSPACE Defense Agent")
    _run_git(repo, "add", "-A")

    staged = _run_git(repo, "diff", "--cached", "--quiet", check=False)
    if staged.returncode == 0:
        print("  [gitctf_sdk] 변경사항 없음")
        return True

    run_id = os.getenv("AGENT_RUN_ID", "")
    full_message = message
    if run_id and "Agent-Run-ID:" not in full_message:
        full_message += f"\n\nAgent-Run-ID: {run_id}"

    commit = _run_git(repo, "commit", "-m", full_message, check=False)
    if commit.returncode != 0:
        raise RuntimeError(f"git commit failed: {commit.stderr or commit.stdout}")

    push = _run_git_authed(repo, "push", "origin", "HEAD:main", check=False)
    if push.returncode != 0:
        raise RuntimeError(f"git push failed: {push.stderr or push.stdout}")

    print("  [gitctf_sdk] commit & push 완료")
    return True

