"""
Small SDK used by team attack/defense agents.

The SDK owns coordinator provenance fields: agent run creation, run id reuse,
LLM gateway calls, PoC upload metadata, and defense commit trailers.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import subprocess
import tarfile
import base64
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

SDK_NAME = "hspace-agent-sdk/1"


class AgentSDKError(RuntimeError):
    pass


@dataclass
class AgentContext:
    coordinator_url: str
    team_id: str
    team_token: str
    mode: str
    target_team: str
    round_num: int
    agent_run_id: str
    agent_run_token: str
    allowed_models: list[str]

    @classmethod
    def from_env(cls) -> "AgentContext":
        coordinator_url = os.environ["COORDINATOR_URL"].rstrip("/")
        team_id = os.environ.get("TEAM_ID") or os.environ.get("ATTACKER_TEAM")
        if not team_id:
            raise AgentSDKError("TEAM_ID env is required")
        team_token = os.environ["TEAM_TOKEN"]
        mode = os.environ.get("MODE", "attack")
        target_team = os.environ["TARGET_TEAM"]
        round_num = int(os.environ["ROUND"])

        existing_run = os.environ.get("AGENT_RUN_ID")
        if existing_run:
            existing_token = os.environ.get("AGENT_RUN_TOKEN")
            if not existing_token:
                raise AgentSDKError("AGENT_RUN_TOKEN env is required when AGENT_RUN_ID is set")
            return cls(
                coordinator_url=coordinator_url,
                team_id=team_id,
                team_token=team_token,
                mode=mode,
                target_team=target_team,
                round_num=round_num,
                agent_run_id=existing_run,
                agent_run_token=existing_token,
                allowed_models=[],
            )

        headers = {"X-Team-Token": team_token, "X-Agent-SDK": SDK_NAME}
        runner_secret = os.environ.get("RUNNER_SECRET")
        if runner_secret:
            headers["X-Runner-Secret"] = runner_secret

        resp = httpx.post(
            f"{coordinator_url}/agent-runs",
            headers=headers,
            json={
                "team_id": team_id,
                "mode": mode,
                "target_team": target_team,
                "round_num": round_num,
                "agent_image": os.environ.get("AGENT_IMAGE"),
                "agent_image_digest": os.environ.get("AGENT_IMAGE_DIGEST"),
                "agent_commit": os.environ.get("AGENT_COMMIT"),
            },
            timeout=15.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/agent-runs failed: HTTP {resp.status_code} {resp.text[:300]}")
        data = resp.json()
        return cls(
            coordinator_url=coordinator_url,
            team_id=team_id,
            team_token=team_token,
            mode=mode,
            target_team=target_team,
            round_num=round_num,
            agent_run_id=data["agent_run_id"],
            agent_run_token=data["agent_run_token"],
            allowed_models=data.get("allowed_models", []),
        )

    def _headers(self, method: str, path: str) -> dict[str, str]:
        timestamp = str(int(time.time()))
        token_hash = hashlib.sha256(self.agent_run_token.encode("utf-8")).hexdigest()
        payload = "\n".join([method.upper(), path, self.agent_run_id, timestamp]).encode("utf-8")
        signature = hmac.new(token_hash.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return {
            "X-Team-Token": self.team_token,
            "X-Agent-Run-Token": self.agent_run_token,
            "X-Agent-SDK": SDK_NAME,
            "X-Agent-SDK-Timestamp": timestamp,
            "X-Agent-SDK-Signature": signature,
        }

    def finish(self, status: str = "completed", error: str = "") -> None:
        path = f"/agent-runs/{self.agent_run_id}/finish"
        resp = httpx.post(
            f"{self.coordinator_url}{path}",
            headers=self._headers("POST", path),
            json={"status": status, "error": error},
            timeout=10.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"finish failed: HTTP {resp.status_code} {resp.text[:300]}")

    def llm(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        purpose: str = "general",
    ) -> dict:
        path = "/llm"
        resp = httpx.post(
            f"{self.coordinator_url}{path}",
            headers=self._headers("POST", path),
            json={
                "agent_run_id": self.agent_run_id,
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "purpose": purpose,
            },
            timeout=75.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/llm failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def attack(
        self,
        payload: str,
        llm_call_id: int,
        target_team: Optional[str] = None,
        session_id: Optional[str] = None,
        history: Optional[list[dict[str, Any]]] = None,
        path: Optional[str] = None,
        method: str = "POST",
        json_body: Any = None,
        query: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
    ) -> dict:
        target = target_team or self.target_team
        url_path = "/attack"
        resp = httpx.post(
            f"{self.coordinator_url}{url_path}",
            headers=self._headers("POST", url_path),
            json={
                "agent_run_id": self.agent_run_id,
                "llm_call_id": llm_call_id,
                "attacker_team": self.team_id,
                "target_team": target,
                "payload": payload,
                "session_id": session_id,
                "history": history,
                "path": path,
                "method": method,
                "json_body": json_body,
                "query": query,
                "headers": headers,
                "data": data,
            },
            timeout=40.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/attack failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def request_target(
        self,
        path: str,
        llm_call_id: int,
        method: str = "GET",
        json_body: Any = None,
        query: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        target_team: Optional[str] = None,
    ) -> dict:
        """Send an arbitrary HTTP probe to the assigned target service through coordinator."""
        return self.attack(
            payload="",
            llm_call_id=llm_call_id,
            target_team=target_team,
            path=path,
            method=method,
            json_body=json_body,
            query=query,
            headers=headers,
            data=data,
        )

    def fetch_target_repo(self, dest: str | Path = "target_repo") -> dict:
        if self.mode != "attack":
            raise AgentSDKError("fetch_target_repo is only available in attack mode")

        path = f"/agent-runs/{self.agent_run_id}/target-repo.tar"
        resp = httpx.get(
            f"{self.coordinator_url}{path}",
            headers=self._headers("GET", path),
            timeout=30.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/target-repo.tar failed: HTTP {resp.status_code} {resp.text[:300]}")

        repo_team = resp.headers.get("X-Repo-Team") or self.target_team
        commit = resp.headers.get("X-Repo-Commit") or ""
        dest_root = (Path(dest) / self.agent_run_id).resolve()
        dest_root.mkdir(parents=True, exist_ok=True)

        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:*") as archive:
            for member in archive.getmembers():
                member_path = (dest_root / member.name).resolve()
                try:
                    member_path.relative_to(dest_root)
                except ValueError as exc:
                    raise AgentSDKError(f"unsafe repo archive path: {member.name}") from exc

                if member.isdir():
                    member_path.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue

                member_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                member_path.write_bytes(extracted.read())

        return {
            "path": str(dest_root / repo_team),
            "team": repo_team,
            "commit": commit,
        }

    def clone_target_repo(
        self,
        dest: str | Path = "target_repo",
        repo_url: Optional[str] = None,
    ) -> dict:
        """Clone the assigned target repo through coordinator git HTTP."""
        target = self.target_team
        url = repo_url or os.environ.get("TARGET_REPO_URL") or f"{self.coordinator_url}/git/{target}"
        dest_path = Path(dest).resolve()
        if dest_path.exists() and any(dest_path.iterdir()):
            raise AgentSDKError(f"destination is not empty: {dest_path}")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        raw = f"{self.team_id}:{self.team_token}".encode("utf-8")
        header = "Authorization: Basic " + base64.b64encode(raw).decode("ascii")
        result = subprocess.run(
            ["git", "-c", f"http.extraHeader={header}", "clone", "--depth", "1", url, str(dest_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AgentSDKError(f"git clone failed: {result.stderr[-500:]}")
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=dest_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return {"path": str(dest_path), "team": target, "commit": commit, "url": url}

    def submit_poc(
        self,
        path: str | Path,
        llm_call_id: int,
        target_team: Optional[str] = None,
        flag_id: str = "vuln1",
    ) -> dict:
        poc_path = Path(path)
        data = poc_path.read_bytes()
        return self._submit_poc_bytes(
            data,
            file_name=poc_path.name,
            llm_call_id=llm_call_id,
            target_team=target_team,
            flag_id=flag_id,
        )

    def submit_poc_source(
        self,
        source: str,
        llm_call_id: int,
        target_team: Optional[str] = None,
        flag_id: str = "vuln1",
        file_name: str = "poc.py",
    ) -> dict:
        """Submit an agent-generated PoC without requiring a local poc*.py file."""
        return self._submit_poc_bytes(
            source.encode("utf-8"),
            file_name=file_name,
            llm_call_id=llm_call_id,
            target_team=target_team,
            flag_id=flag_id,
        )

    def _submit_poc_bytes(
        self,
        data: bytes,
        *,
        file_name: str,
        llm_call_id: int,
        target_team: Optional[str],
        flag_id: str,
    ) -> dict:
        sha256 = hashlib.sha256(data).hexdigest()
        target = target_team or self.target_team
        url_path = "/pocs"
        resp = httpx.post(
            f"{self.coordinator_url}{url_path}",
            headers=self._headers("POST", url_path),
            data={
                "agent_run_id": self.agent_run_id,
                "llm_call_id": str(llm_call_id),
                "attacker_team": self.team_id,
                "target_team": target,
                "flag_id": flag_id,
                "sha256": sha256,
            },
            files={"file": (file_name, data, "text/x-python")},
            timeout=30.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/pocs failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def commit_patch(self, message: str, repo_dir: str | Path = ".") -> str:
        if self.mode != "defense":
            raise AgentSDKError("commit_patch is only available in defense mode")
        repo = Path(repo_dir)
        full_message = f"{message.rstrip()}\n\nAgent-Run-ID: {self.agent_run_id}"
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo)
        if staged.returncode == 0:
            raise AgentSDKError("no staged defense patch changes to commit")
        subprocess.run(["git", "commit", "-m", full_message], cwd=repo, check=True)
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def push_repo(
        self,
        repo_dir: str | Path = ".",
        repo_team: Optional[str] = None,
        remote_url: Optional[str] = None,
        branch: str = "main",
    ) -> None:
        """Push current HEAD with a temporary Basic Auth header."""
        repo = Path(repo_dir)
        target = repo_team or self.target_team
        url = remote_url or os.environ.get("TARGET_REPO_URL") or f"{self.coordinator_url}/git/{target}"
        raw = f"{self.team_id}:{self.team_token}".encode("utf-8")
        header = "Authorization: Basic " + base64.b64encode(raw).decode("ascii")
        result = subprocess.run(
            ["git", "-c", f"http.extraHeader={header}", "push", url, f"HEAD:{branch}"],
            cwd=repo,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AgentSDKError(f"git push failed: {result.stderr[-800:]}")


def write_json(path: str | Path, data: object) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
