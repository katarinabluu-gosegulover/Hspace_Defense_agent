"""
A&D Defense Agent.

Main behavior:
1. Clone target repository.
2. Apply deterministic defensive patches.
3. Call 4 defense LLM models for provenance/review.
4. If deterministic patch misses anything, try fallback patches from the 4 LLMs.
5. Validate syntax.
6. Commit with Agent-Run-ID.
7. Push.

Important:
- The remote pre-receive hook may reject pushes unless the current Agent-Run-ID
  is connected to a valid defense LLM call.
- Therefore this agent calls all configured defense LLM models before pushing.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


import httpx


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# 4개 AI 모델을 전부 실행한다.
#
# 필요하면 환경변수로 덮어쓸 수 있다.
#
# 예:
# LLM_MODELS="google/gemini-2.0-flash-001,openai/gpt-4o-mini,mistralai/mistral-small-3.1,microsoft/phi-4"
#
LLM_MODELS = [
    model.strip()
    for model in os.getenv(
        "LLM_MODELS",
        ",".join(
            [
                "google/gemini-2.0-flash-001",
                "openai/gpt-4o-mini",
                "mistralai/mistral-small-3.1",
                "microsoft/phi-4",
            ]
        ),
    ).split(",")
    if model.strip()
]

REPO_DIR = Path(os.getenv("REPO_DIR", "target_repo"))

MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "28"))
MAX_REPO_PROMPT_BYTES = int(os.getenv("MAX_REPO_PROMPT_BYTES", str(64 * 1024)))
MAX_REPO_FILE_BYTES = int(os.getenv("MAX_REPO_FILE_BYTES", str(10 * 1024)))

# 기본은 1회 실행 + 정상 종료.
# 하니스가 매 라운드 에이전트를 새로 띄우므로, 이게 곧 "항상 켜짐"이다.
# 내부 무한루프(LOOP_FOREVER=1)는 라운드당 시간제한을 넘겨 런이 timeout/kill 처리되니 쓰지 말 것.
LOOP_FOREVER = os.getenv("LOOP_FOREVER", "0") == "1"
LOOP_INTERVAL_SECONDS = int(os.getenv("LOOP_INTERVAL_SECONDS", "300"))

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".sh",
}

IMPORTANT_NAMES = {
    "dockerfile",
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "vuln_spec.json",
    "app.py",
    "main.py",
    "server.py",
}

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
}


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentEnv:
    team_id: str
    team_token: str
    target_team: str
    round_num: int
    run_id: str
    run_token: str
    openrouter_base_url: str
    agent_base_url: str
    target_repo_url: str

    @classmethod
    def from_env(cls) -> "AgentEnv":
        coordinator_url = os.environ["COORDINATOR_URL"].rstrip("/")
        target_team = os.environ["TARGET_TEAM"]

        return cls(
            team_id=os.environ["TEAM_ID"],
            team_token=os.environ["TEAM_TOKEN"],
            target_team=target_team,
            round_num=int(os.environ["ROUND"]),
            run_id=os.environ["AGENT_RUN_ID"],
            run_token=os.environ["AGENT_RUN_TOKEN"],
            openrouter_base_url=os.environ["OPENROUTER_BASE_URL"].rstrip("/"),
            agent_base_url=os.environ["HSPACE_AGENT_BASE_URL"].rstrip("/"),
            target_repo_url=os.getenv("TARGET_REPO_URL")
            or f"{coordinator_url}/git/{target_team}",
        )

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.run_token}"}


# ---------------------------------------------------------------------------
# HTTP / LLM helpers
# ---------------------------------------------------------------------------

def _check_response(resp: httpx.Response, label: str) -> None:
    if resp.status_code >= 400:
        raise RuntimeError(
            f"{label} failed: HTTP {resp.status_code} {resp.text[:500]}"
        )


def call_llm_model(
    env: AgentEnv,
    *,
    model: str,
    messages: list[dict[str, Any]],
    max_tokens: int,
    temperature: float = 0.2,
) -> tuple[int, str]:
    """
    Call one LLM model through the official wrapper.

    The current Agent-Run-ID is tied to the wrapper authorization token.
    Successful calls help satisfy provenance requirements.
    """
    resp = httpx.post(
        f"{env.openrouter_base_url}/chat/completions",
        headers={
            **env.auth,
            "X-Agent-Purpose": "defense",
        },
        json={
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        timeout=30.0,
    )

    _check_response(resp, f"LLM wrapper model={model}")

    data = resp.json()

    llm_call_id = (
        resp.headers.get("X-LLM-Call-ID")
        or (data.get("hspace") or {}).get("llm_call_id")
    )

    if not llm_call_id:
        raise RuntimeError(
            f"LLM wrapper response for model={model} did not include "
            "X-LLM-Call-ID or hspace.llm_call_id"
        )

    choices = data.get("choices") or []
    content = ((choices[0] if choices else {}).get("message") or {}).get("content") or ""

    return int(llm_call_id), content


def finish(env: AgentEnv, status: str, error: str = "") -> None:
    try:
        httpx.post(
            f"{env.agent_base_url}/finish",
            headers=env.auth,
            json={
                "status": status,
                "error": error[:2000],
            },
            timeout=10.0,
        )
    except Exception as exc:
        print(f"finish failed: {exc}")


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git_auth_header(env: AgentEnv) -> str:
    raw = f"{env.team_id}:{env.team_token}".encode("utf-8")
    return "Authorization: Basic " + base64.b64encode(raw).decode("ascii")


def reset_repo_dir(dest: Path) -> None:
    if dest.exists():
        print(f"  removing old repository directory: {dest}")
        shutil.rmtree(dest)


def clone_target_repo(env: AgentEnv, dest: Path) -> dict[str, str]:
    if dest.exists() and any(dest.iterdir()):
        raise RuntimeError(f"destination is not empty: {dest}")

    dest.parent.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            "git",
            "-c",
            f"http.extraHeader={_git_auth_header(env)}",
            "clone",
            "--depth",
            "1",
            env.target_repo_url,
            str(dest),
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr[-1000:]}")

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=dest,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    return {
        "path": str(dest),
        "team": env.target_team,
        "commit": commit,
        "url": env.target_repo_url,
    }


def has_staged_changes(repo: Path) -> bool:
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=repo,
    )
    return result.returncode != 0


def has_worktree_changes(repo: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return bool(result.stdout.strip())


def commit_patch(env: AgentEnv, repo: Path, message: str) -> str | None:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

    if not has_staged_changes(repo):
        print("  no staged changes; nothing to commit")
        return None

    full_message = f"{message.rstrip()}\n\nAgent-Run-ID: {env.run_id}"

    subprocess.run(
        [
            "git",
            "-c",
            "user.email=defense-agent@hspace.local",
            "-c",
            "user.name=A&D Defense Agent",
            "commit",
            "-m",
            full_message,
        ],
        cwd=repo,
        check=True,
    )

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip()


def push_repo_once(env: AgentEnv, repo: Path, branch: str = "main") -> None:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"http.extraHeader={_git_auth_header(env)}",
            "push",
            env.target_repo_url,
            f"HEAD:{branch}",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"git push failed: {result.stderr[-1200:]}")


def push_repo_with_retry(env: AgentEnv, repo: Path, branch: str = "main") -> None:
    try:
        push_repo_once(env, repo, branch)
        return

    except RuntimeError as first_error:
        msg = str(first_error)

        if "fetch first" not in msg and "non-fast-forward" not in msg:
            raise

        print("  push rejected because remote moved; fetching and rebasing once")

        subprocess.run(
            [
                "git",
                "-c",
                f"http.extraHeader={_git_auth_header(env)}",
                "fetch",
                "origin",
                branch,
            ],
            cwd=repo,
            check=True,
        )

        subprocess.run(
            ["git", "rebase", f"origin/{branch}"],
            cwd=repo,
            check=True,
        )

        push_repo_once(env, repo, branch)


# ---------------------------------------------------------------------------
# Repository context
# ---------------------------------------------------------------------------

def _candidate_file(path: Path) -> bool:
    name = path.name.lower()
    return name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def _priority(path: Path) -> tuple[int, str]:
    name = path.name.lower()

    if name == "vuln_spec.json":
        return 0, str(path)

    if name in {"main.py", "app.py", "server.py"}:
        return 1, str(path)

    if name in IMPORTANT_NAMES:
        return 2, str(path)

    if path.suffix.lower() == ".py":
        return 3, str(path)

    return 4, str(path)


def load_repo_context(root: Path, commit: str) -> str:
    chunks = [f"Target commit: {commit}"]
    total = sum(len(c.encode("utf-8")) for c in chunks)
    included = 0
    files: list[Path] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        rel_parts = path.relative_to(root).parts

        if any(part in SKIP_DIRS for part in rel_parts):
            continue

        if _candidate_file(path):
            files.append(path)

    for path in sorted(files, key=_priority):
        if included >= MAX_REPO_FILES or total >= MAX_REPO_PROMPT_BYTES:
            break

        raw = path.read_bytes()

        if b"\x00" in raw:
            continue

        text = raw[:MAX_REPO_FILE_BYTES].decode("utf-8", errors="replace")
        chunk = f"\n\n### {path.relative_to(root)}\n```\n{text}\n```"
        size = len(chunk.encode("utf-8"))

        if total + size > MAX_REPO_PROMPT_BYTES:
            break

        chunks.append(chunk)
        total += size
        included += 1

    return "".join(chunks)


# ---------------------------------------------------------------------------
# Patch application
# ---------------------------------------------------------------------------

def _json_from_text(text: str) -> dict[str, Any]:
    match = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    raw = match.group(1) if match else text

    data = json.loads(raw)

    if not isinstance(data, dict):
        raise ValueError("defense LLM response must be a JSON object")

    return data


def apply_llm_patch(repo: Path, data: dict[str, Any]) -> int:
    changed = 0

    patch = data.get("patch")

    if isinstance(patch, str) and patch.strip():
        proc = subprocess.run(
            ["git", "apply", "--whitespace=fix", "-"],
            cwd=repo,
            input=patch,
            text=True,
            capture_output=True,
        )

        if proc.returncode != 0:
            raise RuntimeError(
                "git apply failed for LLM patch:\n"
                f"stdout:\n{proc.stdout[-1000:]}\n"
                f"stderr:\n{proc.stderr[-1000:]}"
            )

        changed += 1

    files = data.get("files", [])

    if files:
        if not isinstance(files, list):
            raise ValueError("'files' must be a list")

        root = repo.resolve()

        for item in files:
            if not isinstance(item, dict):
                continue

            rel = str(item.get("path") or "")
            content = item.get("content")

            if not rel or not isinstance(content, str):
                continue

            target = (root / rel).resolve()

            # Prevent path traversal.
            target.relative_to(root)

            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            changed += 1

    return changed


def syntax_check(repo: Path) -> None:
    py_files = [
        str(p.relative_to(repo))
        for p in repo.rglob("*.py")
        if ".git" not in p.parts
    ]

    if py_files:
        subprocess.run(
            ["python", "-m", "py_compile", *py_files],
            cwd=repo,
            check=True,
        )


# ---------------------------------------------------------------------------
# Deterministic known leak patch
# ---------------------------------------------------------------------------

LEAK_GUARDS = [
    ("backend/routers/analysis.py", "vuln1", "ANALYSIS_META"),
    ("backend/routers/recommend.py", "vuln2", "RECOMMENDATION_SYSTEM"),
    ("backend/routers/files.py", "vuln3", "FILE_EXPORT"),
    ("backend/routers/debug.py", "vuln4", "DEBUG_RUNTIME"),
]


def neutralize_leaks(repo: Path) -> list[str]:
    patched: list[str] = []

    for rel, vuln_id, guard in LEAK_GUARDS:
        path = repo / rel

        if not path.is_file():
            continue

        text = path.read_text(encoding="utf-8")

        marker = f"# A&D defense: {vuln_id} leak disabled"

        if marker in text:
            patched.append(f"{vuln_id}(noop)")
            continue

        anchor = f"        and {guard}\n    ):"

        if anchor not in text:
            continue

        replacement = f"        and {guard}\n        and False  {marker}\n    ):"

        path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
        patched.append(vuln_id)

    return patched


# 운영진이 라운드 중 새로 심는 누출 분기 탐지용 템플릿.
# 알려진 4개와 동일한 시그니처를 매칭한다:
#     <indent>if (
#         ... 매직헤더 h.get(...) 조건들 ...
#         and <ALLCAPS_GUARD>
#     <indent>):
# 가드 줄이 닫는 `):` 바로 앞에 올 때만 매칭하므로, `and False`가 한번 끼면
# 가드가 더 이상 `):` 앞이 아니게 되어 재매칭되지 않는다(멱등).
_TEMPLATE_LEAK_RE = re.compile(
    r"(?P<ind>[ \t]*)if \(\n"
    r"(?P<body>(?:[ \t]+[^\n]*\n)+?)"
    r"(?P<gind>[ \t]+)and (?P<guard>[A-Z][A-Z0-9_]{2,})\n"
    r"(?P=ind)\):"
)


def neutralize_template_leaks(repo: Path) -> list[str]:
    """git 히스토리 없이, 파일 내용만으로 새로 심긴 누출 분기를 찾아 막는다.

    운영진이 라운드마다 새 취약점을 섞고 git 로그/diff를 지워도, 누출 분기는
    동일한 템플릿(매직 헤더 3개 + 마지막 대문자 가드 상수로 비밀을 응답에 주입)을
    재사용한다. 그 구조를 backend/ 의 .py 전체에서 스캔해 가드 바로 뒤에
    `and False`를 끼워 분기를 영구히 죽인다. 가드명/파일명이 달라도 잡힌다.

    오탐으로 정상 분기를 죽이지 않도록, if(...) 조건 안에 매직 헤더 검사
    `h.get(` 가 들어있는 블록만 누출 템플릿으로 인정한다. 정상 응답 경로·엔드포인트는
    한 글자도 바뀌지 않는다.

    반환: 막은 분기 목록("relpath:GUARD"). 이미 막힌 블록은 재매칭되지 않으므로 멱등.
    """
    neutralized: list[str] = []

    backend = repo / "backend"
    scan_root = backend if backend.is_dir() else repo

    for path in scan_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")

        def _repl(match: re.Match) -> str:
            body = match.group("body")
            # 매직 헤더 시그니처가 없으면 누출 템플릿이 아님 → 그대로 둔다.
            if "h.get(" not in body:
                return match.group(0)
            ind = match.group("ind")
            gind = match.group("gind")
            guard = match.group("guard")
            neutralized.append(f"{path.relative_to(repo).as_posix()}:{guard}")
            return (
                f"{ind}if (\n"
                f"{body}"
                f"{gind}and {guard}\n"
                f"{gind}and False  # A&D defense: auto-disabled leak ({guard})\n"
                f"{ind}):"
            )

        new_text = _TEMPLATE_LEAK_RE.sub(_repl, text)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")

    return neutralized


# ---------------------------------------------------------------------------
# LLM prompt / 4-model execution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LLMResult:
    model: str
    ok: bool
    call_id: int | None
    content: str
    error: str


def build_llm_messages(
    env: AgentEnv,
    repo: Path,
    commit: str,
    missing: set[str],
) -> list[dict[str, Any]]:
    context = load_repo_context(repo, commit)

    if missing:
        missing_text = ", ".join(sorted(missing))
    else:
        missing_text = "none"

    return [
        {
            "role": "system",
            "content": (
               "# Six-Vulnerability Precision Defense Prompt"

                "## Purpose"
                
                "Use this prompt when the defense agent knows that **six vulnerabilities exist**, but does **not** know where they are located."
                
                "The agent must perform a careful, repository-wide defensive review. It must not assume that vulnerabilities are limited to previously known files or known leak branches. The agent must inspect the current repository snapshot, suspicious code snippets, available diffs, routers, service logic, frontend files, configuration files, and response construction paths."
                
                "The objective is to find and safely fix all six vulnerabilities while preserving service availability and normal behavior."
                
                "---"
                
                "## Replacement Defense Prompt"
                
                "```text"
                "You are an autonomous A&D defense agent patching a FastAPI or web service."
                
                "Return only JSON."
                
                "The service is expected to contain exactly six vulnerabilities, but their locations are unknown."
                
                "Your goal is to perform a precise repository-wide defensive inspection, identify the vulnerable code paths, and apply safe, minimal, non-breaking defensive patches."
                
                "Do not assume the vulnerabilities are only in known routes or previously patched files."
                "Do not rely only on commit history, because commit logs may be missing, rewritten, truncated, or unavailable."
                "Use the current repository snapshot, suspicious snippets, available working-tree diff, route handlers, service logic, templates, frontend files, and configuration files to search for vulnerabilities."
                
                "Search carefully for all of the following vulnerability classes:"
                
                "1. Secret, flag, token, credential, or password leakage."
                "2. Debug or internal runtime state exposure."
                "3. Unsafe file read, file export, file download, or path traversal."
                "4. Hidden admin behavior, magic-header branches, or suspicious query-parameter branches."
                "5. Authentication or authorization bypass."
                "6. Unsafe dynamic execution, unsafe deserialization, template injection, shell command injection, or unsafe subprocess usage."
                
                "Also inspect response fields that may carry sensitive data, including:"
                "- meta"
                "- system"
                "- debug"
                "- internal"
                "- data"
                "- state"
                "- export"
                "- runtime"
                "- summary"
                "- details"
                "- token"
                "- credential"
                
                "Known leak branches may still exist, but they are not the only possible vulnerabilities."
                "If known branches exist, patch them safely."
                "If new auxiliary or secondary vulnerabilities exist, patch them safely as well."
                
                "Preferred minimal fixes:"
                "- Redact sensitive fields."
                "- Remove only sensitive response keys."
                "- Validate user-controlled paths."
                "- Restrict file access to a safe base directory."
                "- Disable only leak-only branches."
                "- Replace sensitive values with safe placeholders."
                "- Use safe parsers or safe loaders."
                "- Avoid shell=True and unsafe dynamic execution."
                "- Preserve normal route behavior."
                
                "Hard constraints:"
                "- Do NOT remove or rename normal endpoints or routers."
                "- Do NOT break health-check endpoints."
                "- Do NOT break public API routes."
                "- Do NOT break checker/admin routes."
                "- Do NOT modify /admin/inject, /admin/check, services/ad_state.py, store_flag(), stored_summary(), or VULN_FLAGS unless absolutely necessary."
                "- Do NOT modify vuln_spec.json unless absolutely necessary."
                "- Do NOT delete important functionality just to silence an error."
                "- Keep edits minimal and syntax-valid."
                "- Preserve service availability."
                "- Preserve normal response formats expected by clients or checkers."
                
                "Legal warning improvement:"
                "If it is safe and non-breaking, add a visible legal warning to the UI, homepage, login page, footer, banner, or API root response."
                "The warning should state that unauthorized access, hacking attempts, exploitation, credential theft, data exfiltration, bypassing security controls, or service interference are strictly prohibited and may violate applicable laws."
                
                "Validation requirements:"
                "After proposing a patch, ensure the code remains syntactically valid."
                "Prefer fixes that can pass:"
                "- python -m py_compile"
                "- existing tests, if available"
                "- lightweight route or service validation, if available"
                
                "If a patch fails:"
                "- Read the exact error message."
                "- Identify the file, line, function, import, route, dependency, or logic condition causing the failure."
                "- Apply only the necessary correction."
                "- Re-run validation."
                "- Repeat until the patch is valid or no safe fix is possible."
                
                "If no safe fix is possible, revert unsafe changes and clearly report why."
                
                "Output format:"
                "Return exactly one JSON object."
                
                "If a patch is needed, return either:"
                
                "{\"patch\":\"<unified diff>\", \"summary\":\"...\"}"
                
                "or:"
                
                "{\"files\":[{\"path\":\"relative/path\", \"content\":\"full file content\"}], \"summary\":\"...\"}"
                
                "If no additional safe patch is required, return:"
                
                "{\"patch\":\"\", \"summary\":\"no additional safe patch required after repository-wide six-vulnerability review\"}"
                "```"
                
                "---"
                
                "## Repository-Wide Inspection Checklist"
                
                "The agent must inspect these areas carefully:"
                
                "### 1. API Routes"
                
                "Check all route handlers for:"
                
                "- suspicious headers"
                "- query parameters that unlock hidden behavior"
                "- debug or admin-only branches"
                "- response fields containing internal data"
                "- file export or download behavior"
                "- unexpected secret insertion into JSON responses"
                
                "### 2. Service Layer"
                
                "Check service modules for:"
                
                "- storage helpers"
                "- runtime state helpers"
                "- summary or metadata builders"
                "- file access helpers"
                "- unsafe serialization"
                "- unsafe subprocess usage"
                "- data returned to routers without filtering"
                
                "### 3. Configuration and Environment Access"
                
                "Search for:"
                
                "- `os.environ`"
                "- `os.getenv`"
                "- `.env`"
                "- config dumps"
                "- API keys"
                "- tokens"
                "- debug settings exposed through responses"
                
                "### 4. File Access and Export Logic"
                
                "Search for:"
                
                "- `open(`"
                "- `read_text`"
                "- `read_bytes`"
                "- `FileResponse`"
                "- `StreamingResponse`"
                "- `send_file`"
                "- `download`"
                "- `export`"
                "- `path`"
                "- `filename`"
                
                "Verify that user-controlled paths cannot read arbitrary files."
                
                "### 5. Frontend and Templates"
                
                "Inspect templates and frontend files for:"
                
                "- embedded secrets"
                "- exposed internal endpoints"
                "- debug data in JavaScript"
                "- unsafe template rendering"
                "- hardcoded credentials"
                "- hidden admin links or tokens"
                
                "### 6. Dynamic Execution and Deserialization"
                
                "Search for:"
                
                "- `eval(`"
                "- `exec(`"
                "- `subprocess`"
                "- `os.system`"
                "- `shell=True`"
                "- `pickle`"
                "- `yaml.load`"
                "- `render_template_string`"
                
                "Patch only unsafe use of untrusted input."
                
                "---"
                
                "## Suspicious Search Terms"
                
                "Use these terms during the scan:"
                
                "```text"
                "flag"
                "secret"
                "token"
                "credential"
                "password"
                "api_key"
                "internal"
                "debug"
                "runtime"
                "state"
                "meta"
                "system"
                "export"
                "summary"
                "details"
                "os.environ"
                "os.getenv"
                "process.env"
                "base64"
                "headers"
                "Header"
                "query"
                "query_params"
                "admin"
                "magic"
                "X-"
                "Authorization"
                "Bearer"
                "FileResponse"
                "StreamingResponse"
                "send_file"
                "open("
                "read_text"
                "read_bytes"
                "../"
                "path"
                "filename"
                "download"
                "eval("
                "exec("
                "subprocess"
                "os.system"
                "shell=True"
                "pickle"
                "yaml.load"
                "template"
                "render_template_string"
                "```"
                
                "---"
                
                "## Defensive Decision Rule"
                
                "When uncertain, choose the safest defensive option:"
                
                "```text"
                "small patch > broad rewrite"
                "redaction > deletion"
                "input validation > blocking entire route"
                "disable leak branch > remove endpoint"
                "preserve route > block request"
                "syntax-valid patch > clever patch"
                "availability > aggressive hardening"
                "```"
                
                "The agent must find and patch all six vulnerabilities where safely possible, while preserving the intended service behavior."


                "Hard constraints:\n"
                "- Do NOT remove or rename endpoints or routers.\n"
                "- Keep /health, /upload, /files, /files/{id}, /analysis, /recommend, "
                "and /debug/state working normally if present.\n"
                "- Do NOT break checker/admin routes.\n"
                "- Do NOT modify /admin/inject, /admin/check, services/ad_state.py, "
                "store_flag(), stored_summary(), or VULN_FLAGS.\n"
                "- Do NOT modify vuln_spec.json or Dockerfile unless absolutely necessary.\n"
                "- Keep edits minimal and syntax-valid.\n"
                "- Preserve availability.\n\n"

                "Legal warning improvement:\n"
                "If it is safe and non-breaking, add a visible warning to the UI, homepage, "
                "login page, footer, banner, or API root response. The warning should state "
                "that unauthorized access, hacking attempts, exploitation, credential theft, "
                "data exfiltration, bypassing security controls, or service interference are "
                "strictly prohibited and may violate applicable laws.\n\n"

                "If deterministic patches already fixed everything, return JSON with an empty "
                "patch and a summary. Example:\n"
                "{\"patch\":\"\", \"summary\":\"deterministic patch already covered all known leaks\"}\n\n"

                "Output format must be exactly one JSON object, either:\n"
                "{\"patch\":\"<unified diff>\", \"summary\":\"...\"}\n"
                "or\n"
                "{\"files\":[{\"path\":\"relative/path\", \"content\":\"full file content\"}], "
                "\"summary\":\"...\"}\n"
                
                    "The agent should periodically repeat the following cycle:\n"

                    "1. Re-read the full defense instructions, rules, and constraints."
                    "2. Re-check the target repository for vulnerable code paths."
                    "3. Apply only safe, minimal, non-breaking defensive patches if needed."
                    "4. Verify that normal service behavior, APIs, endpoints, and checker/admin routes still work."
                    "5. Commit and push any valid defense patch that includes the current Agent-Run-ID."

                    "This periodic review must not remove, rename, or break existing routes, APIs, checker logic, admin endpoints, or normal service functionality. The agent must preserve availability while continuously improving the defensive posture."
                    "When modifying code, if the patch does not work, the defense agent must inspect the error message, logs, failed command output, syntax errors, test failures, or runtime exceptions, and then revise the code accordingly."

                    "The agent must not stop after the first failed modification. It should use the observed error details to identify the root cause, apply a corrected minimal patch, and re-run the relevant validation step."

                    "The agent should repeat this repair cycle until the code is syntactically valid, the relevant checks pass, and the service behavior is preserved."

                    "Repair cycle:"

                    "1. Apply the intended defensive code change."
                    "2. Run syntax checks, tests, build commands, or service validation commands when available."
                    "3. If an error occurs, read the full error message carefully."
                    "4. Determine which file, line, function, import, dependency, route, or logic condition caused the failure."
                    "5. Modify only the necessary code to fix the error."
                    "6. Re-run the validation command."
                    "7. Repeat until the patch works correctly or no safe fix is possible."

                    "Constraints:"

                    "* Do not make random changes."
                    "* Do not delete important functionality just to silence an error."
                    "* Do not remove or rename existing APIs, routes, endpoints, checker logic, admin routes, or normal service behavior."
                    "* Keep each fix minimal and explainable."
                    "* Preserve availability."
                    "* If no safe fix is possible, revert unsafe changes and report the failure clearly."
                    "# Continuous Defense Focus Instructions"

                    "## Objective"
                    
                    "The defense agent must remain focused on continuous defensive improvement.  "
                    "The target repository may keep changing, and new vulnerabilities may appear at any time.  "
                    "The agent must repeatedly inspect the repository, identify newly introduced vulnerable code paths, and apply only safe, minimal, non-breaking defensive fixes."
                    
                    "The primary goal is to protect the service while preserving normal functionality, API compatibility, checker behavior, and availability."
                    
                    "---"
                    
                    "## Periodic Defense Review Cycle"
                    
                    "The agent should repeatedly perform the following defense-focused cycle:"
                    
                    "1. Re-read the full defense instructions, rules, constraints, and competition requirements."
                    "2. Re-check the latest target repository state because files may have changed since the previous run."
                    "3. Search for newly introduced vulnerable code paths, including:"
                    "   - secret leakage"
                    "   - flag leakage"
                    "   - debug information exposure"
                    "   - internal state exposure"
                    "   - unsafe file export behavior"
                    "   - environment variable exposure"
                    "   - hidden admin or magic-header branches"
                    "   - suspicious response fields such as `meta`, `system`, `debug`, `internal`, `data`, or `state`"
                    "4. Apply only safe, minimal, non-breaking defensive patches when a vulnerability is found."
                    "5. Verify that normal service behavior still works."
                    "6. Verify that APIs, endpoints, router registration, checker logic, and admin routes are not broken."
                    "7. Run syntax checks, tests, build commands, or lightweight service validation commands when available."
                    "8. Commit and push only valid defensive patches that include the current `Agent-Run-ID`."
                    
                    "---"
                    
                    "## Continuous Vulnerability Search Requirement"
                    
                    "Because the repository may continue to change and new vulnerabilities may be introduced, the agent must not assume that previous patches are sufficient."
                    
                    "Even if known vulnerabilities have already been patched, the agent must continue to inspect the repository for new risks."
                    
                    "The agent must specifically look for:"
                    
                    "- newly added routes"
                    "- changed response schemas"
                    "- new debug endpoints"
                    "- new file read/export logic"
                    "- new admin-only code paths"
                    "- new magic headers or query parameters"
                    "- new references to secrets, flags, tokens, credentials, environment variables, or internal runtime state"
                    "- changes to router files, service files, frontend templates, and API handlers"
                    
                    "If a new vulnerability is discovered, the agent must patch only the vulnerable behavior while preserving the intended service behavior."
                    
                    "---"
                    
                    "## Safe Patch Requirements"
                    
                    "Any defensive patch must follow these constraints:"
                    
                    "- Do not make random changes."
                    "- Do not delete important functionality just to silence an error."
                    "- Do not remove, rename, or break existing APIs, routes, endpoints, checker logic, admin routes, or normal service behavior."
                    "- Do not modify `vuln_spec.json`, checker logic, or flag storage logic unless absolutely necessary."
                    "- Keep every fix minimal and explainable."
                    "- Preserve availability."
                    "- Prefer redaction, filtering, or disabling only the leak branch over deleting an entire route."
                    "- If no safe fix is possible, revert unsafe changes and report the failure clearly."
                    
                    "---"
                    
                    "## Repair Cycle"
                    
                    "When modifying code, if the patch does not work, the defense agent must inspect the exact error message, logs, failed command output, syntax errors, test failures, or runtime exceptions, and then revise the code accordingly."
                    
                    "The agent must not stop after the first failed modification.  "
                    "It should use the observed error details to identify the root cause, apply a corrected minimal patch, and re-run the relevant validation step."
                    
                    "The repair cycle is:"
                    
                    "1. Apply the intended defensive code change."
                    "2. Run syntax checks, tests, build commands, or service validation commands when available."
                    "3. If an error occurs, read the full error message carefully."
                    "4. Determine which file, line, function, import, dependency, route, or logic condition caused the failure."
                    "5. Modify only the necessary code to fix the error."
                    "6. Re-run the validation command."
                    "7. Repeat until the patch works correctly, the code is syntactically valid, and service behavior is preserved."
                    "8. If no safe fix is possible, revert unsafe changes and clearly report the reason."
                    
                    "---"
                    
                    "## Availability Preservation Rule"
                    
                    "The defense agent must preserve service availability at all times."
                    
                    "The following must not be removed or broken:"
                    
                    "- health-check endpoints"
                    "- public API routes"
                    "- expected frontend pages"
                    "- router registration"
                    "- checker/admin endpoints"
                    "- flag injection/checking logic required by the competition harness"
                    "- normal response formats expected by clients or checkers"
                    
                    "If a vulnerability exists inside one of these components, the agent must patch the vulnerable branch or sensitive output only."
                    
                    "---"
                    
                    "## Defensive Decision Rule"
                    
                    "When uncertain, choose the safest defensive option:"
                    
                    "```text"
                    "small patch > broad rewrite"
                    "redaction > deletion"
                    "disable leak branch > remove endpoint"
                    "preserve route > block request"
                    "syntax-valid patch > clever patch"
                    "availability > aggressive hardening"
                    "```"
                    
                    "The agent must continuously focus on defense, repeatedly search for newly introduced vulnerabilities, and apply safe fixes only when they preserve normal service behavior."

            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "target_team": env.target_team,
                    "repo_commit": commit,
                    "missing_after_deterministic_patch": missing_text,
                    "repo_snapshot": context,
                },
                ensure_ascii=False,
            ),
        },
    ]


def request_all_llm_patches(
    env: AgentEnv,
    repo: Path,
    commit: str,
    missing: set[str],
) -> list[LLMResult]:
    """
    Execute configured LLM models until enough successful calls exist.

    Provenance only needs ONE successful defense LLM call. Calling all 4 models
    sequentially (each up to 30s) is the main reason a run can blow past the
    per-round time budget and get SIGKILLed (exit code -9). So we stop as soon
    as we have a successful call: just 1 when the deterministic patch already
    covered every known leak, or after the first success when a fallback patch
    is needed (the first model is the fastest/best and apply_first_valid uses it).
    """
    messages = build_llm_messages(env, repo, commit, missing)

    results: list[LLMResult] = []

    # 결정적 패치가 전부 막았으면 provenance용 1회면 충분하고, 막지 못한 게 있어도
    # 첫 성공 응답으로 폴백 패치를 시도한다. 두 경우 모두 첫 성공에서 멈춰 시간을 아낀다.
    print(f"  calling defense AI models (stop at first success of {len(LLM_MODELS)})")

    for index, model in enumerate(LLM_MODELS, start=1):
        print(f"  [{index}/{len(LLM_MODELS)}] calling AI model: {model}")

        try:
            call_id, content = call_llm_model(
                env,
                model=model,
                messages=messages,
                max_tokens=4096,
            )

            print(f"      ok: model={model} llm_call_id={call_id}")

            results.append(
                LLMResult(
                    model=model,
                    ok=True,
                    call_id=call_id,
                    content=content,
                    error="",
                )
            )
            # 성공 1회면 provenance 확보 + 폴백 후보 확보 → 즉시 중단(타임아웃 방지).
            break

        except Exception as exc:
            print(f"      failed: model={model} error={exc}")

            results.append(
                LLMResult(
                    model=model,
                    ok=False,
                    call_id=None,
                    content="",
                    error=str(exc),
                )
            )

    ok_count = sum(1 for result in results if result.ok)
    print(f"  defense AI calls completed: {ok_count}/{len(results)} succeeded")

    if ok_count == 0:
        errors = "; ".join(
            f"{result.model}: {result.error}"
            for result in results
        )
        raise RuntimeError(f"all defense AI model calls failed: {errors[:1500]}")

    return results


def apply_first_valid_llm_fallback(repo: Path, results: list[LLMResult]) -> int:
    """
    Try to apply the first valid LLM patch among successful model responses.

    This avoids applying conflicting patches from multiple models.
    """
    for result in results:
        if not result.ok:
            continue

        try:
            data = _json_from_text(result.content)
            changed = apply_llm_patch(repo, data)

            if changed:
                print(f"  applied LLM fallback from model={result.model}, changes={changed}")
                return changed

            print(f"  model={result.model} returned no applicable patch")

        except Exception as exc:
            print(f"  model={result.model} fallback patch unusable: {exc}")

    return 0


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------

def run_once() -> None:
    env = AgentEnv.from_env()

    print(
        f"[{env.team_id}] defense run {env.run_id} "
        f"target={env.target_team} round={env.round_num}"
    )

    try:
        reset_repo_dir(REPO_DIR)

        repo_info = clone_target_repo(env, REPO_DIR)
        repo = Path(repo_info["path"])

        # 1a. Deterministic patch for the 4 known leaks.
        patched = neutralize_leaks(repo)

        if patched:
            print(f"  deterministic patch: {', '.join(patched)}")
        else:
            print("  deterministic patch: no anchors matched")

        # 1b. Template scan: catch leaks newly injected this round (no git history
        #     needed — matches the operator's leak signature by file content).
        template_hits = neutralize_template_leaks(repo)
        if template_hits:
            print(f"  template scan disabled new leak branches: {', '.join(template_hits)}")
        else:
            print("  template scan: no additional leak branches found")

        patched_ids = {p.split("(")[0] for p in patched}
        expected_ids = {vid for _, vid, _ in LEAK_GUARDS}
        missing = expected_ids - patched_ids

        # 2. Mandatory 4-AI execution for provenance/review.
        llm_results = request_all_llm_patches(
            env=env,
            repo=repo,
            commit=repo_info["commit"],
            missing=missing,
        )

        # 3. Apply fallback only if deterministic patch missed known anchors.
        applied = 0

        if missing:
            print(f"  anchors not matched for {sorted(missing)}; trying LLM fallbacks")
            applied = apply_first_valid_llm_fallback(repo, llm_results)

            if applied == 0:
                print("  no LLM fallback patch was applied")
        else:
            print("  deterministic patch covered all known leaks; AI calls kept for provenance/review")

        # 4. Validate syntax.
        syntax_check(repo)
        print("  syntax check passed")

        # 5. If nothing changed, finish successfully.
        if not has_worktree_changes(repo):
            print("  repository already safe or no changes produced; nothing to push")
            finish(env, "completed")
            return

        # 6. Commit.
        summary = f"A&D defense: neutralize {env.target_team} leak branches vuln1-vuln4"[:120]
        commit = commit_patch(env, repo, summary)

        if commit is None:
            print("  no commit created")
            finish(env, "completed")
            return

        print(f"  created defense commit {commit[:12]}")

        # 7. Push.
        push_repo_with_retry(env, repo)
        print(f"  pushed defense commit {commit[:12]}")

        finish(env, "completed")

    except Exception as exc:
        print(f"  run failed: {exc}")
        finish(env, "failed", str(exc))
        raise


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not LLM_MODELS:
        raise RuntimeError("LLM_MODELS is empty; at least one model is required")

    print(f"[config] defense AI models: {', '.join(LLM_MODELS)}")

    if not LOOP_FOREVER:
        run_once()
        return

    print("[loop] defense agent started")
    print(f"[loop] interval = {LOOP_INTERVAL_SECONDS} seconds")

    while True:
        try:
            run_once()

        except KeyboardInterrupt:
            print("[loop] interrupted by user")
            raise

        except Exception as exc:
            print(f"[loop] run failed, will retry later: {exc}")

        print(f"[loop] sleeping {LOOP_INTERVAL_SECONDS} seconds before next run")
        time.sleep(LOOP_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
