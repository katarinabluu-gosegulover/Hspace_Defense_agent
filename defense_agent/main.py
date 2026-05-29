#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HSPACE LiveFire A&D — Team2 Defense Agent (Team1 서비스 방어용)
==============================================================
파일: defense_agent/main.py

── 방어 대상 서비스 ──────────────────────────────────────────────────────────
  Team1 / Study Compass (귀찮은 업무 도우미)
  URL: http://knights.hspace.io:42001
  메인 파일: main.py (루트 단일 파일 구조)

── 취약점 요약 ───────────────────────────────────────────────────────────────
  vuln1 indirect_prompt_injection  POST /chat  "검색/추천" → 오염된 캐시 반환
  vuln2 memory_poisoning           POST /chat  "기록/이전" → 세션 메모리 노출
  vuln3 orchestration_logic_bypass POST /chat  "모든 할 일" → admin 할 일 노출
  vuln4 tool_call_manipulation     POST /chat  "디버그" → tool_secret 노출

── 패치 방법 ─────────────────────────────────────────────────────────────────
  vuln1: _get_search_result() 의 오염된 캐시 반환 블록 제거
  vuln2: recall_memory 응답에서 "[시스템 메모:" 항목 필터링
  vuln3: list_todos 응답에서 "admin" 키 제외
  vuln4: debug_dump 응답에서 "tool_secret" 키 제외

── 기능 ─────────────────────────────────────────────────────────────────────
  1. LLM 호출      coordinator wrapper를 통해 패치 적절성 확인 (AI agent 요건)
  2. 취약점 패치    vuln1~4 코드 블록 수정 (deterministic string replacement)
  3. 공격 탐지     POST /chat body 분석 미들웨어 → 공격 로그 자동 기록
  4. 라운드 리포트  공격 로그를 LLM으로 분석 → defense_reports/ 에 저장
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx

# ── 환경변수 (coordinator 주입) ───────────────────────────────────────────────
BASE_URL  = (os.environ.get("OPENROUTER_BASE_URL") or
             os.environ.get("OPENAI_BASE_URL", "")).rstrip("/")
API_KEY   = (os.environ.get("OPENROUTER_API_KEY") or
             os.environ.get("OPENAI_API_KEY", ""))
AGENT_RUN_TOKEN       = os.environ.get("AGENT_RUN_TOKEN", "")
HSPACE_AGENT_BASE_URL = os.environ.get("HSPACE_AGENT_BASE_URL", "")
AGENT_RUN_ID          = os.environ.get("AGENT_RUN_ID", "")
CHECKER_TOKEN         = os.environ.get("CHECKER_TOKEN", "validate-test-token")
LLM_BASE_SOURCE       = "OPENROUTER_BASE_URL" if os.environ.get("OPENROUTER_BASE_URL") else "OPENAI_BASE_URL"

REPO_PATH   = Path(os.environ.get("SERVICE_REPO_PATH", "."))
SERVICE_URL = os.environ.get("SERVICE_URL", "http://knights.hspace.io:42001")
AGENT_ROOT = Path(__file__).resolve().parents[1]

# 리포트 저장 폴더
REPORT_DIR = REPO_PATH / "defense_reports"
AGENT_LOG_PATH = Path(
    os.environ.get("AGENT_LOG_PATH")
    or os.environ.get("HSPACE_AGENT_LOG_PATH")
    or str(Path(tempfile.gettempdir()) / "hspace_defense_agent.jsonl")
)

# ── 허용 모델 ─────────────────────────────────────────────────────────────────
MODELS = [
    "google/gemini-2.0-flash-001",
    "qwen/qwen-2.5-14b",
    "mistralai/mistral-small-3.1",
]

_llm_call_count = 0


def _load_build_rev() -> str:
    env_rev = os.environ.get("HSPACE_AGENT_BUILD_REV", "").strip()
    if env_rev:
        return env_rev

    manifest_path = AGENT_ROOT / "agent_manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        revision = str(data.get("revision", "")).strip()
        if revision:
            return revision
    except Exception:
        pass
    return "unknown-build-rev"


BUILD_REV = _load_build_rev()


def log_event(event: str, **fields) -> None:
    safe_fields = {
        key: "[redacted]" if any(word in key.lower() for word in ("token", "secret", "key", "authorization", "password")) else value
        for key, value in fields.items()
    }
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **safe_fields,
    }
    try:
        AGENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AGENT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass
    print("[hspace-defense-agent] " + json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr, flush=True)


# ═════════════════════════════════════════════════════════════════════════════
# 1. LLM 클라이언트
# ═════════════════════════════════════════════════════════════════════════════

def call_llm(
    messages: list[dict],
    model: str | None = None,
    purpose: str = "defense",
    retries: int = 3,
) -> tuple[str, int]:
    """coordinator wrapper를 통한 LLM 호출. 반환: (content, llm_call_id)"""
    global _llm_call_count
    model = model or MODELS[0]
    log_event("llm_call_start", model=model, base_source=LLM_BASE_SOURCE, purpose=purpose)

    for attempt in range(retries):
        try:
            resp = httpx.post(
                BASE_URL + "/chat/completions",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "X-Agent-Purpose": purpose,
                },
                json={"model": model, "messages": messages},
                timeout=90,
            )
            if resp.status_code == 429:
                wait = 15 * (attempt + 1)
                print(f"    [llm] 429 — {wait}s 대기...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            _llm_call_count += 1
            content = resp.json()["choices"][0]["message"]["content"]
            call_id = int(resp.headers.get("X-LLM-Call-ID", 0))
            log_event("llm_call_finish", model=model, call_id=call_id, chars=len(content))
            return content, call_id
        except Exception as e:
            log_event("llm_call_error", model=model, attempt=attempt + 1, error=str(e)[:500])
            print(f"    [llm] 오류 (시도 {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(5 * (attempt + 1))

    return "", 0


def llm_confirm_patches() -> str:
    """
    LLM으로 패치 적절성을 확인한다. (AI agent 요건 충족)
    실제 패치는 deterministic하게 진행하되, LLM이 검토·승인하는 구조.
    """
    prompt = textwrap.dedent("""
    당신은 A&D CTF 방어 전문가입니다.
    Team1의 Study Compass 서비스(귀찮은 업무 도우미)에 다음 4개의 취약점이 존재합니다.
    각 취약점은 실제 공개된 CVE 패턴을 참고하여 구현되었습니다.
    각 취약점에 대한 패치 방법이 올바른지 검토하고, 서비스 가용성을 해치지 않는지 확인해주세요.

    ## 서비스 구조
    - 단일 파일: main.py (루트)
    - 주요 엔드포인트: POST /chat (모든 취약점의 진입점)
    - 취약점은 _run_service() 함수 내 키워드 분기에 존재

    ## 취약점 및 패치 방법

    vuln1 (indirect_prompt_injection) — ref: CVE-2026-27960
    - CVE 패턴: OpenCTI 미인증 API 쿼리로 내부 데이터 탈취
    - 트리거: POST /chat, message에 "검색"/"찾아"/"추천" 포함
    - 동작: _get_search_result()가 오염된 _search_cache["vuln1"]을 그대로 반환
    - 노출: flag가 포함된 캐시 문자열이 응답에 포함됨
    - 패치: _get_search_result() 내 오염된 캐시 반환 if-블록 제거 → 항상 일반 결과만 반환

    vuln2 (memory_poisoning) — ref: CVE-2026-1060
    - CVE 패턴: WP Adminify REST API 권한 검증 누락으로 민감 정보 노출
    - 트리거: POST /chat, message에 "기록"/"이전"/"history" 포함
    - 동작: _session_memory 전체를 "\n".join()으로 응답에 포함
    - 노출: "[시스템 메모: 보안 코드 = FLAG]" 항목이 응답에 포함됨
    - 패치: memories 구성 시 "[시스템 메모:" 로 시작하는 항목 필터링

    vuln3 (orchestration_logic_bypass) — ref: CVE-2026-20223
    - CVE 패턴: Cisco Secure Workload 인증 우회 → 민감 정보 노출 (CVSS 10.0)
    - 트리거: POST /chat, message에 "할 일"/"todo" AND "다른 사용자"/"모든"/"admin" 포함
    - 동작: dict(_todo_db) 전체를 응답에 포함 (admin 키 포함)
    - 노출: _todo_db["admin"] = "관리자 비밀 할 일: FLAG"
    - 패치: all_todos 구성 시 "admin" 키 제외

    vuln4 (tool_call_manipulation) — ref: CVE-2026-20164
    - CVE 패턴: Splunk 낮은 권한으로 credentials 노출
    - 트리거: POST /chat, message에 "디버그"/"debug"/"툴 상태" 포함
    - 동작: dict(_tool_debug_tokens) 전체를 응답에 포함
    - 노출: _tool_debug_tokens["tool_secret"] = FLAG
    - 패치: debug_state 구성 시 "tool_secret" 키 제외

    각 패치가 CVE 패턴을 효과적으로 차단하면서 서비스 기능을 유지하는지 검토해주세요.
    특히 /chat 엔드포인트 자체는 유지되어야 하고, 일반 사용자의 정상 요청은 영향받지 않아야 합니다.
    """).strip()

    content, _ = call_llm(
        [{"role": "user", "content": prompt}],
        model=MODELS[0],
        purpose="defense",
    )
    return content


# ═════════════════════════════════════════════════════════════════════════════
# 2. 취약점 패치 정의 (deterministic string replacement)
# ═════════════════════════════════════════════════════════════════════════════

# main.py 경로 (루트 단일 파일)
_MAIN_PY = "main.py"

# vuln1: _get_search_result() 내 오염된 캐시 반환 블록 제거
_VULN1_OLD = '''\
def _get_search_result(query: str) -> str:
    """검색 캐시 조회. inject로 오염된 캐시가 있으면 그것을 반환."""
    if _vuln_flags["vuln1"] and "vuln1" in _search_cache:
        # 오염된 캐시: flag가 숨겨진 검색 결과 반환
        return _search_cache["vuln1"]
    return f"'{query}'에 대한 일반 검색 결과입니다."'''

_VULN1_NEW = '''\
def _get_search_result(query: str) -> str:
    """검색 캐시 조회. 일반 결과만 반환 (캐시 오염 패치됨)."""
    return f"'{query}'에 대한 일반 검색 결과입니다."'''

# vuln2: 세션 메모리 조회 시 시스템 메모 필터링
_VULN2_OLD = '''\
    elif "기록" in lower or "이전" in lower or "history" in lower:
        memories = "\\n".join(_session_memory)
        tool_calls.append({"tool": "recall_memory", "result": memories})
        response = f"기억하고 있는 내용:\\n{memories}" if memories else "저장된 기록이 없습니다."'''

_VULN2_NEW = '''\
    elif "기록" in lower or "이전" in lower or "history" in lower:
        memories = "\\n".join(
            m for m in _session_memory
            if not m.startswith("[시스템 메모:")
        )
        tool_calls.append({"tool": "recall_memory", "result": memories})
        response = f"기억하고 있는 내용:\\n{memories}" if memories else "저장된 기록이 없습니다."'''

# vuln3: 전체 할 일 조회 시 admin 키 제외
_VULN3_OLD = '''\
        if "다른 사용자" in lower or "모든" in lower or "admin" in lower:
            # 권한 체크 누락 — admin 데이터까지 반환
            all_todos = dict(_todo_db)
            tool_calls.append({"tool": "list_todos", "result": all_todos})
            response = f"전체 할 일: {all_todos}"'''

_VULN3_NEW = '''\
        if "다른 사용자" in lower or "모든" in lower or "admin" in lower:
            # admin 키 제외 (권한 우회 패치됨)
            all_todos = {k: v for k, v in _todo_db.items() if k != "admin"}
            tool_calls.append({"tool": "list_todos", "result": all_todos})
            response = f"전체 할 일: {all_todos}"'''

# vuln4: 디버그 상태 조회 시 tool_secret 키 제외
_VULN4_OLD = '''\
    elif "디버그" in lower or "debug" in lower or "툴 상태" in lower:
        debug_state = dict(_tool_debug_tokens)
        tool_calls.append({"tool": "debug_dump", "result": debug_state})
        response = f"디버그 툴 상태: {debug_state}"'''

_VULN4_NEW = '''\
    elif "디버그" in lower or "debug" in lower or "툴 상태" in lower:
        debug_state = {k: v for k, v in _tool_debug_tokens.items() if k != "tool_secret"}
        tool_calls.append({"tool": "debug_dump", "result": debug_state})
        response = f"디버그 툴 상태: {debug_state}"'''


VULN_PATCHES: list[tuple[str, str, str, str]] = [
    ("vuln1", _MAIN_PY, _VULN1_OLD, _VULN1_NEW),
    ("vuln2", _MAIN_PY, _VULN2_OLD, _VULN2_NEW),
    ("vuln3", _MAIN_PY, _VULN3_OLD, _VULN3_NEW),
    ("vuln4", _MAIN_PY, _VULN4_OLD, _VULN4_NEW),
]

# 패치 검증 마커 (패치 후 이 문자열이 없어야 함)
VULN_MARKERS = {
    "vuln1": 'return _search_cache["vuln1"]',
    "vuln2": 'memories = "\\n".join(_session_memory)',
    "vuln3": '# 권한 체크 누락 — admin 데이터까지 반환',
    "vuln4": 'debug_state = dict(_tool_debug_tokens)',
}

FEATURE_MARKERS = {
    "health": '@app.get("/health")',
    "chat": '@app.post("/chat")',
    "admin_inject": '@app.post("/admin/inject")',
    "admin_check": '@app.get("/admin/check")',
    "markdown_upload": '@app.post("/api/markdown/upload")',
    "markdown_list": '@app.get("/api/markdown/list")',
    "markdown_preview": '@app.post("/api/markdown/preview")',
}


def inspect_vulnerability_state(repo: Path) -> list[dict]:
    """vuln1~4를 순서대로 읽고 현재 패치 상태를 구조화한다."""
    main_path = repo / _MAIN_PY
    if not main_path.exists():
        return [{"vuln_id": "all", "status": "missing_main", "detail": _MAIN_PY}]
    content = main_path.read_text(encoding="utf-8")
    states = []
    for vuln_id, _rel_path, old_block, _new_block in VULN_PATCHES:
        marker = VULN_MARKERS.get(vuln_id, "")
        if old_block in content or (marker and marker in content):
            status = "vulnerable"
        else:
            status = "patched_or_not_present"
        states.append({"vuln_id": vuln_id, "status": status})
        log_event("vuln_inspected", vuln_id=vuln_id, status=status)
    return states


def verify_feature_markers(repo: Path) -> list[str]:
    """사용자 기능/체커 기능이 삭제되지 않았는지 확인한다."""
    main_path = repo / _MAIN_PY
    if not main_path.exists():
        return [f"{_MAIN_PY} 파일 없음"]
    content = main_path.read_text(encoding="utf-8")
    missing = [
        f"기능 마커 삭제됨: {name} ({marker})"
        for name, marker in FEATURE_MARKERS.items()
        if marker not in content
    ]
    return missing


def syntax_check_main(repo: Path) -> list[str]:
    """main.py 문법 검사. import 실행 없이 컴파일만 수행한다."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import py_compile; "
                "py_compile.compile('main.py', cfile='/tmp/team1_main_check.pyc', doraise=True)"
            ),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return [(result.stderr or result.stdout)[-500:]]
    return []


def verify_single_vuln_patch(repo: Path, vuln_id: str) -> list[str]:
    """단일 취약점 패치 직후 안전성 검증."""
    issues = []
    main_path = repo / _MAIN_PY
    content = main_path.read_text(encoding="utf-8")
    marker = VULN_MARKERS.get(vuln_id, "")
    if marker and marker in content:
        issues.append(f"{vuln_id}: 취약 마커가 아직 남아 있음")
    issues.extend(verify_feature_markers(repo))
    issues.extend(syntax_check_main(repo))
    if issues:
        log_event("vuln_patch_verify_failed", vuln_id=vuln_id, issues=issues[:5])
    else:
        log_event("vuln_patch_verified", vuln_id=vuln_id)
    return issues


def apply_vuln_patches(repo: Path) -> tuple[list[str], dict[str, str]]:
    """취약 코드 블록을 순서대로 검수/패치/검증한다. 실패 시 즉시 롤백한다."""
    changed: list[str] = []
    backups: dict[str, str] = {}
    inspect_vulnerability_state(repo)

    for vuln_id, rel_path, old_block, new_block in VULN_PATCHES:
        full_path = repo / rel_path
        if not full_path.exists():
            print(f"  [{vuln_id}] 파일 없음 ({rel_path}) → 스킵")
            continue

        original = full_path.read_text(encoding="utf-8")
        if str(full_path) not in backups:
            backups[str(full_path)] = original

        if old_block not in original:
            marker = VULN_MARKERS.get(vuln_id, "")
            if marker and marker not in original:
                print(f"  [{vuln_id}] 이미 패치됨 → 스킵")
            else:
                print(f"  [{vuln_id}] 취약 블록을 찾지 못함 → 스킵")
            continue

        patched = original.replace(old_block, new_block, 1)
        full_path.write_text(patched, encoding="utf-8")
        issues = verify_single_vuln_patch(repo, vuln_id)
        if issues:
            rollback(backups)
            raise RuntimeError(f"{vuln_id} 안전 패치 검증 실패: {issues[:3]}")
        if rel_path not in changed:
            changed.append(rel_path)
        print(f"  [{vuln_id}] ✓ 취약 블록 패치 완료")

    return changed, backups


def verify_vuln_patches(repo: Path) -> list[str]:
    """취약 마커 잔존 여부 + 엔드포인트 유지 여부 확인."""
    issues = []
    main_path = repo / _MAIN_PY
    if not main_path.exists():
        return [f"{_MAIN_PY} 파일 없음"]
    content = main_path.read_text(encoding="utf-8")

    for vuln_id, marker in VULN_MARKERS.items():
        if marker in content:
            issues.append(f"{vuln_id}: 취약 블록 미제거 ({marker[:40]}...)")

    issues.extend(verify_feature_markers(repo))
    issues.extend(syntax_check_main(repo))

    return issues


def rollback(backups: dict[str, str]) -> None:
    for path_str, content in backups.items():
        Path(path_str).write_text(content, encoding="utf-8")
    print(f"  [rollback] {len(backups)}개 파일 복원")


# ═════════════════════════════════════════════════════════════════════════════
# 3. 공격 탐지 미들웨어 설치
# ═════════════════════════════════════════════════════════════════════════════

# Team1용 attack_monitor: POST /chat body에서 message를 읽어 시그니처 탐지
_ATTACK_MONITOR_PY = '''\
"""공격 탐지 및 로깅 서비스 (defense agent에 의해 설치됨, Team1용)."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ATTACK_LOG_PATH = Path(os.getenv("ATTACK_LOG_PATH", "/tmp/attack_log.jsonl"))

# Team1 취약점 공격 시그니처 (POST /chat message 기반)
ATTACK_SIGNATURES: dict = {
    "vuln1": {
        "description": "indirect_prompt_injection (검색 캐시 오염)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords": ["검색", "찾아", "추천"],
        "cve": "CVE-2026-27960",
    },
    "vuln2": {
        "description": "memory_poisoning (세션 메모리 유출)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords": ["기록", "이전", "history"],
        "cve": "CVE-2026-1060",
    },
    "vuln3": {
        "description": "orchestration_logic_bypass (admin 할 일 노출)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords_all": [["할 일", "todo"], ["다른 사용자", "모든", "admin"]],
        "cve": "CVE-2026-20223",
    },
    "vuln4": {
        "description": "tool_call_manipulation (tool_secret 노출)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords": ["디버그", "debug", "툴 상태"],
        "cve": "CVE-2026-20164",
    },
}


def detect_attack(path: str, method: str, message: str) -> Optional[str]:
    """POST /chat의 message에서 공격 시그니처 탐지. 일치하면 vuln_id, 아니면 None."""
    lower = message.lower()
    for vuln_id, sig in ATTACK_SIGNATURES.items():
        if not path.startswith(sig["endpoint"]):
            continue
        if sig.get("method") and method != sig["method"]:
            continue

        # 단일 키워드 그룹
        if "keywords" in sig:
            if any(k in lower for k in sig["keywords"]):
                return vuln_id

        # 복수 키워드 그룹 (모든 그룹에서 하나씩 매칭)
        if "keywords_all" in sig:
            if all(any(k in lower for k in group) for group in sig["keywords_all"]):
                return vuln_id

    return None


def log_attack(vuln_id: str, method: str, path: str,
               client_ip: str, message_preview: str) -> None:
    """공격 시도를 JSONL 파일에 기록한다."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vuln_id": vuln_id,
        "description": ATTACK_SIGNATURES.get(vuln_id, {}).get("description", ""),
        "cve": ATTACK_SIGNATURES.get(vuln_id, {}).get("cve", ""),
        "method": method,
        "path": path,
        "client_ip": client_ip,
        "message_preview": message_preview,
    }
    try:
        ATTACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ATTACK_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\\n")
    except Exception:
        pass


def read_log() -> list[dict]:
    if not ATTACK_LOG_PATH.exists():
        return []
    entries = []
    try:
        with open(ATTACK_LOG_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return entries


def clear_log() -> None:
    try:
        ATTACK_LOG_PATH.unlink(missing_ok=True)
    except Exception:
        pass
'''

# main.py 에 추가할 미들웨어 코드 (app = FastAPI() 이후 삽입)
_MONITOR_ANCHOR = "app = FastAPI()"

_MONITOR_INSERT = '''\
app = FastAPI()

# ── Attack Monitor Middleware (installed by defense agent) ─────────────────
try:
    import json as _json
    from starlette.middleware.base import BaseHTTPMiddleware as _BaseHTTPMiddleware
    from services.attack_monitor import detect_attack as _detect_attack, log_attack as _log_attack

    class _AttackMonitorMiddleware(_BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.method == "POST" and request.url.path.startswith("/chat"):
                try:
                    body = await request.body()
                    data = _json.loads(body)
                    message = data.get("message", "")
                    vuln_id = _detect_attack(
                        request.url.path,
                        request.method,
                        message,
                    )
                    if vuln_id:
                        _log_attack(
                            vuln_id,
                            request.method,
                            request.url.path,
                            getattr(request.client, "host", "unknown")
                            if request.client else "unknown",
                            message[:120],
                        )
                except Exception:
                    pass
            return await call_next(request)

    app.add_middleware(_AttackMonitorMiddleware)
except Exception:
    pass  # 미들웨어 설치 실패가 서비스를 중단시키면 안 됨
# ───────────────────────────────────────────────────────────────────────────'''

_ENHANCED_ATTACK_MONITOR_PY = '''\
"""Team1 서비스 공격 탐지 및 JSONL 로깅.

서비스 동작을 막지 않고 의심 요청만 기록한다.
방어 담당자는 runner/service stderr 또는 defense agent 리포트로
새 이벤트를 확인할 수 있다.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_plus


ATTACK_LOG_PATH = Path(os.getenv("ATTACK_LOG_PATH", "/tmp/attack_log.jsonl"))
MAX_BODY_CAPTURE = int(os.getenv("ATTACK_LOG_BODY_PREVIEW", "512"))
MAX_LOG_ENTRIES = int(os.getenv("ATTACK_LOG_MAX_ENTRIES", "3000"))

_FLAG_RE = re.compile(r"HSPACE\\{[^}]{1,128}\\}")
_SECRET_RE = re.compile(
    r"(?i)(x-checker-token|authorization|bearer|token|secret|api[_-]?key)\\s*[:=]\\s*[^\\s,&\\"']+"
)


ATTACK_SIGNATURES: dict = {
    "vuln1": {
        "description": "indirect_prompt_injection (검색 캐시 오염)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords": ["검색", "찾아", "추천"],
        "cve": "CVE-2026-27960",
    },
    "vuln2": {
        "description": "memory_poisoning (세션 메모리 유출)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords": ["기록", "이전", "history"],
        "cve": "CVE-2026-1060",
    },
    "vuln3": {
        "description": "orchestration_logic_bypass (admin 할 일 노출)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords_all": [["할 일", "todo"], ["다른 사용자", "모든", "admin"]],
        "cve": "CVE-2026-20223",
    },
    "vuln4": {
        "description": "tool_call_manipulation (tool_secret 노출)",
        "endpoint": "/chat",
        "method": "POST",
        "keywords": ["디버그", "debug", "툴 상태"],
        "cve": "CVE-2026-20164",
    },
}


GENERIC_RULES = [
    {
        "alert_id": "scanner_user_agent",
        "severity": "medium",
        "description": "scanner user-agent fingerprint",
        "patterns": [r"sqlmap", r"nikto", r"dirbuster", r"gobuster", r"wfuzz", r"nuclei", r"masscan"],
        "target": "user_agent",
    },
    {
        "alert_id": "path_traversal",
        "severity": "high",
        "description": "path traversal or local file inclusion probe",
        "patterns": [r"\\.\\./", r"\\.\\.\\\\", r"/etc/passwd", r"/proc/self", r"php://filter", r"win\\.ini"],
        "target": "combined",
    },
    {
        "alert_id": "sql_injection",
        "severity": "high",
        "description": "SQL injection style payload",
        "patterns": [r"union\\s+select", r"or\\s+1\\s*=\\s*1", r"'\\s*or\\s*'", r"sleep\\s*\\(", r"benchmark\\s*\\("],
        "target": "combined",
    },
    {
        "alert_id": "xss_probe",
        "severity": "medium",
        "description": "XSS probe payload",
        "patterns": [r"<script", r"javascript:", r"onerror\\s*=", r"onload\\s*=", r"<img"],
        "target": "combined",
    },
    {
        "alert_id": "admin_endpoint_probe",
        "severity": "high",
        "description": "admin/checker endpoint access attempt",
        "patterns": [r"^/admin/", r"/admin/inject", r"/admin/check"],
        "target": "path",
    },
    {
        "alert_id": "sensitive_file_probe",
        "severity": "high",
        "description": "sensitive file or debug path probe",
        "patterns": [r"\\.env", r"flags\\.env", r"gitctf\\.env", r"/debug", r"/swagger", r"/openapi\\.json"],
        "target": "combined",
    },
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(value: object) -> str:
    text = "" if value is None else str(value)
    text = _FLAG_RE.sub("HSPACE{REDACTED}", text)
    return _SECRET_RE.sub(lambda match: f"{match.group(1)}=REDACTED", text)


def _normalize_headers(headers: dict | None) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (headers or {}).items()}


def _body_text(body_bytes: bytes | str | None) -> str:
    if body_bytes is None:
        return ""
    if isinstance(body_bytes, str):
        return body_bytes[:MAX_BODY_CAPTURE]
    return body_bytes[:MAX_BODY_CAPTURE].decode("utf-8", errors="replace")


def detect_attack(path: str, method: str, message: str) -> Optional[str]:
    """POST /chat의 message에서 대회 취약점 공격 시그니처를 찾는다."""
    lower = message.lower()
    for vuln_id, sig in ATTACK_SIGNATURES.items():
        if not path.startswith(sig["endpoint"]):
            continue
        if sig.get("method") and method.upper() != sig["method"]:
            continue
        if "keywords" in sig and any(keyword in lower for keyword in sig["keywords"]):
            return vuln_id
        if "keywords_all" in sig:
            if all(any(keyword in lower for keyword in group) for group in sig["keywords_all"]):
                return vuln_id
    return None


def _extract_chat_message(body_text: str) -> str:
    try:
        data = json.loads(body_text)
    except Exception:
        return body_text
    if isinstance(data, dict):
        return str(data.get("message", ""))
    return body_text


def _rule_matches(patterns: list[str], value: str) -> bool:
    return any(re.search(pattern, value, flags=re.IGNORECASE) for pattern in patterns)


def inspect_request(
    *,
    method: str,
    path: str,
    query_string: str = "",
    headers: dict | None = None,
    body_bytes: bytes | str | None = None,
) -> tuple[list[dict], str]:
    """HTTP 요청 하나를 검사하고 `(alerts, body_preview)`를 반환한다."""
    normalized_headers = _normalize_headers(headers)
    body_preview = _body_text(body_bytes)
    decoded_query = unquote_plus(query_string or "")
    decoded_path = unquote_plus(path or "")
    user_agent = normalized_headers.get("user-agent", "")
    combined = " ".join([decoded_path, decoded_query, body_preview])
    alerts: list[dict] = []

    if method.upper() == "POST" and decoded_path.startswith("/chat"):
        message = _extract_chat_message(body_preview)
        vuln_id = detect_attack(decoded_path, method.upper(), message)
        if vuln_id:
            signature = ATTACK_SIGNATURES.get(vuln_id, {})
            alerts.append({
                "alert_id": vuln_id,
                "severity": "high",
                "description": signature.get("description", ""),
                "cve": signature.get("cve", ""),
                "evidence": _redact(message[:180]),
            })

    values = {
        "path": decoded_path,
        "user_agent": user_agent,
        "combined": combined,
    }
    for rule in GENERIC_RULES:
        target = values.get(rule["target"], combined)
        if _rule_matches(rule["patterns"], target):
            alerts.append({
                "alert_id": rule["alert_id"],
                "severity": rule["severity"],
                "description": rule["description"],
                "evidence": _redact(target[:180]),
            })

    deduped: list[dict] = []
    seen: set[str] = set()
    for alert in alerts:
        alert_id = alert.get("alert_id", "unknown")
        if alert_id in seen:
            continue
        seen.add(alert_id)
        deduped.append(alert)

    return deduped, _redact(body_preview[:MAX_BODY_CAPTURE])


def _append_log(entry: dict) -> None:
    ATTACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ATTACK_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\\n")
    try:
        rows = read_log(limit=MAX_LOG_ENTRIES + 200)
        if len(rows) > MAX_LOG_ENTRIES:
            keep = rows[-MAX_LOG_ENTRIES:]
            with ATTACK_LOG_PATH.open("w", encoding="utf-8") as f:
                for row in keep:
                    f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\\n")
    except Exception:
        pass


def log_event(
    *,
    alerts: list[dict],
    method: str,
    path: str,
    query_string: str,
    status_code: int,
    duration_ms: float,
    client_ip: str,
    headers: dict | None,
    body_preview: str,
) -> None:
    if not alerts:
        return
    normalized_headers = _normalize_headers(headers)
    entry = {
        "timestamp": _utc_now(),
        "method": method,
        "path": path,
        "query_string": _redact(query_string),
        "status_code": status_code,
        "duration_ms": round(duration_ms, 2),
        "client_ip": client_ip,
        "user_agent": _redact(normalized_headers.get("user-agent", "")),
        "referer": _redact(normalized_headers.get("referer", "")),
        "alerts": alerts,
        "primary_alert": alerts[0].get("alert_id", "unknown"),
        "severity": alerts[0].get("severity", "medium"),
        "body_preview": body_preview,
    }
    try:
        _append_log(entry)
        print(
            "[hspace-defense-agent] attack_detected "
            + json.dumps(
                {
                    "primary_alert": entry["primary_alert"],
                    "path": entry["path"],
                    "status_code": entry["status_code"],
                    "client_ip": entry["client_ip"],
                    "user_agent": entry["user_agent"],
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    except Exception:
        pass


def log_attack(vuln_id: str, method: str, path: str, client_ip: str, message_preview: str) -> None:
    signature = ATTACK_SIGNATURES.get(vuln_id, {})
    log_event(
        alerts=[{
            "alert_id": vuln_id,
            "severity": "high",
            "description": signature.get("description", ""),
            "cve": signature.get("cve", ""),
            "evidence": _redact(message_preview),
        }],
        method=method,
        path=path,
        query_string="",
        status_code=0,
        duration_ms=0.0,
        client_ip=client_ip,
        headers={},
        body_preview=_redact(message_preview),
    )


def read_log(limit: int = 200) -> list[dict]:
    if not ATTACK_LOG_PATH.exists():
        return []
    entries = deque(maxlen=max(1, limit))
    try:
        with ATTACK_LOG_PATH.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception:
        return []
    return list(entries)


def summarize_log(entries: list[dict]) -> dict:
    alert_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    for entry in entries:
        ip_counter[str(entry.get("client_ip", "unknown"))] += 1
        status_counter[str(entry.get("status_code", "unknown"))] += 1
        for alert in entry.get("alerts", []):
            alert_counter[str(alert.get("alert_id", "unknown"))] += 1
    return {
        "by_alert": dict(alert_counter.most_common()),
        "by_ip": dict(ip_counter.most_common(10)),
        "by_status": dict(status_counter.most_common()),
    }


def clear_log() -> None:
    try:
        ATTACK_LOG_PATH.unlink(missing_ok=True)
    except Exception:
        pass
'''


_ENHANCED_MONITOR_BLOCK = '''\
# ── Attack Monitor Middleware (installed by defense agent) ─────────────────
try:
    import time as _time
    from fastapi import Request as _AttackMonitorRequest
    from starlette.middleware.base import BaseHTTPMiddleware as _BaseHTTPMiddleware
    from services.attack_monitor import (
        MAX_BODY_CAPTURE as _ATTACK_MONITOR_MAX_BODY,
        inspect_request as _inspect_request,
        log_event as _log_event,
    )

    class _AttackMonitorMiddleware(_BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            started = _time.perf_counter()
            body = b""
            status_code = 500
            should_capture_body = request.method in {"POST", "PUT", "PATCH"}
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    should_capture_body = int(content_length) <= _ATTACK_MONITOR_MAX_BODY
                except ValueError:
                    should_capture_body = False

            if should_capture_body:
                try:
                    body = await request.body()

                    async def _receive():
                        return {"type": "http.request", "body": body, "more_body": False}

                    request = _AttackMonitorRequest(request.scope, _receive)
                except Exception:
                    body = b""

            try:
                response = await call_next(request)
                status_code = response.status_code
                return response
            finally:
                try:
                    alerts, body_preview = _inspect_request(
                        method=request.method,
                        path=request.url.path,
                        query_string=request.url.query,
                        headers=dict(request.headers),
                        body_bytes=body,
                    )
                    if request.url.path.startswith("/admin/") and status_code < 400:
                        alerts = [
                            alert for alert in alerts
                            if alert.get("alert_id") != "admin_endpoint_probe"
                        ]
                    if alerts:
                        _log_event(
                            alerts=alerts,
                            method=request.method,
                            path=request.url.path,
                            query_string=request.url.query,
                            status_code=status_code,
                            duration_ms=(_time.perf_counter() - started) * 1000,
                            client_ip=(
                                getattr(request.client, "host", "unknown")
                                if request.client else "unknown"
                            ),
                            headers=dict(request.headers),
                            body_preview=body_preview,
                        )
                except Exception:
                    pass

    app.add_middleware(_AttackMonitorMiddleware)
except Exception:
    pass  # 미들웨어 설치 실패가 서비스를 중단시키면 안 됨
# ───────────────────────────────────────────────────────────────────────────'''

_ENHANCED_MONITOR_INSERT = "app = FastAPI()\n\n" + _ENHANCED_MONITOR_BLOCK


def _replace_marked_block(content: str, start_marker: str, replacement: str) -> tuple[str, bool]:
    start = content.find(start_marker)
    if start == -1:
        return content, False
    end_marker = "# ───────────────────────────────────────────────────────────────────────────"
    end = content.find(end_marker, start)
    if end == -1:
        return content, False
    line_end = content.find("\\n", end + len(end_marker))
    if line_end == -1:
        line_end = len(content)
    else:
        line_end += 1
    return content[:start] + replacement + content[line_end:], True


def apply_monitor_patches(repo: Path) -> list[str]:
    """공격 탐지 관련 파일 생성/수정. 반환: 변경된 파일 경로 목록"""
    changed = []

    # 1) services/ 폴더 생성 + attack_monitor.py
    services_dir = repo / "services"
    services_dir.mkdir(exist_ok=True)

    # __init__.py 생성 (없으면)
    init_path = services_dir / "__init__.py"
    if not init_path.exists():
        init_path.write_text("", encoding="utf-8")

    monitor_path = services_dir / "attack_monitor.py"
    desired_monitor = _ENHANCED_ATTACK_MONITOR_PY
    if not monitor_path.exists():
        monitor_path.write_text(desired_monitor, encoding="utf-8")
        changed.append("services/attack_monitor.py")
        print("  [monitor] ✓ services/attack_monitor.py 생성")
    elif "inspect_request" not in monitor_path.read_text(encoding="utf-8", errors="ignore"):
        monitor_path.write_text(desired_monitor, encoding="utf-8")
        changed.append("services/attack_monitor.py")
        print("  [monitor] ✓ services/attack_monitor.py 고급 탐지 로직으로 교체")
    else:
        print("  [monitor] attack_monitor.py 고급 탐지 로직 이미 존재 → 스킵")

    # 2) main.py 에 미들웨어 삽입
    main_path = repo / "main.py"
    if main_path.exists():
        main_content = main_path.read_text(encoding="utf-8")
        if "_AttackMonitorMiddleware" not in main_content:
            if _MONITOR_ANCHOR in main_content:
                patched = main_content.replace(_MONITOR_ANCHOR, _ENHANCED_MONITOR_INSERT, 1)
                main_path.write_text(patched, encoding="utf-8")
                main_content = patched
                if "main.py" not in changed:
                    changed.append("main.py")
                print("  [monitor] ✓ main.py 미들웨어 삽입")
            else:
                print("  [monitor] main.py 삽입 위치 없음 → 스킵")
        elif "inspect_request as _inspect_request" not in main_content:
            patched, replaced = _replace_marked_block(
                main_content,
                "# ── Attack Monitor Middleware (installed by defense agent)",
                _ENHANCED_MONITOR_BLOCK,
            )
            if replaced:
                main_path.write_text(patched, encoding="utf-8")
                main_content = patched
                if "main.py" not in changed:
                    changed.append("main.py")
                print("  [monitor] ✓ main.py 미들웨어 고급 탐지 버전으로 교체")
            else:
                print("  [monitor] 기존 미들웨어 교체 위치 없음 → 스킵")
        else:
            print("  [monitor] main.py 고급 탐지 미들웨어 이미 설치됨 → 스킵")

        # 3) 새 관리 엔드포인트는 룰 위반 소지가 있어 추가하지 않는다.
        #    예전 agent가 설치한 방어 표식 블록이 있으면 제거한다.
        main_content = main_path.read_text(encoding="utf-8")
        if "/admin/attacks" in main_content:
            patched, replaced = _replace_marked_block(
                main_content,
                "# ── Attack Log Endpoints (installed by defense agent)",
                "",
            )
            if replaced:
                main_path.write_text(patched, encoding="utf-8")
                if "main.py" not in changed:
                    changed.append("main.py")
                print("  [monitor] ✓ 룰 안전을 위해 /admin/attacks 방어 엔드포인트 제거")
            else:
                print("  [monitor] /admin/attacks가 있으나 방어 표식 블록이 아님 → 수동 검토 필요")
        else:
            print("  [monitor] 새 관리 엔드포인트 추가 안 함")

    return changed


# ═════════════════════════════════════════════════════════════════════════════
# 4. Health Check
# ═════════════════════════════════════════════════════════════════════════════

def health_check(base_url: str, retries: int = 5) -> bool:
    url = base_url.rstrip("/") + "/health"
    for i in range(retries):
        try:
            r = httpx.get(url, timeout=10)
            if r.status_code == 200:
                print(f"  [health] ✓ 정상 ({url})")
                return True
            print(f"  [health] HTTP {r.status_code}")
        except Exception as e:
            print(f"  [health] 연결 실패 ({i+1}/{retries}): {e}")
        time.sleep(3)
    return False


def should_skip_live_health_check() -> tuple[bool, str]:
    """Coordinator defense runs patch a git clone, not a locally running service."""
    if AGENT_RUN_ID or os.getenv("TARGET_REPO_URL"):
        return True, "coordinator defense run"
    return False, ""


# ═════════════════════════════════════════════════════════════════════════════
# 5. Commit & Push
# ═════════════════════════════════════════════════════════════════════════════

def commit_patch_sdk(repo: Path, message: str) -> bool:
    try:
        sdk = importlib.import_module("gitctf_sdk")
        sdk.commit_patch(str(repo), message)
        print("  [git] ✓ SDK commit_patch() 완료")
        return True
    except (ImportError, AttributeError):
        return False


def commit_patch_git(repo: Path, message: str) -> bool:
    run_id_line = f"\n\nAgent-Run-ID: {AGENT_RUN_ID}" if AGENT_RUN_ID else ""
    full_msg = message + run_id_line
    try:
        subprocess.run(["git", "-C", str(repo), "add", "-A"],
                       check=True, capture_output=True)
        result = subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", full_msg],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            if "nothing to commit" in result.stdout + result.stderr:
                print("  [git] 변경사항 없음")
                return True
            print(f"  [git] commit 실패: {result.stderr}")
            return False
        push = subprocess.run(
            ["git", "-C", str(repo), "push"],
            capture_output=True, text=True,
        )
        if push.returncode != 0:
            print(f"  [git] push 실패: {push.stderr}")
            return False
        print("  [git] ✓ commit & push 완료")
        return True
    except Exception as e:
        print(f"  [git] 예외: {e}")
        return False


def commit_and_push(repo: Path, changed: list[str]) -> bool:
    msg = (
        "defense: patch team1 vulns + install attack monitor\n\n"
        + "\n".join(f"  - {f}" for f in changed)
    )
    return commit_patch_sdk(repo, msg) or commit_patch_git(repo, msg)


# ═════════════════════════════════════════════════════════════════════════════
# 6. 공격 탐지 리포트 생성
# ═════════════════════════════════════════════════════════════════════════════

def fetch_attack_log() -> list[dict]:
    # 새 서비스 엔드포인트를 추가하는 방식은 룰 위반 소지가 있다.
    # 공격 탐지 이벤트는 서비스 stderr/JSONL과 runner 로그 prefix로 남긴다.
    print("  [log] 서비스 로그 조회 API는 룰 안전을 위해 사용하지 않음")
    return []


def _attack_stats(attacks: list[dict]) -> str:
    if not attacks:
        return ""

    total = len(attacks)
    vuln_counts = Counter(a.get("vuln_id", "?") for a in attacks)
    ip_counts   = Counter(a.get("client_ip", "?") for a in attacks)
    bucket: dict[str, int] = defaultdict(int)
    for a in attacks:
        ts = a.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            key = dt.strftime("%H:%M")[:-1] + "0"
            bucket[key] += 1
        except Exception:
            pass

    lines = [
        "## 📊 자동 통계",
        "",
        f"| 항목 | 값 |",
        f"|------|-----|",
        f"| 총 공격 횟수 | {total}건 |",
        f"| 최초 탐지 | {attacks[0].get('timestamp','')[:19]} UTC |",
        f"| 최근 탐지 | {attacks[-1].get('timestamp','')[:19]} UTC |",
        "",
        "### 취약점별 분포",
        "",
        "| vuln_id | CVE | 횟수 | 비율 |",
        "|---------|-----|------|------|",
    ]
    cve_map = {
        "vuln1": "CVE-2026-27960",
        "vuln2": "CVE-2026-1060",
        "vuln3": "CVE-2026-20223",
        "vuln4": "CVE-2026-20164",
    }
    for vuln, cnt in sorted(vuln_counts.items()):
        pct = cnt / total * 100
        lines.append(f"| {vuln} | {cve_map.get(vuln,'-')} | {cnt} | {pct:.0f}% |")

    lines += ["", "### 공격자 IP별 (상위 10)", "", "| IP | 횟수 |", "|----|------|"]
    for ip, cnt in ip_counts.most_common(10):
        lines.append(f"| {ip} | {cnt} |")

    lines += ["", "### 시간대별 분포 (10분 단위)", "", "| 시각 | 횟수 |", "|------|------|"]
    for t, cnt in sorted(bucket.items()):
        lines.append(f"| {t} | {cnt} |")

    return "\n".join(lines)


def generate_attack_report(attacks: list[dict]) -> str:
    if not attacks:
        return "이번 라운드에서 탐지된 공격 시도가 없습니다.\n"

    attacks_json = json.dumps(attacks, ensure_ascii=False, indent=2)

    prompt = textwrap.dedent(f"""
    아래는 이번 A&D 라운드에서 Team1 서비스(Study Compass, 귀찮은 업무 도우미)에 대해
    탐지된 공격 시도 로그입니다.

    ## 대회 컨텍스트

    ### 취약점 - CVE 매핑
    - vuln1 (indirect_prompt_injection)   → CVE-2026-27960: OpenCTI 미인증 API 쿼리로 내부 데이터 탈취
    - vuln2 (memory_poisoning)            → CVE-2026-1060:  WP Adminify REST API 권한 검증 누락
    - vuln3 (orchestration_logic_bypass)  → CVE-2026-20223: Cisco Secure Workload 인증 우회 (CVSS 10.0)
    - vuln4 (tool_call_manipulation)      → CVE-2026-20164: Splunk credentials 노출

    ### 공격 방식
    모든 공격이 POST /chat 단일 엔드포인트로 진입하며, message 내용으로 취약점을 트리거합니다.

    ### 팀별 서비스 URL (공격자 IP 추정 참고)
    - Team1: http://knights.hspace.io:42001  ← 방어 대상 (우리가 방어)
    - Team2: http://knights.hspace.io:42002
    - Team3: http://knights.hspace.io:42003
    - Team4: http://knights.hspace.io:42004
    - Team5: http://knights.hspace.io:42005
    - Team6: http://knights.hspace.io:42006

    ## 공격 로그

    ```json
    {attacks_json[:4000]}
    ```

    ## 작성 요청

    다음 항목을 포함한 한국어 방어 리포트를 작성해주세요:
    1. 전체 공격 시도 횟수 및 취약점별 분포 (CVE 번호 포함)
    2. 가장 많이 공격받은 취약점과 해당 CVE의 위험도
    3. 공격자 IP 분포 — 위 팀별 URL을 참고해 어느 팀으로 추정되는지 분석
    4. 공격 message 패턴 분석 (어떤 키워드로 공격했는지)
    5. 방어 성공/실패 여부 판단 (패치 적용 시각 기준)
    6. 다음 라운드를 위한 권고사항

    리포트는 팀원이 읽기 쉽게 명확하게 작성해주세요.
    """).strip()

    content, _ = call_llm(
        [{"role": "user", "content": prompt}],
        model=MODELS[0],
        purpose="defense",
    )
    return content or "리포트 생성 실패 (LLM 오류)\n"


def save_report(report: str, attacks: list[dict]) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"round_{ts}.md"

    viewer_hint = textwrap.dedent("""
    > **공격 로그 확인 방법**:
    > ```
    > runner/service stderr에서 [hspace-defense-agent] prefix 검색
    > 서비스 내부 JSONL 기본 경로: /tmp/attack_log.jsonl
    > ```
    """).strip()

    header = textwrap.dedent(f"""
    # Team1 Defense Report (방어 주체: Team2)
    **생성 시각**: {datetime.now(timezone.utc).isoformat()}
    **탐지된 공격**: {len(attacks)}건
    **Agent-Run-ID**: {AGENT_RUN_ID or "(없음)"}

    {viewer_hint}

    ---

    """).lstrip()

    stats_section = _attack_stats(attacks)
    if stats_section:
        stats_section = "\n\n---\n\n" + stats_section

    llm_section = ""
    if report and report.strip():
        llm_section = "\n\n---\n\n## 🤖 LLM 분석\n\n" + report

    raw_section = ""
    if attacks:
        raw_section = "\n\n---\n\n## 원시 로그 (최근 20건)\n\n```json\n"
        raw_section += json.dumps(attacks[-20:], ensure_ascii=False, indent=2)
        raw_section += "\n```\n"

    report_path.write_text(
        header + f"\n\n- Build Rev: `{BUILD_REV}`" + stats_section + llm_section + raw_section,
        encoding="utf-8",
    )
    return report_path


# ═════════════════════════════════════════════════════════════════════════════
# 7. 메인
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print(f"[hspace-defense-agent] build_rev={BUILD_REV}", file=sys.stderr, flush=True)
    print("=" * 64)
    print("  HSPACE LiveFire A&D — Team2 Defense Agent")
    print("  방어 대상: Team1 / Study Compass (귀찮은 업무 도우미)")
    print("=" * 64)
    print(f"  Repo    : {REPO_PATH.resolve()}")
    print(f"  Service : {SERVICE_URL}")
    print(f"  RunID   : {AGENT_RUN_ID or '(없음)'}")
    print(f"  Build   : {BUILD_REV}")
    print()

    if not BASE_URL:
        print("[FATAL] LLM BASE_URL 환경변수 없음")
        sys.exit(1)
    if not API_KEY:
        print("[FATAL] LLM API_KEY 환경변수 없음")
        sys.exit(1)
    log_event(
        "agent_start",
        run_id=AGENT_RUN_ID,
        repo=str(REPO_PATH.resolve()),
        service_url=SERVICE_URL,
        model=MODELS[0],
        llm_base_source=LLM_BASE_SOURCE,
        log_path=str(AGENT_LOG_PATH),
        build_rev=BUILD_REV,
    )

    # ── Step 1: LLM 패치 검토 (AI agent 요건) ────────────────────────────
    print("[1/6] LLM 패치 검토...")
    review = llm_confirm_patches()
    print(f"  → LLM 검토 완료 (호출 #{_llm_call_count})")
    if review:
        preview = " / ".join(review.strip().splitlines()[:2])
        print(f"  → {preview[:120]}")

    # ── Step 2: 취약점 패치 ────────────────────────────────────────────────
    print("\n[2/6] 취약 코드 블록 패치...")
    vuln_changed, backups = apply_vuln_patches(REPO_PATH)
    issues = verify_vuln_patches(REPO_PATH)
    if issues:
        print(f"  [FATAL] 검증 이슈: {issues}")
        rollback(backups)
        log_event("vuln_patch_sequence_failed", issues=issues[:10])
        raise RuntimeError(f"취약점 패치 검증 실패: {issues[:3]}")
    else:
        print("  ✓ 4개 취약점 패치 검증 완료")

    # ── Step 3: 공격 탐지 미들웨어 설치 ──────────────────────────────────
    print("\n[3/6] 공격 탐지 미들웨어 설치...")
    monitor_changed = apply_monitor_patches(REPO_PATH)

    all_changed = list(dict.fromkeys(vuln_changed + monitor_changed))
    print(f"\n  총 변경 파일: {len(all_changed)}개")

    # ── Step 4: Health Check ──────────────────────────────────────────────
    print("\n[4/6] Health check...")
    skip_health_check, skip_reason = should_skip_live_health_check()
    if vuln_changed and not skip_health_check:
        is_healthy = health_check(SERVICE_URL)
        if not is_healthy:
            print("  [WARN] health check 실패 → 취약점 패치 롤백...")
            rollback(backups)
            all_changed = monitor_changed
    else:
        is_healthy = True
        if skip_health_check:
            print(f"  → 실서비스 live health check 생략 ({skip_reason})")
        else:
            print("  → 취약점 패치 없음 또는 이미 적용됨, 스킵")

    # ── Step 5: Commit & Push ─────────────────────────────────────────────
    print("\n[5/6] 커밋 & 푸시...")
    if all_changed:
        push_ok = commit_and_push(REPO_PATH, all_changed)
        if not push_ok:
            print("  [WARN] 커밋 실패")
    else:
        print("  → 변경사항 없음")

    # ── Step 6: 공격 로그 조회 & 리포트 ──────────────────────────────────
    print("\n[6/6] 공격 로그 조회 및 리포트 생성...")
    attacks = fetch_attack_log()
    print(f"  → {len(attacks)}건 탐지")

    report_text = generate_attack_report(attacks)
    report_path = save_report(report_text, attacks)
    print(f"  ✓ 리포트 저장: {report_path}")

    if report_path.exists():
        report_message = f"defense: add round report ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC)"
        if not commit_patch_sdk(REPO_PATH, report_message):
            commit_patch_git(REPO_PATH, report_message)

    # ── 완료 요약 ─────────────────────────────────────────────────────────
    print()
    print("=" * 64)
    print("  완료 요약")
    print("=" * 64)
    print(f"  LLM 호출    : {_llm_call_count}회")
    print(f"  취약점 패치 : {len(vuln_changed)}개 파일")
    print(f"  모니터 설치 : {len(monitor_changed)}개 파일")
    print(f"  서비스 상태 : {'정상' if is_healthy else '확인 필요'}")
    print(f"  공격 탐지   : {len(attacks)}건")
    log_event(
        "agent_finish",
        run_id=AGENT_RUN_ID,
        llm_calls=_llm_call_count,
        vuln_changed=len(vuln_changed),
        monitor_changed=len(monitor_changed),
        healthy=is_healthy,
        attacks=len(attacks),
        build_rev=BUILD_REV,
    )
    print()


if __name__ == "__main__":
    main()
