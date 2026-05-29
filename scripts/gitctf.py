#!/usr/bin/env python3
"""LiveFire A&D participant and organizer CLI."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse


GITCTF_TRUSTED_BOOTSTRAP = True
REMOTE_NAME = "organizer"
CONFIG_PATH = Path(os.getenv("GITCTF_CONFIG", "~/.config/hspace-gitctf/config.json")).expanduser()
UPDATE_CACHE_DIR = Path(os.getenv("GITCTF_CACHE_DIR", "~/.cache/hspace-gitctf")).expanduser()
DEFAULT_UPDATE_URL = ""
AGENT_PATHS = (
    "attack_agent",
    "defense_agent",
    "defence_agent",
    "agent_sdk",
    "agent_manifest.json",
)
COMMON_FLOW = """참가자 기본 흐름:
  1. 팀 로그인 저장
     python scripts/gitctf.py login team1 --token <TEAM_TOKEN> --coordinator http://knights.hspace.io:42000

  2. 서비스 폴더로 이동
     cd <서비스_폴더>

  3. 검증
     python ../scripts/gitctf.py check

  4. 제출
     python ../scripts/gitctf.py push

에이전트 기본 흐름:
  python scripts/gitctf.py agent build team1
  python scripts/gitctf.py agent doctor --mode attack

관리자 기본 흐름:
  python scripts/gitctf.py admin preflight --repeat 3
  python scripts/gitctf.py admin round next
  python scripts/gitctf.py admin status
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch_url(url: str, timeout: float = 5.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "hspace-gitctf/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _extract_cli_option(argv: list[str], name: str) -> str | None:
    prefix = f"{name}="
    for idx, item in enumerate(argv):
        if item == name and idx + 1 < len(argv):
            return argv[idx + 1]
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def _current_subcommand(argv: list[str]) -> str | None:
    commands = {"login", "check", "verify", "push", "submit"}
    for item in argv:
        if item in commands:
            return item
        if item.startswith("-"):
            continue
    return None


def _load_config_quietly() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _coordinator_from_argv(argv: list[str]) -> str | None:
    coordinator = (
        _extract_cli_option(argv, "--coordinator")
        or os.getenv("COORDINATOR_URL")
        or _load_config_quietly().get("coordinator")
    )
    if coordinator:
        return coordinator
    for path in (Path.cwd() / "gitctf.env", Path.cwd() / ".env"):
        if not path.exists():
            continue
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line.startswith("COORDINATOR_URL="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            continue
    return None


def _update_url_from_context(argv: list[str]) -> str | None:
    explicit = os.getenv("GITCTF_UPDATE_URL")
    if explicit:
        return explicit
    coordinator = _coordinator_from_argv(argv)
    if coordinator:
        return f"{coordinator.rstrip('/')}/tools/gitctf.py"
    return DEFAULT_UPDATE_URL or None


def _looks_like_gitctf_script(source: bytes) -> bool:
    return (
        b"GITCTF_TRUSTED_BOOTSTRAP = True" in source
        and b"def main()" in source
        and (b"LiveFire A&D participant" in source or b"Participant-facing LiveFire" in source)
    )


def _cache_tool(name: str, source: bytes, digest: str) -> Path:
    target_dir = UPDATE_CACHE_DIR / digest
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / name
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=target_dir) as fh:
        fh.write(source)
        tmp = Path(fh.name)
    tmp.replace(target)
    return target


def _maybe_cache_sibling(update_url: str, digest: str, name: str) -> Path | None:
    try:
        source = _fetch_url(urljoin(update_url, name), timeout=5.0)
    except Exception:
        local = Path(__file__).with_name(name)
        if not local.exists():
            return None
        source = local.read_bytes()
    return _cache_tool(name, source, digest)


def _support_script(name: str) -> Path:
    if name == "validate_vulns.py":
        override = os.getenv("GITCTF_VALIDATE_VULNS_PATH")
        if override and Path(override).exists():
            return Path(override)
    candidates = [Path(__file__).with_name(name)]
    source_dir = os.getenv("GITCTF_SOURCE_DIR")
    if source_dir:
        candidates.append(Path(source_dir) / name)
    for path in candidates:
        if path.exists():
            return path
    return candidates[0]


def _json_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: object | None = None,
    timeout: float = 30.0,
) -> dict:
    raw_body = None
    request_headers = dict(headers or {})
    if body is not None:
        raw_body = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=raw_body, headers=request_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"coordinator 연결 실패: {exc}") from exc
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def _coordinator_setting(cli_value: str | None = None) -> str:
    coordinator = cli_value or os.getenv("COORDINATOR_URL") or _load_config_quietly().get("coordinator") or "http://localhost:42000"
    _validate_coordinator(coordinator)
    return coordinator.rstrip("/")


def _admin_secret(cli_value: str | None = None) -> str:
    if cli_value:
        return cli_value
    if os.getenv("ADMIN_SECRET"):
        return os.environ["ADMIN_SECRET"]
    candidates = [
        Path.cwd() / "coordinator" / ".env",
        Path(__file__).resolve().parents[1] / "coordinator" / ".env",
    ]
    for path in candidates:
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("ADMIN_SECRET="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if value:
                    return value
    raise SystemExit("ADMIN_SECRET이 필요합니다. 환경변수로 넣거나 coordinator/.env를 확인하세요.")


def _admin_headers(secret: str) -> dict[str, str]:
    return {"X-Admin-Secret": secret}


def _self_update(argv: list[str]) -> None:
    if os.getenv("GITCTF_SELF_UPDATED") == "1":
        return
    subcommand = _current_subcommand(argv)
    if os.getenv("GITCTF_NO_SELF_UPDATE") == "1":
        if subcommand in {"push", "submit"} and os.getenv("GITCTF_ALLOW_STALE") != "1":
            raise SystemExit("push/submit은 공식 gitctf.py 최신본 확인을 건너뛸 수 없습니다.")
        return
    if not argv or "-h" in argv or "--help" in argv:
        return
    if argv[0] == "admin":
        return

    update_url = _update_url_from_context(argv)
    if not update_url:
        return

    require_update = os.getenv("GITCTF_REQUIRE_SELF_UPDATE") == "1" or subcommand in {"push", "submit"}
    try:
        source = _fetch_url(update_url, timeout=5.0)
        if not _looks_like_gitctf_script(source):
            raise RuntimeError(f"공식 gitctf.py 형식이 아닙니다: {update_url}")
        current = Path(__file__).read_bytes()
        remote_hash = _sha256(source)
        validate_path = None
        if subcommand in {"check", "verify"}:
            validate_path = _maybe_cache_sibling(update_url, remote_hash, "validate_vulns.py")
            if validate_path:
                os.environ["GITCTF_VALIDATE_VULNS_PATH"] = str(validate_path)
        if _sha256(current) == remote_hash:
            return
        cached = _cache_tool("gitctf.py", source, remote_hash)
        env = os.environ.copy()
        env["GITCTF_SELF_UPDATED"] = "1"
        env["GITCTF_SOURCE_DIR"] = str(Path(__file__).resolve().parent)
        if validate_path:
            env["GITCTF_VALIDATE_VULNS_PATH"] = str(validate_path)
        env["GITCTF_ORIGINAL"] = str(Path(__file__).resolve())
        print(f"[gitctf.py] 최신 공식 helper로 재실행합니다 ({remote_hash[:12]}).", flush=True)
        os.execve(sys.executable, [sys.executable, str(cached), *argv], env)
    except Exception as exc:
        if require_update and os.getenv("GITCTF_ALLOW_STALE") != "1":
            raise SystemExit(
                "공식 gitctf.py 최신본 확인에 실패했습니다.\n"
                f"업데이트 URL: {update_url}\n"
                f"오류: {exc}\n"
                "coordinator 주소와 네트워크를 확인하세요. 긴급 오프라인 제출만 GITCTF_ALLOW_STALE=1로 우회할 수 있습니다."
            ) from exc
        print(f"[gitctf.py] 최신본 확인 실패, 현재 파일로 계속합니다: {exc}", file=sys.stderr)


def _run(cmd: list[str], cwd: Path, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        env=env,
        text=True,
        capture_output=capture,
    )


def _git(cwd: Path, *args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=cwd, check=check, capture=capture)


def _has_git_repo(repo: Path) -> bool:
    if not (repo / ".git").exists():
        return False
    result = _git(repo, "rev-parse", "--is-inside-work-tree", check=False, capture=True)
    if result.returncode != 0 or result.stdout.strip() != "true":
        return False
    top = _git(repo, "rev-parse", "--show-toplevel", check=False, capture=True)
    return top.returncode == 0 and Path(top.stdout.strip()).resolve() == repo.resolve()


def _has_head(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--verify", "HEAD", check=False, capture=True).returncode == 0


def _require_file(repo: Path, name: str) -> None:
    if not (repo / name).exists():
        raise SystemExit(
            f"필수 파일이 없습니다: {name}\n"
            f"확인 위치: {repo}\n"
            "서비스 repo 루트에서 실행했는지 확인하거나 --repo로 서비스 폴더를 지정하세요."
        )


def _print_section(title: str) -> None:
    print(f"\n[{title}]", flush=True)


def _print_kv(label: str, value: object) -> None:
    print(f"  {label:<12} {value}", flush=True)


def _mask_token(token: str | None) -> str:
    if not token:
        return "(없음)"
    if len(token) <= 8:
        return "<hidden>"
    return f"{token[:4]}...{token[-4:]}"


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: invalid config file: {CONFIG_PATH}: {exc}") from exc


def _write_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    CONFIG_PATH.chmod(0o600)


def _load_env_file(path: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    if not path.exists():
        return loaded
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            loaded[key] = value
            os.environ.setdefault(key, value)
    return loaded


def _load_local_env(repo: Path) -> dict[str, str]:
    seen: set[Path] = set()
    loaded: dict[str, str] = {}
    for path in (
        Path.cwd() / "gitctf.env",
        repo / "gitctf.env",
        Path.cwd() / ".env",
        repo / ".env",
    ):
        resolved = path.resolve()
        if resolved not in seen:
            for key, value in _load_env_file(resolved).items():
                loaded.setdefault(key, value)
            seen.add(resolved)
    return loaded


def _resolve_setting(
    name: str,
    cli_value: str | None,
    env_name: str,
    config_key: str,
    config: dict,
    default: str | None = None,
    required: bool = True,
) -> str | None:
    value = cli_value or os.getenv(env_name) or config.get(config_key) or default
    if required and not value:
        raise SystemExit(
            f"{name} 값이 필요합니다.\n"
            f"해결: `python scripts/gitctf.py login team1 --token <TEAM_TOKEN> "
            f"--coordinator http://knights.hspace.io:42000`을 먼저 실행하거나 {env_name} 환경변수를 설정하세요."
        )
    return value


def _init_repo(repo: Path) -> None:
    if _has_git_repo(repo):
        return
    result = _git(repo, "init", "-b", "main", check=False)
    if result.returncode != 0:
        _git(repo, "init")
        _git(repo, "checkout", "-B", "main")


def _ensure_identity(repo: Path) -> None:
    if _git(repo, "config", "user.email", check=False, capture=True).returncode != 0:
        _git(repo, "config", "user.email", "hspace-team@example.invalid")
    if _git(repo, "config", "user.name", check=False, capture=True).returncode != 0:
        _git(repo, "config", "user.name", "HSPACE Team")


def _ensure_main_branch(repo: Path) -> None:
    branch = _git(repo, "branch", "--show-current", check=False, capture=True).stdout.strip()
    if branch != "main":
        _git(repo, "checkout", "-B", "main")


def _stage_and_commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    staged = _git(repo, "diff", "--cached", "--quiet", check=False)
    if staged.returncode == 0:
        if not _has_head(repo):
            raise SystemExit("커밋할 파일이 없고 기존 커밋도 없습니다. 서비스 파일을 먼저 추가하세요.")
        print("변경된 파일이 없습니다. 현재 HEAD를 그대로 제출합니다.", flush=True)
        return
    print(f"커밋 생성: {message}", flush=True)
    _git(repo, "commit", "-m", message)


def _set_remote(repo: Path, coordinator: str, repo_team: str) -> str:
    base = coordinator.rstrip("/")
    remote_url = f"{base}/git/{repo_team}"
    existing = _git(repo, "remote", "get-url", REMOTE_NAME, check=False, capture=True)
    if existing.returncode == 0:
        _git(repo, "remote", "set-url", REMOTE_NAME, remote_url)
    else:
        _git(repo, "remote", "add", REMOTE_NAME, remote_url)
    return remote_url


def _basic_auth_header(team: str, token: str) -> str:
    raw = f"{team}:{token}".encode("utf-8")
    return "Authorization: Basic " + base64.b64encode(raw).decode("ascii")


def _validate_coordinator(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("--coordinator는 http://knights.hspace.io:42000 같은 주소여야 합니다.")


def _coordinator_status(coordinator: str) -> dict:
    try:
        raw = _fetch_url(f"{coordinator.rstrip('/')}/status", timeout=5.0)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _has_agent_files(repo: Path) -> bool:
    return any((repo / path).exists() for path in AGENT_PATHS)


def _copy_agent_paths(src: Path, dst: Path) -> None:
    for rel in AGENT_PATHS:
        target = dst / rel
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()

    for rel in AGENT_PATHS:
        source = src / rel
        target = dst / rel
        if source.is_dir():
            ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache")
            shutil.copytree(source, target, ignore=ignore)
        elif source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def _push_agent_projection(
    repo: Path,
    remote_url: str,
    team: str,
    token: str,
    message: str,
) -> None:
    header = _basic_auth_header(team, token)
    with tempfile.TemporaryDirectory(prefix="hspace-agent-push-") as td:
        work = Path(td) / "repo"
        _git(
            Path(td),
            "-c",
            f"http.extraHeader={header}",
            "clone",
            "--branch",
            "main",
            "--single-branch",
            remote_url,
            str(work),
        )
        _copy_agent_paths(repo, work)
        _ensure_identity(work)
        _git(work, "add", "-A", ".")
        if _git(work, "diff", "--cached", "--quiet", check=False).returncode == 0:
            print("변경된 agent 파일이 없습니다. 서버 agent 상태를 그대로 유지합니다.", flush=True)
            return
        _git(work, "commit", "-m", message)
        _git(work, "-c", f"http.extraHeader={header}", "push", "origin", "HEAD:main")


def login(args: argparse.Namespace) -> int:
    _load_local_env(Path.cwd())
    config = _load_config()
    team = args.team or os.getenv("TEAM_ID") or config.get("team")
    if not team:
        raise SystemExit("ERROR: team is required, for example: python scripts/gitctf.py login team1")
    coordinator = args.coordinator or os.getenv("COORDINATOR_URL") or config.get("coordinator") or "http://localhost:42000"
    _validate_coordinator(coordinator)

    token = args.token or os.getenv("TEAM_TOKEN")
    if not token:
        if not sys.stdin.isatty():
            raise SystemExit("ERROR: token is required in non-interactive mode. Use --token or TEAM_TOKEN.")
        token = getpass.getpass("Team token: ")
    if not token:
        raise SystemExit("ERROR: empty token")

    config.update({"team": team, "token": token, "coordinator": coordinator})
    _write_config(config)
    _print_section("로그인 저장 완료")
    _print_kv("팀", team)
    _print_kv("coordinator", coordinator)
    _print_kv("토큰", _mask_token(token))
    _print_kv("설정 파일", CONFIG_PATH)
    _print_section("다음 단계")
    print("  cd <서비스_폴더>")
    print("  python ../scripts/gitctf.py check")
    print("  python ../scripts/gitctf.py push")
    return 0


def submit(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"서비스 폴더가 없습니다: {repo}")
    explicit_env = {
        key: os.environ[key]
        for key in ("TEAM_ID", "TEAM_TOKEN", "COORDINATOR_URL", "REPO_TEAM")
        if key in os.environ
    }
    local_env = _load_local_env(repo)
    config = _load_config()
    team = args.team or explicit_env.get("TEAM_ID") or config.get("team") or local_env.get("TEAM_ID")
    token = args.token or explicit_env.get("TEAM_TOKEN") or config.get("token") or local_env.get("TEAM_TOKEN")
    coordinator = (
        args.coordinator
        or explicit_env.get("COORDINATOR_URL")
        or config.get("coordinator")
        or local_env.get("COORDINATOR_URL")
        or "http://localhost:42000"
    )
    if not team:
        raise SystemExit(
            "team 값이 필요합니다.\n"
            "해결: `python scripts/gitctf.py login team1 --token <TEAM_TOKEN> "
            "--coordinator http://knights.hspace.io:42000`을 먼저 실행하세요."
        )
    if not token:
        raise SystemExit("token 값이 필요합니다. login을 먼저 실행하거나 TEAM_TOKEN 환경변수를 설정하세요.")
    _validate_coordinator(coordinator)
    _require_file(repo, "Dockerfile")
    _require_file(repo, "vuln_spec.json")

    repo_team = (
        args.repo_team
        or explicit_env.get("REPO_TEAM")
        or local_env.get("REPO_TEAM")
        or config.get("repo_team")
        or local_env.get("TEAM_ID")
        or team
    )
    _print_section("제출 준비")
    _print_kv("서비스 폴더", repo)
    _print_kv("제출 대상", repo_team)
    _print_kv("제출 팀", team)
    _print_kv("coordinator", coordinator)
    _print_kv("커밋 방식", "기존 HEAD 사용" if args.no_commit else "변경분 자동 커밋")

    _init_repo(repo)
    _ensure_identity(repo)
    _ensure_main_branch(repo)
    if not args.no_commit:
        _stage_and_commit(repo, args.message)
    elif not _has_head(repo):
        raise SystemExit("ERROR: --no-commit requires an existing HEAD commit")

    remote_url = _set_remote(repo, coordinator, repo_team)

    _print_section("git remote")
    _print_kv("이름", REMOTE_NAME)
    _print_kv("주소", remote_url)
    if args.dry_run:
        _print_section("dry run 완료")
        print("  여기까지 준비만 확인했습니다. 실제 push는 하지 않았습니다.")
        return 0

    _print_section("push 시작")
    header = _basic_auth_header(team, token)
    status = _coordinator_status(coordinator)
    service_locked = bool(status.get("round_active") or status.get("preflight_done"))
    agent_projection = _has_agent_files(repo) and (repo_team != team or service_locked)
    if agent_projection:
        _print_kv("모드", "agent-only")
        _push_agent_projection(repo, remote_url, team, token, args.message)
        _print_section("제출 완료")
        print("  agent 파일만 서버에 반영했습니다. coordinator가 agent 이미지를 빌드합니다.")
        return 0

    _git(repo, "-c", f"http.extraHeader={header}", "push", REMOTE_NAME, "HEAD:main")
    _print_section("제출 완료")
    print("  coordinator가 변경된 서비스/agent 파일을 검증한 뒤 반영합니다.")
    return 0


def verify(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"서비스 폴더가 없습니다: {repo}")
    _load_local_env(repo)
    _require_file(repo, "Dockerfile")
    spec = Path(args.spec).resolve() if args.spec else repo / "vuln_spec.json"
    if not spec.exists():
        raise SystemExit(f"vuln_spec.json을 찾을 수 없습니다: {spec}")

    _print_section("서비스 검증")
    _print_kv("서비스 폴더", repo)
    _print_kv("spec", spec)
    _print_kv("대상", f"http://{args.host}:{args.port}")
    poc_mode = bool(args.vuln or args.poc or any(getattr(args, f"poc{idx}") for idx in range(1, 5)))
    if not poc_mode:
        _print_kv("반복", f"{args.repeat}회")
    if poc_mode:
        _print_kv("PoC 검증", "사용")
        _print_kv("제한 시간", f"{args.poc_timeout}초")
        if args.vuln:
            _print_kv("취약점", args.vuln)
        if args.poc:
            _print_kv("PoC", args.poc)
        for idx in range(1, 5):
            poc = getattr(args, f"poc{idx}")
            if poc:
                _print_kv(f"poc{idx}", poc)

    cmd = [
        sys.executable,
        str(_support_script("validate_vulns.py")),
        "--spec",
        str(spec),
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--repeat",
        str(args.repeat),
        "--checker-token",
        args.checker_token,
    ]
    if args.vuln:
        cmd.extend(["--vuln", args.vuln])
    if args.poc:
        cmd.extend(["--poc", args.poc])
    for idx in range(1, 5):
        poc = getattr(args, f"poc{idx}")
        if poc:
            cmd.extend([f"--poc{idx}", poc])
    if args.poc_timeout:
        cmd.extend(["--poc-timeout", str(args.poc_timeout)])
    if args.save_report:
        cmd.extend(["--save-report", args.save_report])
    result = _run(cmd, cwd=repo, check=False)
    if result.returncode != 0:
        _print_section("검증 실패")
        if poc_mode:
            print("  PoC가 주입된 flag를 stdout의 마지막 non-empty line에 출력해야 PASS입니다.", file=sys.stderr)
            print("  PoC는 TARGET_HOST, TARGET_PORT, TARGET_TEAM, FLAG_ID 환경변수를 사용하세요.", file=sys.stderr)
        else:
            print("  vuln_spec.json에 선언된 4개 취약점이 모두 flag를 노출해야 제출 준비가 됩니다.", file=sys.stderr)
            print("  서비스를 실행 중인지, --host/--port가 맞는지, checker 요청이 서비스 구현과 맞는지 확인하세요.", file=sys.stderr)
    else:
        _print_section("검증 완료")
        print("  이제 `python ../scripts/gitctf.py push`로 제출할 수 있습니다.")
    return result.returncode


def admin_status(args: argparse.Namespace) -> int:
    coordinator = _coordinator_setting(args.coordinator)
    status = _json_request("GET", f"{coordinator}/status", timeout=10.0)
    board = _json_request("GET", f"{coordinator}/scoreboard", timeout=10.0)
    _print_section("운영 상태")
    _print_kv("coordinator", coordinator)
    _print_kv("round", f"{status.get('round')} / {status.get('total_rounds')}")
    _print_kv("active", status.get("round_active"))
    _print_section("점수")
    for row in board.get("scores", []):
        print(
            f"  {row['team_id']:<5} score={row['score']:<5} "
            f"service={row.get('service_status', 'UNKNOWN'):<7}"
        )
    return 0


def admin_preflight(args: argparse.Namespace) -> int:
    if args.admin_secret:
        os.environ["ADMIN_SECRET"] = args.admin_secret
    cmd = [
        sys.executable,
        str(_support_script("preflight_check.py")),
        "--coordinator",
        _coordinator_setting(args.coordinator),
        "--port",
        str(args.port),
        "--repeat",
        str(args.repeat),
        "--report",
        args.report,
    ]
    if args.hosts_file:
        cmd.extend(["--hosts-file", args.hosts_file])
    if args.skip_vuln:
        cmd.append("--skip-vuln")
    return _run(cmd, cwd=Path.cwd(), check=False).returncode


def _start_round(coordinator: str, secret: str, force: bool) -> dict:
    suffix = "?force=true" if force else ""
    return _json_request(
        "POST",
        f"{coordinator}/admin/start-round{suffix}",
        headers=_admin_headers(secret),
        timeout=300.0,
    )


def _end_round(coordinator: str, secret: str) -> dict:
    return _json_request(
        "POST",
        f"{coordinator}/admin/end-round",
        headers=_admin_headers(secret),
        timeout=300.0,
    )


def admin_round(args: argparse.Namespace) -> int:
    coordinator = _coordinator_setting(args.coordinator)
    secret = _admin_secret(args.admin_secret)
    action = args.action
    status = _json_request("GET", f"{coordinator}/status", timeout=10.0)

    if action in {"end", "next"} and status.get("round_active"):
        _print_section("라운드 종료")
        ended = _end_round(coordinator, secret)
        _print_kv("round", ended.get("round"))
        _print_kv("score_changes", ended.get("score_changes"))
    elif action == "end":
        print("진행 중인 라운드가 없습니다.")
        return 0

    if action in {"start", "next"}:
        _print_section("라운드 시작")
        started = _start_round(coordinator, secret, args.force)
        _print_kv("round", started.get("round"))
        _print_kv("message", started.get("message"))
        _print_kv("checker", started.get("checker"))
    return 0


def admin_bundle(args: argparse.Namespace) -> int:
    cmd = [sys.executable, str(_support_script("build_user_deploy.py"))]
    return _run(cmd, cwd=Path.cwd(), check=False).returncode


def agent_delegate(args: argparse.Namespace) -> int:
    if not args.agent_args:
        print("agent 명령 예시:")
        print("  python scripts/gitctf.py agent build team1")
        print("  python scripts/gitctf.py agent config team1")
        print("  python scripts/gitctf.py agent doctor --mode attack")
        print("  python scripts/gitctf.py agent run attack --team team1 --target team3 --token <TOKEN> --runner-secret <RUNNER_SECRET>")
        return 0
    cmd = [sys.executable, str(_support_script("agent.py")), *args.agent_args]
    return _run(cmd, cwd=Path.cwd(), check=False).returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HSPACE LiveFire A&D 단일 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=COMMON_FLOW,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    login_parser = sub.add_parser(
        "login",
        help="팀 토큰과 coordinator 주소를 저장",
        description="팀 토큰과 coordinator 주소를 저장합니다. 이후 check/push에서 반복 입력하지 않아도 됩니다.",
    )
    login_parser.add_argument("team", nargs="?", help="팀 ID, 예: team1")
    login_parser.add_argument("--token", help="팀 토큰. 생략하면 터미널에서 숨김 입력으로 받습니다.")
    login_parser.add_argument(
        "--coordinator",
        default=os.getenv("COORDINATOR_URL"),
        help="coordinator 주소. 기본값: COORDINATOR_URL, 저장된 설정, 또는 http://localhost:42000",
    )
    login_parser.set_defaults(func=login)

    check_parser = sub.add_parser(
        "check",
        aliases=["verify"],
        help="제출 전 서비스와 vuln_spec.json 검증",
        description=(
            "로컬에서 실행 중인 서비스를 vuln_spec.json 기준으로 검증합니다.\n"
            "서비스는 자유롭게 만든 웹 서비스이면 됩니다. 고정 API는 vuln_spec.json에 선언합니다.\n"
            "PoC runner 계약 디버깅이 필요하면 --vuln 1 --poc poc.py를 추가합니다."
        ),
    )
    check_parser.add_argument("--repo", default=".", help="서비스 repo 경로. 기본값: 현재 폴더")
    check_parser.add_argument("--spec", help="vuln_spec.json 경로. 기본값: <repo>/vuln_spec.json")
    check_parser.add_argument("--host", default="localhost", help="실행 중인 서비스 host. 기본값: localhost")
    check_parser.add_argument("--port", type=int, default=8000, help="실행 중인 서비스 port. 기본값: 8000")
    check_parser.add_argument("--repeat", type=int, default=3, help="취약점당 반복 횟수. 모든 시도가 성공해야 PASS")
    check_parser.add_argument(
        "--checker-token",
        default=os.getenv("CHECKER_TOKEN", "validate-test-token"),
        help="checker 인증 토큰. 기본값: CHECKER_TOKEN 또는 validate-test-token",
    )
    check_parser.add_argument("--vuln", help="PoC로 검증할 취약점 번호. 예: 1 또는 vuln1")
    check_parser.add_argument("--poc", help="--vuln으로 지정한 취약점을 검증할 PoC 파일")
    for idx in range(1, 5):
        check_parser.add_argument(
            f"--poc{idx}",
            nargs="?",
            const=f"poc{idx}.py",
            help=argparse.SUPPRESS,
        )
    check_parser.add_argument("--poc-timeout", type=int, default=40, help="PoC 실행 제한 시간(초). 기본값: 40")
    check_parser.add_argument("--save-report", help="검증 결과 JSON 저장 경로")
    check_parser.set_defaults(func=verify)

    push_parser = sub.add_parser(
        "push",
        aliases=["submit"],
        help="서비스 repo를 commit 후 coordinator에 제출",
        description=(
            "서비스 repo를 main 브랜치로 정리한 뒤 coordinator git remote에 push합니다.\n"
            "팀 토큰은 git config에 저장하지 않고 push 명령에만 임시로 붙입니다."
        ),
    )
    push_parser.add_argument("--repo", default=".", help="서비스 repo 경로. 기본값: 현재 폴더")
    push_parser.add_argument("--team", default=None, help="제출 팀 ID. 기본값: TEAM_ID 또는 login 저장값")
    push_parser.add_argument(
        "--repo-team",
        default=None,
        help="push할 repo 소유 팀. 기본값: --team. 방어 패치 제출 때 사용합니다.",
    )
    push_parser.add_argument("--token", default=None, help="팀 토큰. 기본값: TEAM_TOKEN 또는 login 저장값")
    push_parser.add_argument(
        "--coordinator",
        default=None,
        help="coordinator 주소. 기본값: COORDINATOR_URL 또는 login 저장값",
    )
    push_parser.add_argument("--message", default="Submit service", help="자동 커밋 메시지")
    push_parser.add_argument("--no-commit", action="store_true", help="자동 커밋 없이 현재 HEAD를 제출")
    push_parser.add_argument("--dry-run", action="store_true", help="커밋/remote 준비만 하고 실제 push는 하지 않음")
    push_parser.set_defaults(func=submit)

    agent_parser = sub.add_parser(
        "agent",
        help="attack/defense agent 빌드와 로컬 디버그",
        description=(
            "agent helper를 gitctf.py 안에서 실행합니다.\n"
            "예: python scripts/gitctf.py agent build team1\n"
            "예: python scripts/gitctf.py agent doctor --mode attack"
        ),
        epilog=(
            "주요 명령:\n"
            "  build team1                         attack/defense 이미지 빌드\n"
            "  config team1                        coordinator 설정용 이미지 이름 출력\n"
            "  doctor --mode attack                runner entrypoint 확인\n"
            "  run attack --team team1 --target team3 --token <TOKEN> --runner-secret <RUNNER_SECRET>\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    agent_parser.add_argument("agent_args", nargs=argparse.REMAINDER, help="agent helper에 넘길 인자")
    agent_parser.set_defaults(func=agent_delegate)

    admin_parser = sub.add_parser(
        "admin",
        help="운영자용 상태 확인, 사전검증, 라운드 전환",
        description="운영자가 자주 쓰는 명령을 한 곳에서 실행합니다.",
    )
    admin_sub = admin_parser.add_subparsers(dest="admin_command", metavar="<admin-command>")
    admin_sub.required = True

    status_parser = admin_sub.add_parser("status", help="coordinator와 점수판 상태 확인")
    status_parser.add_argument("--coordinator", default=None, help="기본값: COORDINATOR_URL 또는 http://localhost:42000")
    status_parser.set_defaults(func=admin_status)

    preflight_parser = admin_sub.add_parser("preflight", help="행사 시작 전 전체 사전검증")
    preflight_parser.add_argument("--coordinator", default=None, help="기본값: COORDINATOR_URL 또는 http://localhost:42000")
    preflight_parser.add_argument("--admin-secret", default=None, help="기본값: ADMIN_SECRET 또는 coordinator/.env")
    preflight_parser.add_argument("--hosts-file", metavar="PATH", help="팀 IP 매핑 JSON")
    preflight_parser.add_argument("--port", type=int, default=8000, help="팀 서비스 포트. 기본값: 8000")
    preflight_parser.add_argument("--repeat", type=int, default=3, help="취약점 반복 검증 횟수. 기본값: 3")
    preflight_parser.add_argument("--report", default=str(Path(__file__).with_name("validation_report.json")))
    preflight_parser.add_argument("--skip-vuln", action="store_true", help="취약점 검증 생략")
    preflight_parser.set_defaults(func=admin_preflight)

    round_parser = admin_sub.add_parser("round", help="라운드 시작/종료/다음 라운드 진행")
    round_parser.add_argument("action", nargs="?", choices=["next", "start", "end"], default="next")
    round_parser.add_argument("--coordinator", default=None, help="기본값: COORDINATOR_URL 또는 http://localhost:42000")
    round_parser.add_argument("--admin-secret", default=None, help="기본값: ADMIN_SECRET 또는 coordinator/.env")
    round_parser.add_argument("--force", action="store_true", help="preflight 미완료 상태에서도 start-round 실행")
    round_parser.set_defaults(func=admin_round)

    bundle_parser = admin_sub.add_parser("bundle", help="참가자 배포 번들 생성")
    bundle_parser.set_defaults(func=admin_bundle)
    return parser


def main() -> int:
    _self_update(sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


def _safe_cmd(cmd: object) -> str:
    if not isinstance(cmd, list):
        return str(cmd)
    masked: list[str] = []
    for item in cmd:
        if isinstance(item, str) and item.startswith("http.extraHeader=Authorization:"):
            masked.append("http.extraHeader=Authorization: <redacted>")
        else:
            masked.append(str(item))
    return " ".join(masked)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: command failed: {_safe_cmd(exc.cmd)}", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        raise SystemExit(exc.returncode)
