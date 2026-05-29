"""
취약점 검증 스크립트 (live-fire 방식).

팀 사용법 (제출 전 자기 서비스 검증):
  python ../scripts/gitctf.py check
  python ../scripts/gitctf.py check --vuln 1 --poc poc.py

주최측 사용법 (전 팀 일괄 검증):
  python validate_vulns.py --all --spec-dir ../vuln_specs --hosts-file hosts.json

반복 검증 (재현성 확인, N/N 성공):
  python validate_vulns.py --spec vuln_spec.json --host localhost --port 8000 --repeat 3

결과 저장:
  python validate_vulns.py --all ... --repeat 3 --save-report validation_report.json

검증 흐름 (live-fire):
  1. service.health 확인 (미지정 시 템플릿 호환용 /health)
  2. checker.inject: 테스트 flag를 서비스에 주입
  3. checker.retrieve: flag가 서비스에 저장됐는지 확인
  4. 공격 또는 PoC 실행: 응답/stdout 마지막 줄에서 HSPACE{...} 패턴 탐지
  5. checker.basic_function: 기본 기능 동작 확인
"""
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

CHECKER_TOKEN_DEFAULT = "validate-test-token"
FLAG_PATTERN = re.compile(r"HSPACE\{[a-f0-9]{32}\}")


def generate_flag() -> str:
    return "HSPACE{" + secrets.token_hex(16) + "}"


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_hosts(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _service_config(spec: dict) -> dict:
    service = spec.get("service")
    return service if isinstance(service, dict) else {}


def _request_from_spec(
    host: str,
    port: int,
    request_spec: dict,
    *,
    default_endpoint: str | None = None,
    default_method: str = "GET",
    default_body: Any = None,
    default_auth_header: str | None = None,
    flag: str = "",
    payload: str = "",
    checker_token: str = "",
    timeout: float = 10.0,
) -> httpx.Response:
    endpoint = request_spec.get("endpoint", default_endpoint)
    if not endpoint or not str(endpoint).startswith("/"):
        raise ValueError(f"endpoint must start with '/': {endpoint!r}")
    method = request_spec.get("method", default_method).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError(f"unsupported method: {method}")

    url = f"http://{host}:{port}{endpoint}"
    headers = _sub(request_spec.get("headers", {}), flag=flag, payload=payload, checker_token=checker_token)
    auth_header = request_spec.get("auth_header", default_auth_header)
    if auth_header and checker_token:
        headers[auth_header] = checker_token

    params = _sub(request_spec.get("params", request_spec.get("query", {})), flag=flag, payload=payload, checker_token=checker_token)
    body = request_spec.get("json", request_spec.get("body", default_body))
    data = request_spec.get("data")
    body = _sub(body, flag=flag, payload=payload, checker_token=checker_token)
    data = _sub(data, flag=flag, payload=payload, checker_token=checker_token)

    return httpx.request(method, url, headers=headers, params=params, json=body, data=data, timeout=timeout)


def _response_text(resp: httpx.Response, response_path: str | None = None) -> str:
    if response_path:
        try:
            data: Any = resp.json()
        except Exception:
            return resp.text
        for part in response_path.split("."):
            if isinstance(data, dict):
                data = data.get(part)
            elif isinstance(data, list) and part.isdigit():
                data = data[int(part)]
            else:
                return ""
        return data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    try:
        data = resp.json()
        if isinstance(data, dict) and isinstance(data.get("response"), str):
            return data["response"]
        return json.dumps(data, ensure_ascii=False)
    except Exception:
        return resp.text


def _check_health(host: str, port: int, service_spec: dict) -> tuple[bool, str]:
    health_spec = service_spec.get("health") or {"endpoint": "/health", "method": "GET", "expect_status": 200}
    expect_status = health_spec.get("expect_status", 200)
    try:
        resp = _request_from_spec(
            host,
            port,
            health_spec,
            default_endpoint="/health",
            default_method="GET",
            timeout=5.0,
        )
        return resp.status_code == expect_status, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, str(e)


def _inject_flag(host: str, port: int, inject_spec: dict, flag: str, checker_token: str) -> bool:
    if not inject_spec:
        return True
    try:
        r = _request_from_spec(
            host,
            port,
            inject_spec,
            default_method="POST",
            default_auth_header="X-Checker-Token",
            flag=flag,
            checker_token=checker_token,
        )
        return r.status_code in (200, 201, 204)
    except Exception as e:
        print(f"    inject 오류: {e}")
        return False


def _retrieve_flag(host: str, port: int, retrieve_spec: dict, flag: str, checker_token: str) -> bool:
    if not retrieve_spec:
        return True
    expect = _sub(retrieve_spec.get("expect_contains", "{{FLAG}}"), flag=flag, checker_token=checker_token)
    try:
        r = _request_from_spec(
            host,
            port,
            retrieve_spec,
            default_method="GET",
            default_auth_header="X-Checker-Token",
            flag=flag,
            checker_token=checker_token,
        )
        text = _response_text(r, retrieve_spec.get("response_path"))
        return r.status_code == retrieve_spec.get("expect_status", 200) and expect in text
    except Exception as e:
        print(f"    retrieve 오류: {e}")
        return False


def _attack(host: str, port: int, attack_spec: dict, payload: str, flag: str) -> tuple[bool, str]:
    """test_payload로 공격 후 응답에서 flag 패턴 탐지."""
    attack_spec = attack_spec or {}
    default_body = {"message": "{{PAYLOAD}}"}
    expect = _sub(attack_spec.get("expect_contains", "{{FLAG}}"), flag=flag, payload=payload)
    try:
        r = _request_from_spec(
            host,
            port,
            attack_spec,
            default_endpoint="/chat",
            default_method="POST",
            default_body=default_body,
            flag=flag,
            payload=payload,
            timeout=30.0,
        )
        r.raise_for_status()
        response_text = _response_text(r, attack_spec.get("response_path"))
        # 응답에서 HSPACE{...} 패턴 추출
        found = FLAG_PATTERN.findall(response_text)
        success = expect in response_text or flag in found
        return success, response_text[:300]
    except Exception as e:
        return False, f"[오류: {e}]"


def _basic_function(host: str, port: int, basic_spec: dict) -> bool:
    if not basic_spec:
        return True
    payload = basic_spec.get("payload", "안녕하세요")
    expect_status = basic_spec.get("expect_status", 200)
    try:
        r = _request_from_spec(
            host,
            port,
            basic_spec,
            default_endpoint="/chat",
            default_method="POST",
            default_body={"message": "{{PAYLOAD}}"},
            payload=payload,
            timeout=15.0,
        )
        text = _response_text(r, basic_spec.get("response_path"))
        expect_contains = basic_spec.get("expect_contains")
        return r.status_code == expect_status and (not expect_contains or _sub(expect_contains, payload=payload) in text)
    except Exception:
        return False


def _last_non_empty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _normalize_vuln_id(value: str) -> str:
    raw = str(value).strip().lower()
    if raw.isdigit():
        raw = f"vuln{raw}"
    if raw not in {"vuln1", "vuln2", "vuln3", "vuln4"}:
        raise ValueError("--vuln 은 1~4 또는 vuln1~vuln4 중 하나여야 합니다")
    return raw


def _find_vuln(spec: dict, vuln_id: str) -> dict:
    for vuln in spec.get("vulnerabilities", []):
        if vuln.get("id") == vuln_id:
            return vuln
    raise ValueError(f"vuln_spec.json에서 {vuln_id} 항목을 찾을 수 없습니다")


def _process_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _run_poc_file(
    poc_path: Path,
    host: str,
    port: int,
    target_team: str,
    vuln_id: str,
    timeout: int,
) -> dict:
    if not poc_path.exists():
        return {
            "timeout": False,
            "exit_code": None,
            "stdout": "",
            "stderr": f"PoC 파일 없음: {poc_path}",
        }

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONUNBUFFERED": "1",
        "TARGET_HOST": host,
        "TARGET_PORT": str(port),
        "TARGET_TEAM": target_team,
        "FLAG_ID": vuln_id,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="poc-check-") as workdir:
            completed = subprocess.run(
                [sys.executable, str(poc_path.resolve())],
                cwd=workdir,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        return {
            "timeout": False,
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "timeout": True,
            "exit_code": None,
            "stdout": _process_text(exc.stdout),
            "stderr": _process_text(exc.stderr),
        }


def validate_poc_single(
    spec: dict,
    host: str,
    port: int,
    vuln_id: str,
    poc_path: Path,
    checker_token: str = CHECKER_TOKEN_DEFAULT,
    timeout: int = 20,
) -> dict:
    """
    특정 취약점 하나에 대해 실제 PoC 파일이 주입된 flag를 출력하는지 검증.

    Production PoC runner와 같은 핵심 계약을 확인한다:
    TARGET_HOST/TARGET_PORT/TARGET_TEAM/FLAG_ID 환경변수를 주고 실행한 뒤,
    stdout의 마지막 non-empty line에 방금 주입한 flag가 있어야 PASS다.
    """
    vuln_id = _normalize_vuln_id(vuln_id)
    vuln = _find_vuln(spec, vuln_id)
    service_spec = _service_config(spec)
    checker_spec = vuln.get("checker", {})
    target_team = spec["team_id"]

    print(f"\n  [{vuln_id}] PoC 검증")
    print(f"    파일: {poc_path}")

    result = {
        "passed": False,
        "vuln_id": vuln_id,
        "poc": str(poc_path),
        "health": False,
        "inject": False,
        "retrieve": False,
        "poc_timeout": False,
        "poc_exit_code": None,
        "poc_flag_match": False,
        "basic_func": False,
        "failure": "",
    }

    health_ok, health_detail = _check_health(host, port, service_spec)
    result["health"] = health_ok
    if not health_ok:
        result["failure"] = f"health 실패: {health_detail}"
        print(f"    ✗ {result['failure']}")
        return result

    test_flag = generate_flag()
    inject_ok = _inject_flag(host, port, checker_spec.get("inject"), test_flag, checker_token)
    result["inject"] = inject_ok
    if not inject_ok:
        result["failure"] = "checker.inject 실패"
        print(f"    ✗ {result['failure']}")
        return result

    retrieve_ok = _retrieve_flag(host, port, checker_spec.get("retrieve"), test_flag, checker_token)
    result["retrieve"] = retrieve_ok
    if not retrieve_ok:
        result["failure"] = "checker.retrieve 실패"
        print(f"    ✗ {result['failure']}")
        return result

    poc_run = _run_poc_file(poc_path, host, port, target_team, vuln_id, timeout)
    result["poc_timeout"] = poc_run["timeout"]
    result["poc_exit_code"] = poc_run["exit_code"]
    if poc_run["timeout"]:
        result["failure"] = f"PoC timeout after {timeout}s"
        print(f"    ✗ {result['failure']}")
        return result

    final_line = _last_non_empty_line(poc_run["stdout"])
    flags = FLAG_PATTERN.findall(final_line)
    flag_ok = test_flag in flags
    result["poc_flag_match"] = flag_ok
    if not flag_ok:
        combined_flags = FLAG_PATTERN.findall(poc_run["stdout"] + "\n" + poc_run["stderr"])
        if test_flag in combined_flags:
            result["failure"] = "flag는 stdout의 마지막 non-empty line에 출력해야 합니다"
        else:
            result["failure"] = "PoC가 주입된 flag를 출력하지 못했습니다"
        print(f"    ✗ {result['failure']}")
        if poc_run["stderr"]:
            print(f"    stderr: {poc_run['stderr'][:300]}")
        return result

    basic_ok = _basic_function(host, port, checker_spec.get("basic_function"))
    result["basic_func"] = basic_ok
    if not basic_ok:
        result["failure"] = "checker.basic_function 실패"
        print(f"    ✗ {result['failure']}")
        return result

    result["passed"] = True
    print("    ✓ PASS (PoC가 주입된 flag를 마지막 stdout 줄에 출력)")
    return result


def validate_single(
    spec: dict,
    host: str,
    port: int,
    repeat: int = 1,
    checker_token: str = CHECKER_TOKEN_DEFAULT,
) -> dict:
    """
    단일 팀 전체 취약점 검증.

    Returns:
        {
          "passed": bool,
          "vulns": {
            vuln_id: {
              "health": bool, "inject": bool, "retrieve": bool,
              "attack_success": int, "attack_attempts": int,
              "basic_func": bool, "passed": bool, "failure_snippet": str
            }
          }
        }
    """
    team_id = spec["team_id"]
    vulns = spec.get("vulnerabilities", [])
    service_spec = _service_config(spec)
    base_url = f"http://{host}:{port}"

    print(f"\n{'='*55}")
    print(f"팀: {team_id}  ({spec.get('service_description', '')})")
    print(f"타겟: {base_url}  (반복: {repeat}회)")
    print(f"{'='*55}")

    schema_errors = _validate_vuln_schema(vulns)
    if schema_errors:
        for err in schema_errors:
            print(f"  ✗ 스키마 오류: {err}")
        return {"passed": False, "vulns": {}, "health": False, "schema_errors": schema_errors}

    # 1. health 확인
    health_ok, health_detail = _check_health(host, port, service_spec)
    if not health_ok:
        print(f"  ✗ health 실패: {health_detail}")

    if not health_ok:
        print(f"  ✗ 서비스 DOWN — 이후 검증 생략")
        return {"passed": False, "vulns": {}, "health": False}

    print(f"  ✓ health OK")

    team_result = {"passed": True, "health": True, "vulns": {}}

    for vuln in vulns:
        vid = vuln["id"]
        vuln_type = vuln.get("type", "unknown")
        checker_spec = vuln.get("checker", {})
        test_payload = vuln.get("test_payload", "")
        attack_spec = vuln.get("attack") or checker_spec.get("attack") or service_spec.get("attack") or {}

        print(f"\n  [{vid}] {vuln_type}")

        if not test_payload:
            print(f"    SKIP — test_payload 없음")
            team_result["vulns"][vid] = {"passed": False, "failure_snippet": "test_payload 없음"}
            team_result["passed"] = False
            continue

        vuln_ok = True
        vuln_r = {
            "inject": False, "retrieve": False,
            "attack_success": 0, "attack_attempts": repeat,
            "basic_func": False, "passed": False, "failure_snippet": "",
        }

        for attempt in range(1, repeat + 1):
            if attempt > 1:
                time.sleep(2)

            # 테스트용 임시 flag 생성
            test_flag = generate_flag()

            # 2. inject
            inject_spec = checker_spec.get("inject")
            inject_ok = _inject_flag(host, port, inject_spec, test_flag, checker_token)
            vuln_r["inject"] = inject_ok
            if not inject_ok:
                print(f"    시도 {attempt}/{repeat}: inject 실패")
                vuln_ok = False
                continue

            # 3. retrieve
            retrieve_spec = checker_spec.get("retrieve")
            retrieve_ok = _retrieve_flag(host, port, retrieve_spec, test_flag, checker_token)
            vuln_r["retrieve"] = retrieve_ok
            if not retrieve_ok:
                print(f"    시도 {attempt}/{repeat}: retrieve 실패")
                vuln_ok = False
                continue

            # 4. attack
            attack_ok, snippet = _attack(host, port, attack_spec, test_payload, test_flag)
            if attack_ok:
                vuln_r["attack_success"] += 1
                print(f"    시도 {attempt}/{repeat}: ✓ flag 탈취 성공")
            else:
                vuln_r["failure_snippet"] = snippet
                print(f"    시도 {attempt}/{repeat}: ✗ flag 미탈취")

        # 5. basic_function (1번만)
        basic_spec = checker_spec.get("basic_function")
        basic_ok = _basic_function(host, port, basic_spec)
        vuln_r["basic_func"] = basic_ok
        if not basic_ok:
            print(f"    basic_function 실패")

        # 최종 판정: N/N 공격 성공 + basic_function 정상
        vuln_passed = (vuln_r["attack_success"] == repeat and basic_ok)
        vuln_r["passed"] = vuln_passed

        if vuln_passed:
            print(f"    ✓ PASS ({repeat}/{repeat} 공격 성공, basic_func OK)")
        else:
            print(f"    ✗ FAIL (공격 {vuln_r['attack_success']}/{repeat}, basic_func={basic_ok})")
            team_result["passed"] = False

        team_result["vulns"][vid] = vuln_r

    status = "모든 취약점 검증 통과 ✓" if team_result["passed"] else "일부 취약점 검증 실패 ✗"
    print(f"\n  결과: {status}")
    return team_result


def _validate_vuln_schema(vulns: list[dict]) -> list[str]:
    errors: list[str] = []
    if len(vulns) != 4:
        errors.append(f"취약점은 정확히 4개여야 함 (현재 {len(vulns)}개)")
    ids = [v.get("id") for v in vulns]
    if ids != ["vuln1", "vuln2", "vuln3", "vuln4"]:
        errors.append("취약점 id는 vuln1~vuln4 순서여야 함")
    return errors


def _collect_poc_targets(args: argparse.Namespace) -> list[tuple[str, Path]]:
    numbered: dict[str, Path] = {}
    for idx in range(1, 5):
        poc = getattr(args, f"poc{idx}", None)
        if poc:
            numbered[f"vuln{idx}"] = Path(poc)

    if args.poc:
        if not args.vuln:
            raise ValueError("--poc 사용 시 --vuln 1~4를 함께 지정하세요")
        vuln_id = _normalize_vuln_id(args.vuln)
        numbered[vuln_id] = Path(args.poc)
    elif args.vuln:
        vuln_id = _normalize_vuln_id(args.vuln)
        if not numbered:
            raise ValueError("--vuln 사용 시 --poc 또는 같은 번호의 --pocN을 함께 지정하세요")
        if vuln_id not in numbered:
            raise ValueError(f"--vuln {args.vuln}에 대응하는 --poc{vuln_id[-1]} 옵션이 필요합니다")
        numbered = {vuln_id: numbered[vuln_id]}

    return sorted(numbered.items(), key=lambda item: item[0])


def main():
    parser = argparse.ArgumentParser(description="AI A&D 취약점 검증 스크립트 (live-fire)")
    parser.add_argument("--spec", help="vuln_spec.json 경로 (단일 팀)")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--all", action="store_true", help="전 팀 일괄 검증")
    parser.add_argument("--spec-dir", help="vuln_specs 디렉토리")
    parser.add_argument("--hosts-file", help="팀별 IP 매핑 JSON")
    parser.add_argument("--repeat", type=int, default=1,
                        help="취약점당 반복 횟수, N/N 성공해야 PASS (이벤트 표준: 3)")
    parser.add_argument("--save-report", metavar="PATH")
    parser.add_argument("--checker-token", default=CHECKER_TOKEN_DEFAULT,
                        help="checker.inject/retrieve 요청에 넣을 X-Checker-Token 값")
    parser.add_argument("--vuln", help="PoC로 검증할 취약점 번호. 예: 1 또는 vuln1")
    parser.add_argument("--poc", help="--vuln으로 지정한 취약점을 검증할 PoC 파일")
    for idx in range(1, 5):
        parser.add_argument(
            f"--poc{idx}",
            nargs="?",
            const=f"poc{idx}.py",
            help=f"vuln{idx} 검증용 PoC 파일. 값 생략 시 poc{idx}.py",
        )
    parser.add_argument("--poc-timeout", type=int, default=20, help="PoC 실행 제한 시간(초). 기본값: 20")
    args = parser.parse_args()

    if args.repeat < 1:
        print("ERROR: --repeat 은 1 이상")
        sys.exit(1)
    if args.poc_timeout < 1:
        print("ERROR: --poc-timeout 은 1 이상")
        sys.exit(1)
    try:
        poc_targets = _collect_poc_targets(args)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    if poc_targets and args.all:
        print("ERROR: PoC 파일 검증은 --spec 단일 검증에서만 사용할 수 있습니다")
        sys.exit(1)
    if poc_targets and not args.spec:
        print("ERROR: PoC 파일 검증은 --spec 이 필요합니다")
        sys.exit(1)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repeat_n": args.repeat,
        "all_passed": False,
        "teams": {},
    }

    # 단일 팀
    if args.spec:
        spec = load_spec(args.spec)
        if poc_targets:
            base_url = f"http://{args.host}:{args.port}"
            print(f"\n{'='*55}")
            print(f"팀: {spec['team_id']}  ({spec.get('service_description', '')})")
            print(f"타겟: {base_url}")
            print(f"PoC 검증: {len(poc_targets)}개")
            print(f"{'='*55}")
            poc_results = {}
            for vuln_id, poc_path in poc_targets:
                try:
                    poc_results[vuln_id] = validate_poc_single(
                        spec,
                        args.host,
                        args.port,
                        vuln_id,
                        poc_path,
                        checker_token=args.checker_token,
                        timeout=args.poc_timeout,
                    )
                except ValueError as exc:
                    print(f"\n  [{vuln_id}] PoC 검증")
                    print(f"    ✗ {exc}")
                    poc_results[vuln_id] = {
                        "passed": False,
                        "vuln_id": vuln_id,
                        "poc": str(poc_path),
                        "health": False,
                        "failure": str(exc),
                    }
            result = {
                "passed": all(item["passed"] for item in poc_results.values()),
                "health": all(item["health"] for item in poc_results.values()),
                "pocs": poc_results,
            }
            status = "모든 PoC 검증 통과 ✓" if result["passed"] else "일부 PoC 검증 실패 ✗"
            print(f"\n  결과: {status}")
        else:
            result = validate_single(spec, args.host, args.port,
                                     repeat=args.repeat, checker_token=args.checker_token)
        report["teams"][spec["team_id"]] = result
        report["all_passed"] = result["passed"]
        if args.save_report:
            Path(args.save_report).write_text(json.dumps(report, indent=2, ensure_ascii=False))
            print(f"\n리포트 저장: {args.save_report}")
        sys.exit(0 if result["passed"] else 1)

    # 전 팀 일괄
    if args.all:
        if not args.spec_dir or not args.hosts_file:
            print("ERROR: --all 사용 시 --spec-dir 과 --hosts-file 필요")
            sys.exit(1)

        hosts = load_hosts(args.hosts_file)
        spec_dir = Path(args.spec_dir)

        for spec_file in sorted(spec_dir.glob("*.json")):
            if spec_file.name == "example.json":
                continue
            spec = load_spec(str(spec_file))
            team_id = spec["team_id"]
            host = hosts.get(team_id)
            if not host:
                print(f"\n[{team_id}] SKIP — hosts_file에 IP 없음")
                continue
            result = validate_single(spec, host, args.port,
                                     repeat=args.repeat, checker_token=args.checker_token)
            report["teams"][team_id] = result

        all_passed = all(r["passed"] for r in report["teams"].values())
        report["all_passed"] = all_passed

        print(f"\n{'='*55}")
        print("전체 결과 요약")
        print(f"{'='*55}")
        for team, r in report["teams"].items():
            mark = "✓" if r["passed"] else "✗"
            print(f"  {mark} {team}")

        if args.save_report:
            Path(args.save_report).write_text(json.dumps(report, indent=2, ensure_ascii=False))
            print(f"\n리포트 저장: {args.save_report}")

        if not all_passed:
            failed = [t for t, r in report["teams"].items() if not r["passed"]]
            print(f"\n검증 실패 팀: {', '.join(failed)}")
            sys.exit(1)
        else:
            print("\n전 팀 검증 통과")
        return

    parser.print_help()


def _sub(obj, flag: str = "", payload: str = "", checker_token: str = ""):
    """spec 안의 템플릿 변수를 실제 값으로 치환."""
    if isinstance(obj, str):
        return (
            obj.replace("{{FLAG}}", flag)
            .replace("{{PAYLOAD}}", payload)
            .replace("{{CHECKER_TOKEN}}", checker_token)
        )
    if isinstance(obj, dict):
        return {k: _sub(v, flag=flag, payload=payload, checker_token=checker_token) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sub(v, flag=flag, payload=payload, checker_token=checker_token) for v in obj]
    return obj


if __name__ == "__main__":
    main()
