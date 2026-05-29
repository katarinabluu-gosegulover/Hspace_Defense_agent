"""실시간 공격 탐지 이벤트 watcher.

예:
  python scripts/watch_attacks.py --url http://knights.hspace.io:42001 --token <CHECKER_TOKEN>
  CHECKER_TOKEN=<token> python scripts/watch_attacks.py --url http://knights.hspace.io:42001
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _redact(text: object) -> str:
    value = "" if text is None else str(text)
    start = 0
    while True:
        idx = value.find("HSPACE{", start)
        if idx < 0:
            return value
        end = value.find("}", idx)
        if end < 0:
            return value[:idx] + "HSPACE{REDACTED}"
        value = value[:idx] + "HSPACE{REDACTED}" + value[end + 1:]
        start = idx + len("HSPACE{REDACTED}")


def _fetch(base_url: str, token: str, limit: int) -> dict:
    url = base_url.rstrip("/") + f"/admin/attacks?limit={limit}"
    request = urllib.request.Request(url, headers={"X-Checker-Token": token})
    with urllib.request.urlopen(request, timeout=10) as response:
        raw = response.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _event_key(event: dict) -> str:
    return "|".join([
        str(event.get("timestamp", "")),
        str(event.get("primary_alert", "")),
        str(event.get("client_ip", "")),
        str(event.get("path", "")),
        str(event.get("body_preview", ""))[:80],
    ])


def _print_event(event: dict) -> None:
    alerts = ",".join(alert.get("alert_id", "?") for alert in event.get("alerts", []))
    line = (
        f"[{event.get('timestamp')}] "
        f"{event.get('severity', '?').upper():<6} "
        f"{event.get('client_ip', 'unknown'):<15} "
        f"{event.get('method', '')} {event.get('path', '')} "
        f"status={event.get('status_code')} "
        f"alert={event.get('primary_alert')} all={alerts} "
        f"ua={_redact(event.get('user_agent', ''))!r} "
        f"body={_redact(event.get('body_preview', ''))!r}"
    )
    print(line, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Poll /admin/attacks and print new attack events.")
    parser.add_argument("--url", default=os.getenv("SERVICE_URL", "http://knights.hspace.io:42001"))
    parser.add_argument("--token", default=os.getenv("CHECKER_TOKEN", ""))
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()

    if not args.token:
        print("ERROR: CHECKER_TOKEN이 필요합니다. --token 또는 환경변수 CHECKER_TOKEN으로 넣으세요.", file=sys.stderr)
        return 2

    seen: set[str] = set()
    print(f"watching {args.url.rstrip('/')}/admin/attacks every {args.interval}s", flush=True)
    while True:
        try:
            payload = _fetch(args.url, args.token, args.limit)
        except urllib.error.HTTPError as exc:
            print(f"HTTP {exc.code}: /admin/attacks 조회 실패", file=sys.stderr, flush=True)
            if exc.code == 403:
                print("토큰이 맞지 않습니다. CHECKER_TOKEN 또는 대회에서 제공한 방어 실행 환경을 확인하세요.", file=sys.stderr)
                return 3
        except Exception as exc:
            print(f"fetch error: {exc}", file=sys.stderr, flush=True)
        else:
            summary = payload.get("summary", {})
            for event in payload.get("attacks", []):
                key = _event_key(event)
                if key in seen:
                    continue
                seen.add(key)
                _print_event(event)
            if not payload.get("attacks"):
                print(f"no events yet; summary={summary}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
