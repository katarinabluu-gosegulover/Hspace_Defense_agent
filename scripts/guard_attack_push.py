from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path


def _config_path() -> Path:
    raw = os.getenv("GITCTF_CONFIG", r"~/.config/hspace-gitctf/config.json")
    return Path(raw).expanduser()


def _coordinator_url() -> str:
    env = os.getenv("COORDINATOR_URL", "").strip()
    if env:
        return env.rstrip("/")
    cfg_path = _config_path()
    if cfg_path.is_file():
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        value = str(data.get("coordinator", "")).strip()
        if value:
            return value.rstrip("/")
    return "http://knights.hspace.io:42000"


def main() -> int:
    coordinator = _coordinator_url()
    with urllib.request.urlopen(f"{coordinator}/status", timeout=10) as resp:
        status = json.load(resp)

    round_active = bool(status.get("round_active"))
    preflight_done = bool(status.get("preflight_done"))
    if round_active or preflight_done:
        print(
            f"[guard] ok: round_active={round_active} preflight_done={preflight_done}",
            file=sys.stderr,
        )
        return 0

    print(
        "[guard] blocked: round is inactive, so owner push would use service push instead of agent-only.",
        file=sys.stderr,
    )
    print(
        "[guard] use the real team2 service repo for owner pushes, or retry when round_active/preflight_done becomes true.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
