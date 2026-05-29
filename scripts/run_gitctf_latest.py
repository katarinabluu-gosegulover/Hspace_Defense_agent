from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _candidate_helpers() -> list[Path]:
    cache_root = Path.home() / ".cache" / "hspace-gitctf"
    helpers: list[Path] = []
    if cache_root.exists():
        for candidate in cache_root.glob("*/gitctf.py"):
            if candidate.is_file():
                helpers.append(candidate)
    local_helper = Path(__file__).with_name("gitctf.py")
    if local_helper.is_file():
        helpers.append(local_helper)
    helpers.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return helpers


def main(argv: list[str]) -> int:
    helpers = _candidate_helpers()
    if not helpers:
        print("gitctf helper를 찾을 수 없습니다.", file=sys.stderr)
        return 1

    helper = helpers[0]
    env = os.environ.copy()
    env["GITCTF_SELF_UPDATED"] = "1"

    cmd = [sys.executable, str(helper), *argv]
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
