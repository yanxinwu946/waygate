#!/usr/bin/env python3
"""Convenience launcher for waygate.

Nothing here is new functionality - it is a friendlier front door for the CLI
that lives in ``waygate/cli.py``.  Shortcuts:

    python main.py                 # SOCKS5 代理，默认 127.0.0.1:1080（自动选传输）
    python main.py check           # 自检：注册 → 建隧道 → 隧道内 DNS/HTTP，打印出口 IP
    python main.py webui           # 多实例池 + Web 控制台（默认 0.0.0.0:8899，2 个实例，统一入口 1079）
    python main.py webui 3 1080    # 3 个实例，SOCKS5 从 1080 起，控制台 0.0.0.0:8899
    python main.py lan             # 同上，但 SOCKS5 监听 0.0.0.0:1080（局域网可用）

其它任何参数都原样交给 CLI：

    python main.py --transport masque -b 0.0.0.0:1080 -v
    python main.py --check --transport wireguard
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# make the package importable no matter where this is launched from
sys.path.insert(0, str(Path(__file__).resolve().parent))

from waygate.cli import main as cli_main  # noqa: E402

USAGE = __doc__


def _expand(argv: list[str]) -> list[str]:
    """Turn the short commands into the real CLI arguments."""
    if not argv:
        return []
    command, rest = argv[0], argv[1:]

    if command in ("-h", "--help", "help"):
        print(USAGE)
        raise SystemExit(0)

    if command == "check":
        return ["--check", *rest]

    if command == "webui":
        instances = rest[0] if rest and rest[0].isdigit() else "2"
        base_port = rest[1] if len(rest) > 1 and rest[1].isdigit() else "1080"
        extra = rest[2:] if len(rest) > 2 else []
        return ["--webui", "--instances", instances, "--base-port", base_port,
                "--webui-bind", os.environ.get("WAYGATE_WEBUI_BIND")
                or os.environ.get("WARP2S5_WEBUI_BIND") or "0.0.0.0:8899",
                *extra]

    if command == "lan":
        return ["-b", "0.0.0.0:1080", *rest]

    # anything else: straight through to the CLI
    return argv


def main() -> int:
    return cli_main(_expand(sys.argv[1:]))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        raise SystemExit(130)
