from __future__ import annotations

import sys

from weflow_chat.desktop_refresh import run
from weflow_chat.orchestrator import RefreshMode


def main(argv: list[str] | None = None) -> int:
    supplied = sys.argv[1:] if argv is None else argv
    if supplied:
        print(
            "此聊天记录刷新入口不接受任何参数",
            file=sys.stderr,
        )
        return 2
    return run(refresh_mode=RefreshMode.DATABASE_ONLY)


if __name__ == "__main__":
    raise SystemExit(main())
