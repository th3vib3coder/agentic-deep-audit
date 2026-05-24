"""Thin pre-tool policy wrapper used by hook integrations."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentic_deep_audit.policy import append_blocked_attempt, decide_command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--audit-dir", required=True)
    parser.add_argument("command", nargs="+")
    args = parser.parse_args(argv)

    decision = decide_command(args.command, origin=args.origin)
    if not decision.allowed:
        append_blocked_attempt(Path(args.audit_dir), decision)
        print(f"blocked: {decision.reason}", file=sys.stderr)
        return 1
    print("allowed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
