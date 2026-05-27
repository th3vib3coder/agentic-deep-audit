"""Thin pre-tool policy wrapper used by hook integrations."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path


MCP_SAFE_READ_VERBS = {
    "get",
    "list",
    "list_directory",
    "list_tools",
    "read",
    "read_file",
    "search",
    "stat",
}
MCP_RISKY_VERBS = {
    "click",
    "create_directory",
    "edit_block",
    "exec",
    "execute",
    "execute_command",
    "force_terminate",
    "interact_with_process",
    "kill_process",
    "move_file",
    "navigate",
    "open",
    "press",
    "run",
    "spawn",
    "start_process",
    "stop_process",
    "type",
    "use_browser",
    "write",
    "write_file",
}
RISKY_HOST_TOOLS = {"Bash", "Shell", "Exec", "Edit", "Write", "Task", "TaskCreate", "MultiEdit", "NotebookEdit"}

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))

try:
    from agentic_deep_audit.policy import append_blocked_attempt, decide_command
except Exception as exc:  # noqa: BLE001 - hook boundary must fail closed with a clear token.
    IMPORT_ERROR = exc
    append_blocked_attempt = None
    decide_command = None
else:
    IMPORT_ERROR = None


def verify_runtime_ready(strict: bool = False) -> int | None:
    if sys.version_info < (3, 10):
        print("hook_misconfigured: Python >= 3.10 is required", file=sys.stderr)
        return 2
    if IMPORT_ERROR is not None:
        print(f"hook_misconfigured: agentic_deep_audit import failed: {type(IMPORT_ERROR).__name__}", file=sys.stderr)
        return 2
    if strict:
        configured = os.environ.get("AGENTIC_DEEP_AUDIT_PYTHON")
        if not configured:
            print("hook_misconfigured: AGENTIC_DEEP_AUDIT_PYTHON is required", file=sys.stderr)
            return 2
    return None


def read_stdin_event() -> dict:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    return payload if isinstance(payload, dict) else {}


def command_from_event(event: dict) -> list[str]:
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return []
    return shlex.split(command, posix=os.name != "nt")


def mcp_verb(tool_name: str) -> str:
    return tool_name.rsplit("__", 1)[-1] if tool_name.startswith("mcp__") and "__" in tool_name else ""


def tool_requires_policy(tool_name: str) -> bool:
    if tool_name in RISKY_HOST_TOOLS:
        return True
    if tool_name.startswith("mcp__"):
        verb = mcp_verb(tool_name)
        return verb in MCP_RISKY_VERBS or verb not in MCP_SAFE_READ_VERBS
    return False


def audit_dir_from_event(event: dict) -> Path:
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    explicit = tool_input.get("audit_dir") or event.get("audit_dir")
    if isinstance(explicit, str) and explicit:
        return Path(explicit)
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else os.getcwd()
    return Path(cwd) / "audit"


def run_decision(command: list[str], origin: str, audit_dir: Path, block_code: int = 1) -> int:
    runtime_error = verify_runtime_ready(strict=os.environ.get("AGENTIC_DEEP_AUDIT_HOOK_STRICT") == "1")
    if runtime_error is not None:
        return runtime_error
    assert append_blocked_attempt is not None
    assert decide_command is not None
    decision = decide_command(command, origin=origin)
    if not decision.allowed:
        append_blocked_attempt(audit_dir, decision)
        print(f"blocked: {decision.reason}", file=sys.stderr)
        return block_code
    print("allowed")
    return 0


def run_event_decision(event: dict) -> int:
    command = command_from_event(event)
    if command:
        return run_decision(command, "host_pre_tool", audit_dir_from_event(event), block_code=2)
    tool_name = str(event.get("tool_name") or "")
    if tool_requires_policy(tool_name):
        return run_decision(["__tool__", tool_name or "<unknown>"], "host_pre_tool", audit_dir_from_event(event), block_code=2)
    runtime_error = verify_runtime_ready(strict=os.environ.get("AGENTIC_DEEP_AUDIT_HOOK_STRICT") == "1")
    if runtime_error is not None:
        return runtime_error
    print("allowed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--audit-dir", required=True)
    parser.add_argument("command", nargs="+")
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    if not actual_argv:
        try:
            event = read_stdin_event()
        except json.JSONDecodeError as exc:
            print(f"blocked: invalid hook JSON: {exc}", file=sys.stderr)
            return 2
        return run_event_decision(event)

    args = parser.parse_args(actual_argv)
    return run_decision(args.command, args.origin, Path(args.audit_dir))


if __name__ == "__main__":
    sys.exit(main())
