"""Thin pre-tool policy wrapper used by hook integrations."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
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
    from agentic_deep_audit.policy import append_blocked_attempt, blocked_attempt_event_id, command_tokens_from_text, decide_command
except Exception as exc:  # noqa: BLE001 - hook boundary must fail closed with a clear token.
    IMPORT_ERROR = exc
    append_blocked_attempt = None
    blocked_attempt_event_id = None
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
        configured_path = Path(configured)
        if not configured_path.exists():
            print("hook_misconfigured: AGENTIC_DEEP_AUDIT_PYTHON does not exist", file=sys.stderr)
            return 2
        try:
            probe = subprocess.run(
                [str(configured_path), "-c", "import agentic_deep_audit; import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 3)"],
                cwd=str(PLUGIN_ROOT),
                env={**os.environ, "PYTHONPATH": str(SRC_ROOT)},
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"hook_misconfigured: AGENTIC_DEEP_AUDIT_PYTHON probe failed: {type(exc).__name__}", file=sys.stderr)
            return 2
        if probe.returncode != 0:
            detail = (probe.stderr or probe.stdout).strip().splitlines()
            suffix = f": {detail[0]}" if detail else ""
            print(f"hook_misconfigured: AGENTIC_DEEP_AUDIT_PYTHON cannot import agentic_deep_audit{suffix}", file=sys.stderr)
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
    return command_tokens_from_text(command, posix=os.name != "nt")


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
    cwd_value = event.get("cwd")
    cwd = Path(cwd_value) if isinstance(cwd_value, str) and cwd_value else Path(os.getcwd())
    default = cwd / "audit"
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    explicit = tool_input.get("audit_dir") or event.get("audit_dir")
    if isinstance(explicit, str) and explicit:
        # OQ-M22: the PreToolUse event is untrusted input. An arbitrary audit_dir would let a
        # crafted event create directories / write the blocked-attempts log to any path
        # (append_blocked_attempt does mkdir(parents=True) + write). Contain it within cwd.
        candidate = Path(explicit)
        resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve()
        try:
            resolved.relative_to(cwd.resolve())
        except ValueError:
            return default
        return resolved
    return default


def run_decision(command: list[str], origin: str, audit_dir: Path, block_code: int = 1, strict_runtime: bool = False, attempt_id: str | None = None) -> int:
    runtime_error = verify_runtime_ready(strict=strict_runtime or os.environ.get("AGENTIC_DEEP_AUDIT_HOOK_STRICT") == "1")
    if runtime_error is not None:
        return runtime_error
    assert append_blocked_attempt is not None
    assert decide_command is not None
    decision = decide_command(command, origin=origin)
    if not decision.allowed:
        append_blocked_attempt(audit_dir, decision, attempt_id=attempt_id)
        print(f"blocked: {decision.reason}", file=sys.stderr)
        return block_code
    print("allowed")
    return 0


def run_event_decision(event: dict, strict_runtime: bool = False) -> int:
    runtime_error = verify_runtime_ready(strict=strict_runtime or os.environ.get("AGENTIC_DEEP_AUDIT_HOOK_STRICT") == "1")
    if runtime_error is not None:
        return runtime_error
    command = command_from_event(event)
    event_attempt_id = blocked_attempt_event_id(event) if blocked_attempt_event_id is not None else None
    if command:
        return run_decision(command, "host_pre_tool", audit_dir_from_event(event), block_code=2, strict_runtime=strict_runtime, attempt_id=event_attempt_id)
    tool_name = str(event.get("tool_name") or "")
    if tool_requires_policy(tool_name):
        return run_decision(["__tool__", tool_name or "<unknown>"], "host_pre_tool", audit_dir_from_event(event), block_code=2, strict_runtime=strict_runtime, attempt_id=event_attempt_id)
    print("allowed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--audit-dir", required=True)
    parser.add_argument("command", nargs="+")
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    strict_runtime = False
    if "--strict-runtime" in actual_argv:
        strict_runtime = True
        actual_argv = [item for item in actual_argv if item != "--strict-runtime"]
    if not actual_argv:
        try:
            event = read_stdin_event()
        except json.JSONDecodeError as exc:
            print(f"blocked: invalid hook JSON: {exc}", file=sys.stderr)
            return 2
        return run_event_decision(event, strict_runtime=strict_runtime)

    args = parser.parse_args(actual_argv)
    return run_decision(args.command, args.origin, Path(args.audit_dir), strict_runtime=strict_runtime)


if __name__ == "__main__":
    sys.exit(main())
