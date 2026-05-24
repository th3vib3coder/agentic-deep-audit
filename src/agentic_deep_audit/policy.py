"""No-exec and network policy decisions."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .models import ARTIFACT_PATHS, PLUGIN_ROOT


POLICY_ROOT = PLUGIN_ROOT / "policies"


@dataclass(frozen=True)
class CommandDecision:
    decision: str
    command: list[str]
    origin: str
    policy_rule: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


@dataclass(frozen=True)
class NetworkDecision:
    decision: str
    domain: str
    policy_rule: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


@dataclass(frozen=True)
class BlockedCommandAttempt:
    command: list[str]
    origin: str
    decision: str
    policy_rule: str
    evidence_ids: list[str] = field(default_factory=list)
    redacted_args: list[str] = field(default_factory=list)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_blocked_commands_policy(path: Path | None = None) -> dict:
    return load_json(path or POLICY_ROOT / "BLOCKED_COMMANDS_ALLOWLIST.json")


def load_default_network_policy(path: Path | None = None) -> dict:
    return load_json(path or POLICY_ROOT / "DEFAULT_NETWORK_POLICY.json")


def _subcommand_allowed(actual: list[str], allowed: list[str]) -> bool:
    if "*" in allowed:
        return True
    for item in allowed:
        expected = item.split()
        if len(actual) >= len(expected) and actual[: len(expected)] == expected:
            return True
    return False


def decide_command(command: list[str], origin: str, mode: str = "source-audit", policy: dict | None = None) -> CommandDecision:
    policy = policy or load_blocked_commands_policy()
    if not command:
        return CommandDecision("block", command, origin, "empty_command", "empty command is invalid")
    executable = command[0]
    joined = " ".join(command)
    if origin == "target_repo_manifest":
        return CommandDecision("block", command, origin, "target_repo_manifest_no_exec", "target repo commands are observed data")
    for blocked in policy.get("blocked_always", []):
        if executable == blocked or joined.startswith(blocked):
            return CommandDecision("block", command, origin, "blocked_always", f"{blocked} is always blocked")
    for sandbox in policy.get("sandbox_only", []):
        if joined.startswith(sandbox) and mode != "research":
            return CommandDecision("block", command, origin, "sandbox_only", f"{sandbox} requires sandbox consent")
    if origin != "plugin_allowlist":
        return CommandDecision("block", command, origin, "unknown_origin", "only plugin_allowlist origin can execute commands")
    for allowed in policy.get("allowed", []):
        if executable == allowed["command"] and _subcommand_allowed(command[1:], allowed["subcommands"]):
            return CommandDecision("allow", command, origin, "plugin_allowlist", "command allowed by bundled policy")
    return CommandDecision("block", command, origin, "not_allowlisted", "command is not in allowlist")


def append_blocked_attempt(audit_dir: Path, decision: CommandDecision, evidence_ids: list[str] | None = None) -> Path:
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"]
    existing = {"schema_version": "1.0", "attempts": []}
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
    attempt = BlockedCommandAttempt(
        command=decision.command,
        origin=decision.origin,
        decision=decision.decision,
        policy_rule=decision.policy_rule,
        evidence_ids=evidence_ids or [],
        redacted_args=["<redacted>" if "token" in item.lower() else item for item in decision.command],
    )
    existing.setdefault("attempts", []).append(asdict(attempt))
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _host_from_url_or_domain(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _matches_domain(pattern: str, domain: str) -> bool:
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain.endswith(f".{suffix}") and domain != suffix
    return domain == pattern


def _domain_specificity(pattern: str) -> tuple[int, int]:
    if pattern == "*":
        return (0, 0)
    if pattern.startswith("*."):
        return (1, len(pattern))
    return (2, len(pattern))


def classify_payload_contains_source(payload: str | bytes | None) -> bool:
    if payload is None:
        return False
    text = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else payload
    source_markers = [
        r"\bdef\s+\w+\s*\(",
        r"\bclass\s+\w+",
        r"\bfunction\s+\w*\s*\(",
        r"\bimport\s+[\w.{*]",
        r"\bfrom\s+\w+\s+import\b",
        r"=>",
        r"#include\s*[<\"]",
        r"\bpublic\s+class\s+\w+",
        r"\bconst\s+\w+\s*=",
        r"\blet\s+\w+\s*=",
        r"\bvar\s+\w+\s*=",
        r"\bpackage\s+main\b",
        r"\bSELECT\s+.+\s+FROM\s+\w+",
    ]
    return any(re.search(marker, text, re.IGNORECASE | re.DOTALL) for marker in source_markers)


def decide_network(target: str, payload: str | bytes | None = None, policy: dict | None = None) -> NetworkDecision:
    if policy is None:
        return NetworkDecision("block", _host_from_url_or_domain(target), "missing_policy", "network policy snapshot is required")
    domain = _host_from_url_or_domain(target)
    if policy.get("default") != "deny":
        return NetworkDecision("block", domain, "default_not_deny", "network policy must default deny")
    if policy.get("send_source_code") is False and classify_payload_contains_source(payload):
        return NetworkDecision("block", domain, "send_source_code_false", "source-like payload blocked")
    matches: list[tuple[str, str]] = []
    for denied in policy.get("denied_domains", []):
        if _matches_domain(denied, domain):
            matches.append(("deny", denied))
    for allowed in policy.get("allowed_domains", []):
        if _matches_domain(allowed, domain):
            matches.append(("allow", allowed))
    if not matches:
        return NetworkDecision("block", domain, "default_deny", "no allow rule matched")
    matches.sort(key=lambda item: (_domain_specificity(item[1]), 1 if item[0] == "deny" else 0), reverse=True)
    action, pattern = matches[0]
    if action == "deny":
        return NetworkDecision("block", domain, f"denied:{pattern}", "denied domain rule matched")
    return NetworkDecision("allow", domain, f"allowed:{pattern}", "allowed domain rule matched")
