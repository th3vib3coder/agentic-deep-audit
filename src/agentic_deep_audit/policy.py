"""No-exec and network policy decisions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .limits import read_json_capped, read_text_auto_capped
from .mcp_policy import looks_secret
from .models import ARTIFACT_PATHS, PLUGIN_ROOT
from .resources import policy_dir


POLICY_ROOT = policy_dir()
INVALID_COMMAND_TOKEN = "__invalid_command__"
BLOCKED_ATTEMPT_LOCK_TIMEOUT_SECONDS = 5.0
BLOCKED_ATTEMPT_STALE_LOCK_SECONDS = 60.0
DANGEROUS_ARGS_BY_COMMAND = {
    "git": {
        "-c",
        "-P",
        "--config-env",
        "--exec-path",
        "--upload-pack",
        "--receive-pack",
        "--ext-diff",
        "--external-diff",
        "--git-dir",
        "--work-tree",
        "-C",
        "--exec",
        "--namespace",
        "--no-pager",
        "--super-prefix",
    },
    "rg": {"--pre", "--pre-glob"},
}


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
    attempt_id: str | None = None


def load_json(path: Path) -> dict:
    return read_json_capped(path, label="policy JSON")


def load_blocked_commands_policy(path: Path | None = None) -> dict:
    return load_json(path or POLICY_ROOT / "BLOCKED_COMMANDS_ALLOWLIST.json")


def load_default_network_policy(path: Path | None = None) -> dict:
    return load_json(path or POLICY_ROOT / "DEFAULT_NETWORK_POLICY.json")


def command_tokens_from_text(command: str, *, posix: bool = True) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        return []
    try:
        tokens = shlex.split(command, posix=posix)
    except ValueError:
        return [INVALID_COMMAND_TOKEN]
    return tokens or [command.strip()]


def blocked_attempt_event_id(event: dict) -> str:
    event_bytes = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8", errors="replace")
    return f"hook-{hashlib.sha256(event_bytes).hexdigest()[:24]}"


def _subcommand_allowed(actual: list[str], allowed: list[str]) -> bool:
    if "*" in allowed:
        return True
    for item in allowed:
        expected = item.split()
        if len(actual) >= len(expected) and actual[: len(expected)] == expected:
            return True
    return False


def _phrase_matches(command: list[str], phrase: str) -> bool:
    expected = phrase.split()
    return len(command) >= len(expected) and command[: len(expected)] == expected


def _strip_wrapping_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        return token[1:-1]
    return token


def _dangerous_arg(command: list[str]) -> str | None:
    executable = command[0] if command else ""
    blocked = DANGEROUS_ARGS_BY_COMMAND.get(executable, set())
    for arg in command[1:]:
        if arg in blocked:
            return arg
        if executable == "git" and arg.startswith("--config-env="):
            return "--config-env"
        if executable == "git" and arg.startswith("--exec-path="):
            return "--exec-path"
        if executable == "git" and arg.startswith("--ext-diff="):
            return "--ext-diff"
        if executable == "git" and arg.startswith("--external-diff="):
            return "--external-diff"
        if executable == "git" and arg.startswith("--git-dir="):
            return "--git-dir"
        if executable == "git" and arg.startswith("--work-tree="):
            return "--work-tree"
        if executable == "git" and arg.startswith("--upload-pack="):
            return "--upload-pack"
        if executable == "git" and arg.startswith("--receive-pack="):
            return "--receive-pack"
        if executable == "git" and arg.startswith("--exec="):
            return "--exec"
        if executable == "git" and arg.startswith("--namespace="):
            return "--namespace"
        if executable == "git" and arg.startswith("--super-prefix="):
            return "--super-prefix"
        if executable == "rg" and arg.startswith("--pre="):
            return "--pre"
    return None


def decide_command(command: list[str], origin: str, mode: str = "source-audit", policy: dict | None = None) -> CommandDecision:
    policy = policy or load_blocked_commands_policy()
    if not command:
        return CommandDecision("block", command, origin, "empty_command", "empty command is invalid")
    command = [_strip_wrapping_quotes(str(token)) for token in command]
    executable = command[0]
    if origin == "target_repo_manifest":
        return CommandDecision("block", command, origin, "target_repo_manifest_no_exec", "target repo commands are observed data")
    dangerous = _dangerous_arg(command)
    if dangerous is not None:
        return CommandDecision("block", command, origin, "dangerous_argument", f"{dangerous} is blocked by policy")
    for blocked in policy.get("blocked_always", []):
        if executable == blocked or _phrase_matches(command, blocked):
            return CommandDecision("block", command, origin, "blocked_always", f"{blocked} is always blocked")
    for sandbox in policy.get("sandbox_only", []):
        if _phrase_matches(command, sandbox) and mode != "research":
            return CommandDecision("block", command, origin, "sandbox_only", f"{sandbox} requires sandbox consent")
    if origin != "plugin_allowlist":
        return CommandDecision("block", command, origin, "unknown_origin", "only plugin_allowlist origin can execute commands")
    for allowed in policy.get("allowed", []):
        if executable == allowed["command"] and _subcommand_allowed(command[1:], allowed["subcommands"]):
            return CommandDecision("allow", command, origin, "plugin_allowlist", "command allowed by bundled policy")
    return CommandDecision("block", command, origin, "not_allowlisted", "command is not in allowlist")


@contextmanager
def _blocked_attempt_lock(path: Path):
    lock_path = path.with_suffix(f"{path.suffix}.lock")
    start = time.monotonic()
    handle: int | None = None
    while handle is None:
        try:
            handle = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except (FileExistsError, PermissionError):
            try:
                lock_age = time.time() - lock_path.stat().st_mtime
            except OSError:
                lock_age = 0
            if lock_age >= BLOCKED_ATTEMPT_STALE_LOCK_SECONDS:
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() - start >= BLOCKED_ATTEMPT_LOCK_TIMEOUT_SECONDS:
                raise TimeoutError(f"timed out waiting for blocked-attempt lock: {lock_path}")
            time.sleep(0.02)
    try:
        os.write(handle, str(os.getpid()).encode("ascii", errors="ignore"))
        yield
    finally:
        os.close(handle)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


_SHORT_CREDENTIAL_FLAG_RE = re.compile(r"^-(p|pw|pwd)$")
_LONG_CREDENTIAL_FLAG_RE = re.compile(
    r"(?i)^--(?:[a-z0-9]+[-_])*(pw|pwd|pass|passwd|password|secret|token|auth|authorization|credential|credentials|bearer|api[-_]?key|access[-_]?key|secret[-_]?key)$"
)
_INLINE_CREDENTIAL_RE = re.compile(
    r"(?i)(pw|pwd|pass|passwd|password|secret|token|auth|authorization|credential|credentials|bearer|api[-_]?key|access[-_]?key|secret[-_]?key)\s*[=:]\s*\S"
)
# HTTP basic-auth style user[:password] flags (-u/--user/--username/--login). Only a colon-pair
# value is a secret; a bare username (e.g. `-u root`) must stay legible, so the separated form is
# gated on a credential value in redact_command_tokens. The inline `--user=user:pass` form is masked
# directly here (only when it carries a colon pair).
_USERINFO_FLAG_RE = re.compile(r"(?i)^-{1,2}(u|user|username|login)$")
_INLINE_USERINFO_RE = re.compile(r"(?i)^-{1,2}(u|user|username|login)=[^\s]*:[^\s]")
# Attached single-dash password short flags: MySQL's canonical -pPASSWORD with no space. Mask the
# attached value only for MySQL-family commands so generic port-like flags such as -port stay useful.
_ATTACHED_CREDENTIAL_RE = re.compile(r"^(-p)\S")
_MYSQL_COMMANDS = {"mysql", "mysqldump", "mysqladmin", "mysqlshow", "mysqlimport", "mariadb", "mariadb-dump"}
_EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1")


def _token_embeds_secret(token: str) -> bool:
    if "token" in token.lower():
        return True
    try:
        if looks_secret(token):
            return True
        if "@" in token and "://" not in token and urlparse(f"//{token}").password:
            return True
    except ValueError:
        # malformed URL-like token: fail closed (mask) rather than risk leaking or crashing the hook
        return True
    return bool(_INLINE_CREDENTIAL_RE.search(token) or _INLINE_USERINFO_RE.match(token))


def _is_credential_flag(token: str) -> bool:
    return bool(_SHORT_CREDENTIAL_FLAG_RE.match(token) or _LONG_CREDENTIAL_FLAG_RE.match(token))


def _command_basename(command: str) -> str:
    name = str(command).replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in _EXECUTABLE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def redact_command_tokens(tokens: list[str]) -> list[str]:
    # POL-04: mask any token that embeds a secret before it is persisted to
    # BLOCKED_COMMANDS_ATTEMPTS.json. Covers provider tokens / high-entropy material / URL userinfo
    # (looks_secret), the "token" substring, scheme-less user:pass@host, inline credential flags
    # (--password=VALUE), the separated form (-p VALUE), the attached form (-pVALUE), and HTTP
    # basic-auth user:password after -u/--user. Over-redaction is the safe direction for a security
    # log; non-secret structure (command names, hosts, bare usernames) stays legible.
    redacted: list[str] = []
    command_name = _command_basename(str(tokens[0])) if tokens else ""
    redact_value_next = False
    redact_userinfo_next = False
    for token in tokens:
        text = str(token)
        if redact_value_next:
            redact_value_next = False
            redacted.append("<redacted>")
            continue
        if redact_userinfo_next:
            redact_userinfo_next = False
            if not text.startswith("-") and (":" in text or _token_embeds_secret(text)):
                redacted.append("<redacted>")
                continue
        attached = _ATTACHED_CREDENTIAL_RE.match(text)
        if attached:
            if command_name in _MYSQL_COMMANDS:
                redacted.append(f"{attached.group(1)}<redacted>")
                continue
        if _is_credential_flag(text):
            redact_value_next = True
        elif _token_embeds_secret(text):
            redacted.append("<redacted>")
            continue
        elif _USERINFO_FLAG_RE.match(text):
            redact_userinfo_next = True
        redacted.append(token)
    return redacted


def append_blocked_attempt(audit_dir: Path, decision: CommandDecision, evidence_ids: list[str] | None = None, attempt_id: str | None = None) -> Path:
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"]
    redacted_command = redact_command_tokens(decision.command)
    attempt = BlockedCommandAttempt(
        command=redacted_command,
        origin=decision.origin,
        decision=decision.decision,
        policy_rule=decision.policy_rule,
        evidence_ids=evidence_ids or [],
        redacted_args=redacted_command,
        attempt_id=attempt_id,
    )
    attempt_payload = asdict(attempt)
    with _blocked_attempt_lock(path):
        existing = {"schema_version": "1.0", "attempts": []}
        if path.exists():
            existing = json.loads(read_text_auto_capped(path, encoding="utf-8", label="blocked attempts"))
        attempts = existing.setdefault("attempts", [])
        duplicate_event = bool(attempt_id) and any(isinstance(item, dict) and item.get("attempt_id") == attempt_id for item in attempts)
        if not duplicate_event:
            attempts.append(attempt_payload)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
        tmp.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)
    return path


def _host_from_url_or_domain(target: str) -> str:
    try:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return parsed.hostname or target
    except ValueError:
        return target


def _network_target_error(target: str) -> tuple[str, str | None]:
    try:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or target
    except ValueError:
        return target, "invalid_url"
    if parsed.username or parsed.password:
        return domain, "userinfo_not_allowed"
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return domain, "unsupported_scheme"
    return domain, None


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


def matching_redaction_rule(payload: str | bytes | None, rules: list[object]) -> str | None:
    if payload is None:
        return None
    text = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else str(payload)
    lowered = text.lower()
    for rule in rules:
        token = str(rule).strip().lower()
        if token and token in lowered:
            return token
    return None


def decide_network(target: str, payload: str | bytes | None = None, policy: dict | None = None) -> NetworkDecision:
    if policy is None:
        return NetworkDecision("block", _host_from_url_or_domain(target), "missing_policy", "network policy snapshot is required")
    domain, target_error = _network_target_error(target)
    if target_error is not None:
        return NetworkDecision("block", domain, target_error, "network target syntax is not allowed")
    if policy.get("default") != "deny":
        return NetworkDecision("block", domain, "default_not_deny", "network policy must default deny")
    if policy.get("send_source_code") is False and classify_payload_contains_source(payload):
        return NetworkDecision("block", domain, "send_source_code_false", "source-like payload blocked")
    redaction_rules = list(policy.get("redaction_rules") or [])
    redaction_rule = matching_redaction_rule(target, redaction_rules) or matching_redaction_rule(payload, redaction_rules)
    if redaction_rule is not None:
        return NetworkDecision("block", domain, f"redaction_rule:{redaction_rule}", "network target or payload matched redaction rule")
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
