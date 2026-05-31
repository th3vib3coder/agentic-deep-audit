"""Gate enforcement for Agentic Deep Audit repository changes."""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .audit_provenance import GIT_SAFE_CONFIG, git_probe_env, safe_git_executable
from .limits import read_text_auto_capped


PROJECT_SURFACE_PATTERNS: tuple[str, ...] = (
    ".claude-plugin/**",
    ".codex-plugin/**",
    ".github/**",
    "assets/**",
    "docs/**",
    "hooks/**",
    "policies/**",
    "skills/**",
    "src/**",
    "tests/**",
    "README.md",
    "RELEASE_CHECKLIST.md",
    "REVIEW*.md",
    "pyproject.toml",
)


# Shipped defaults carry NO private planning paths. A planning workspace supplies its own
# planning surface (e.g. its implementation/ledger globs) at runtime via --planning-surface;
# the shipped product gates only its own project surface (operator_go).
GATE_POLICY: dict[str, list[str]] = {
    "implementation_realign": [],
    "operator_go": list(PROJECT_SURFACE_PATTERNS),
}

SENSITIVE_PATHS: tuple[str, ...] = tuple(PROJECT_SURFACE_PATTERNS)


@dataclass(frozen=True)
class GateDecision:
    gate: str
    path: str
    allowed: bool
    reason: str


def normalize_repo_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def path_matches(path: str, patterns: Iterable[str]) -> bool:
    normalized = normalize_repo_path(path)
    return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in patterns)


def extract_current_gate(ledger_text: str) -> str:
    for line in ledger_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Stato corrente:"):
            if "`" in stripped:
                return stripped.split("`", 2)[1]
            return stripped.split(":", 1)[1].strip()
    raise ValueError("current gate not found in ledger")


def read_current_gate(ledger_path: Path) -> str:
    return extract_current_gate(read_text_auto_capped(ledger_path, encoding="utf-8", errors="replace", label="gate ledger"))


def decide_path(
    gate: str,
    path: str,
    *,
    sensitive_paths: Iterable[str] | None = None,
    gate_policy: dict[str, list[str]] | None = None,
) -> GateDecision:
    sensitive = SENSITIVE_PATHS if sensitive_paths is None else sensitive_paths
    policy = GATE_POLICY if gate_policy is None else gate_policy
    normalized = normalize_repo_path(path)
    if not path_matches(normalized, sensitive):
        return GateDecision(gate, normalized, True, "path is outside gated surfaces")
    if path_matches(normalized, policy.get(gate, [])):
        return GateDecision(gate, normalized, True, f"path allowed by gate {gate}")
    return GateDecision(gate, normalized, False, f"path requires a different gate: {path}")


def changed_paths(repo_root: Path, base: str) -> list[str]:
    git_path, skipped_reason = safe_git_executable(repo_root)
    if skipped_reason is not None or git_path is None:
        raise RuntimeError(skipped_reason or "git executable unavailable")
    committed = subprocess.run(
        [git_path, *GIT_SAFE_CONFIG, "diff", "--name-only", base, "--"],
        cwd=repo_root,
        env=git_probe_env(),
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    untracked = subprocess.run(
        [git_path, *GIT_SAFE_CONFIG, "ls-files", "--others", "--exclude-standard"],
        cwd=repo_root,
        env=git_probe_env(),
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    paths = set()
    if committed.returncode == 0:
        paths.update(line for line in committed.stdout.splitlines() if line)
    if untracked.returncode == 0:
        paths.update(line for line in untracked.stdout.splitlines() if line)
    return sorted(paths)


def check_paths(repo_root: Path, ledger_path: Path, base: str, explicit_paths: list[str], planning_surface: Iterable[str] = ()) -> int:
    gate = read_current_gate(ledger_path)
    planning = tuple(planning_surface)
    sensitive = tuple(SENSITIVE_PATHS) + planning
    policy = {key: list(value) for key, value in GATE_POLICY.items()}
    if planning:
        policy["implementation_realign"] = list(planning)
    paths = explicit_paths or changed_paths(repo_root, base)
    print(f"current gate: {gate}")
    blocked: list[GateDecision] = []
    for path in paths:
        decision = decide_path(gate, path, sensitive_paths=sensitive, gate_policy=policy)
        status = "ALLOW" if decision.allowed else "DENY"
        print(f"{status} {decision.path} - {decision.reason}")
        if not decision.allowed:
            blocked.append(decision)
    return 1 if blocked else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agentic_deep_audit.gate")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check-paths")
    check.add_argument("--base", default="HEAD")
    check.add_argument("--repo-root", default=".")
    check.add_argument("--ledger", required=True)
    check.add_argument("--path", action="append", default=[])
    check.add_argument(
        "--planning-surface",
        action="append",
        default=[],
        help="extra glob(s) defining the local planning surface (implementation_realign); none ship by default",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check-paths":
        repo_root = Path(args.repo_root).resolve()
        ledger_path = Path(args.ledger)
        if not ledger_path.is_absolute():
            ledger_path = repo_root / ledger_path
        return check_paths(repo_root, ledger_path, args.base, args.path, args.planning_surface)
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
