from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REQUIRED_FIELDS = ["Target:", "Refs:", "Verify:"]
STEP_RE = re.compile(r"^- \[.\] Step (?P<id>\d{3}\.\w+) - (?P<title>.+)$")


@dataclass(frozen=True)
class Violation:
    path: str
    step: str
    message: str


def step_blocks(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    blocks: list[tuple[str, str]] = []
    current_id: str | None = None
    current: list[str] = []
    for line in lines:
        match = STEP_RE.match(line)
        if match:
            if current_id is not None:
                blocks.append((current_id, "\n".join(current)))
            current_id = match.group("id")
            current = [line]
            continue
        if current_id is not None:
            current.append(line)
    if current_id is not None:
        blocks.append((current_id, "\n".join(current)))
    return blocks


def lint_plan_file(path: Path, root: Path) -> list[Violation]:
    text = path.read_text(encoding="utf-8", errors="replace")
    relative = path.relative_to(root).as_posix()
    violations: list[Violation] = []
    blocks = step_blocks(text)
    if not blocks:
        violations.append(Violation(relative, "N/A", "no step blocks"))
        return violations
    for step_id, block in blocks:
        for field in REQUIRED_FIELDS:
            if field not in block:
                violations.append(Violation(relative, step_id, f"missing {field}"))
    return violations


def lint_plan(plan_dir: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(plan_dir.glob("*_seq_*.md")):
        if path.name in {"000_index.md", "900_traceability_to_general_plan.md", "901_internal_review_notes.md", "902_claude_review_packet.md"}:
            continue
        violations.extend(lint_plan_file(path, plan_dir))
    return violations


def write_report(output: Path, plan_dir: Path, violations: list[Violation]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Sequence Atomicity Report",
        "",
        f"- Plan dir: `{plan_dir}`",
        f"- Status: `{'pass' if not violations else 'blocker'}`",
        f"- Violation count: `{len(violations)}`",
        "",
        "## Violations",
        "",
    ]
    if violations:
        lines.extend(f"- `{violation.path}` step `{violation.step}`: {violation.message}" for violation in violations)
    else:
        lines.append("- None.")
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-dir", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    plan_dir = Path(args.plan_dir)
    output = Path(args.output)
    violations = lint_plan(plan_dir)
    write_report(output, plan_dir, violations)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
