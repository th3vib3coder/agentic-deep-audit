"""Markdown report writer for validation results."""

from __future__ import annotations

from pathlib import Path

from .audit_validate_common import ValidationResult
from .models import ARTIFACT_PATHS


def write_validation_report(audit_dir: Path, result: ValidationResult, command: str) -> Path:
    path = audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]
    path.parent.mkdir(parents=True, exist_ok=True)
    blockers = result.errors
    lines = [
        "# Validation Report",
        "",
        f"- Command: `{command}`",
        f"- Status: `{'pass' if result.ok else 'blocker'}`",
        f"- Blocker count: `{len(blockers)}`",
        "",
        "## Pass",
        "",
        "- Validation engine executed.",
        "",
        "## Warn",
        "",
        "- None.",
        "",
        "## Blockers",
        "",
    ]
    if blockers:
        lines.extend(f"- {error}" for error in blockers)
    else:
        lines.append("- None.")
    lines.extend(["", "## Commands Run", "", f"- `{command}`", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
