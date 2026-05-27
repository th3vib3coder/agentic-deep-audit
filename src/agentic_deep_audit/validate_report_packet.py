"""Validation for final report, open questions, review ledger and packet."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .audit_report import GOAL_SECTION_IDS, skipped_artifacts, validation_passed
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


def validate_report_artifacts(audit_dir: Path) -> list[str]:
    errors: list[str] = []
    validate_report(audit_dir, errors)
    validate_open_questions(audit_dir, errors)
    validate_review_ledger(audit_dir, errors)
    validate_review_packet(audit_dir, errors)
    return errors


def validate_report(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["REPORT"]
    if not path.exists():
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="report")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"REPORT.md invalid artifact: {exc}")
        return
    for section_id in GOAL_SECTION_IDS:
        if f"## {section_id} -" not in text:
            errors.append(f"REPORT.md missing goal question section: {section_id}")
    for required in ["Profile:", "Coverage statement:", "Validation status:"]:
        if required not in text:
            errors.append(f"REPORT.md missing coverage/profile statement: {required}")


def validate_open_questions(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["OPEN_QUESTIONS"]
    if not path.exists():
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="open questions")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"OPEN_QUESTIONS.md invalid artifact: {exc}")
        return
    for artifact, _reason in skipped_artifacts(audit_dir):
        if artifact not in text:
            errors.append(f"OPEN_QUESTIONS.md missing skipped artifact: {artifact}")
    if "Human decision required:" not in text:
        errors.append("OPEN_QUESTIONS.md missing human decision line")


def validate_review_ledger(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["REVIEW_LEDGER"]
    if not path.exists():
        return
    try:
        lines = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="review ledger").splitlines()
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"REVIEW_LEDGER.md invalid artifact: {exc}")
        return
    for line in lines:
        if not line.startswith("| `"):
            continue
        cells = [cell.strip(" `") for cell in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        _artifact, author, reviewer, decision = cells[:4]
        if re.search(r"\bACCEPT(?:ED)?\b", decision, flags=re.IGNORECASE) and author.casefold() == reviewer.casefold():
            errors.append(f"REVIEW_LEDGER.md self-acceptance row: {author}")


def validate_review_packet(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]
    if not path.exists():
        run_config_path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
        if run_config_path.exists():
            try:
                run_config = read_json_capped(run_config_path, label="run config")
            except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
                errors.append(f"RUN_CONFIG.json invalid while checking review readiness: {exc}")
                return
            if isinstance(run_config, dict) and run_config.get("ready_for_review") is True:
                errors.append("ADVERSARIAL_REVIEW_PACKET.md missing while RUN_CONFIG.json ready_for_review is true")
        return
    if not validation_passed(audit_dir):
        errors.append("ADVERSARIAL_REVIEW_PACKET.md exists before zero-blocker validation")
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="review packet")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"ADVERSARIAL_REVIEW_PACKET.md invalid artifact: {exc}")
        return
    for section in ["## Artifact Inventory", "## Skipped Artifacts", "## Commands Run", "## Fixture Results", "## Residual Risks"]:
        if section not in text:
            errors.append(f"ADVERSARIAL_REVIEW_PACKET.md missing section: {section}")
    if "| Artifact | Size Bytes | SHA256 |" not in text:
        errors.append("ADVERSARIAL_REVIEW_PACKET.md missing exact artifact inventory table")
