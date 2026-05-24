"""Project telemetry validation helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS


REQUIRED_PARAMETERS = {"time_window_days", "from_ref", "to_ref", "bot_filter", "identity_normalization"}
EXPECTED_CATEGORIES = {
    "changelog_parsing",
    "release_cadence",
    "contributors_graph",
    "bus_factor_proxy",
    "ownership_concentration",
    "dependency_upgrade_churn",
    "api_doc_extraction",
    "commit_message_quality_signal",
    "issue_pr_signals",
}


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"artifact root must be object: {path}")
        return None
    return payload


def validate_project_telemetry_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    available = {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}
    path = audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY"]
    report_path = audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY_MD"]
    payload = load_json(path, errors) if path.exists() else None
    if payload is None:
        errors.append(f"missing required project telemetry artifact: {path}")
        return errors
    records = payload.get("records")
    if not isinstance(records, list):
        errors.append("PROJECT_TELEMETRY.json requires records array")
        records = []
    categories: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"PROJECT_TELEMETRY.json records[{index}] must be object")
            continue
        record_id = str(record.get("telemetry_id") or "")
        if not re.fullmatch(r"tel-\d{6}", record_id):
            errors.append(f"PROJECT_TELEMETRY.json invalid telemetry_id: {record_id or index}")
        categories.append(str(record.get("category") or ""))
        params = record.get("parameters")
        if not isinstance(params, dict) or not REQUIRED_PARAMETERS <= set(params):
            errors.append(f"PROJECT_TELEMETRY.json record {record_id or index} missing required parameters")
        if record.get("status") == "skipped" and not record.get("limitations"):
            errors.append(f"PROJECT_TELEMETRY.json skipped record {record_id or index} requires limitations")
        if record.get("status") == "observed" and record.get("value") is None:
            errors.append(f"PROJECT_TELEMETRY.json observed record {record_id or index} requires value")
        for evidence_id in record.get("evidence_ids") or []:
            if evidence_id not in available:
                errors.append(f"PROJECT_TELEMETRY.json record {record_id or index} references unreachable evidence id: {evidence_id}")
    category_counts = {category: categories.count(category) for category in set(categories)}
    if set(categories) != EXPECTED_CATEGORIES or any(count != 1 for count in category_counts.values()):
        missing = sorted(EXPECTED_CATEGORIES - set(categories))
        extra = sorted(set(categories) - EXPECTED_CATEGORIES)
        duplicates = sorted(category for category, count in category_counts.items() if count > 1)
        errors.append(f"PROJECT_TELEMETRY.json must contain exactly one record per expected category; missing={missing}; extra={extra}; duplicates={duplicates}")
    if not report_path.exists():
        errors.append(f"missing required project telemetry report: {report_path}")
        return errors
    text = report_path.read_text(encoding="utf-8")
    headings = re.findall(r"^##\s+(.+)$", text, flags=re.MULTILINE)
    if sorted(headings) != sorted(categories):
        errors.append("PROJECT_TELEMETRY.md section categories do not match PROJECT_TELEMETRY.json records")
    return errors
