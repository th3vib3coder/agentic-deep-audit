"""Validation helpers for risk and agentic security artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .audit_risk import AGENTIC_CODES, BEHAVIOR_KINDS, RISK_PROMOTION_POLICY, SUPPLY_SIGNALS
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = read_json_capped(path, label="risk validation JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"artifact root must be object: {path}")
        return None
    return payload


def available_evidence(evidence_index: dict[str, Any]) -> set[str]:
    return {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def validate_ids(location: str, ids: Any, available: set[str], errors: list[str]) -> None:
    if not isinstance(ids, list) or not ids:
        errors.append(f"{location} requires non-empty evidence_ids")
        return
    for evidence_id in ids:
        if not isinstance(evidence_id, str) or not re.fullmatch(r"ev-\d{6,}", evidence_id):
            errors.append(f"{location} contains invalid evidence id: {evidence_id!r}")
        elif evidence_id not in available:
            errors.append(f"{location} references unreachable evidence id: {evidence_id}")


def validate_suspicious(audit_dir: Path, available: set[str], errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"]
    if not path.exists():
        return
    payload = load_json(path, errors)
    if payload is None:
        return
    behaviors = payload.get("behaviors")
    if not isinstance(behaviors, list):
        errors.append("SUSPICIOUS_BEHAVIORS.json requires behaviors array")
        return
    for index, behavior in enumerate(behaviors):
        if not isinstance(behavior, dict):
            errors.append(f"SUSPICIOUS_BEHAVIORS.json behaviors[{index}] must be object")
            continue
        for key in ["behavior_id", "kind", "severity", "confidence", "source", "recommendation"]:
            if not behavior.get(key):
                errors.append(f"SUSPICIOUS_BEHAVIORS.json behavior {index} missing {key}")
        if behavior.get("kind") not in BEHAVIOR_KINDS:
            errors.append(f"SUSPICIOUS_BEHAVIORS.json unknown behavior kind: {behavior.get('kind')}")
        validate_ids(f"SUSPICIOUS_BEHAVIORS.json behaviors[{index}].evidence_ids", behavior.get("evidence_ids"), available, errors)


def validate_risk_findings(audit_dir: Path, available: set[str], errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"]
    if not path.exists():
        return
    payload = load_json(path, errors)
    if payload is None:
        return
    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append("RISK_FINDINGS.json requires findings array")
        return
    if payload.get("promotion_policy") != RISK_PROMOTION_POLICY:
        errors.append("RISK_FINDINGS.json must document heuristic promotion policy")
    if not isinstance(payload.get("source_tools"), list):
        errors.append("RISK_FINDINGS.json requires source_tools array")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            errors.append(f"RISK_FINDINGS.json findings[{index}] must be object")
            continue
        if finding.get("source_kind") not in {"external_tool", "heuristic_promoted_with_tool_confirmation"}:
            errors.append(f"RISK_FINDINGS.json finding {index} invalid source_kind: {finding.get('source_kind')}")
        for key in ["finding_id", "category", "severity", "confidence", "recommendation"]:
            if not finding.get(key):
                errors.append(f"RISK_FINDINGS.json finding {index} missing {key}")
        validate_ids(f"RISK_FINDINGS.json findings[{index}].evidence_ids", finding.get("evidence_ids"), available, errors)


def validate_agentic(audit_dir: Path, available: set[str], errors: list[str]) -> None:
    json_path = audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY_FINDINGS"]
    report_path = audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY"]
    if not json_path.exists() and not report_path.exists():
        return
    payload = load_json(json_path, errors) if json_path.exists() else None
    if payload is None:
        errors.append(f"missing required agentic security artifact: {json_path}")
        return
    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append("AGENTIC_SECURITY_FINDINGS.json requires findings array")
        findings = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            errors.append(f"AGENTIC_SECURITY_FINDINGS.json findings[{index}] must be object")
            continue
        code = finding.get("code")
        if code not in AGENTIC_CODES and not (finding.get("external_raw_upstream") is True and finding.get("caveat")):
            errors.append(f"AGENTIC_SECURITY_FINDINGS.json unknown code: {code}")
        validate_ids(f"AGENTIC_SECURITY_FINDINGS.json findings[{index}].evidence_ids", finding.get("evidence_ids"), available, errors)
    if not report_path.exists():
        errors.append(f"missing required agentic security report: {report_path}")
        return
    try:
        text = read_text_auto_capped(report_path, encoding="utf-8", errors="replace", label="agentic security report")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"AGENTIC_SECURITY.md invalid artifact: {exc}")
        return
    for item in payload.get("scanned_files") or []:
        if isinstance(item, dict) and item.get("path") and str(item["path"]) not in text:
            errors.append(f"AGENTIC_SECURITY.md missing scanned file: {item['path']}")
    for item in payload.get("skipped_files") or []:
        if isinstance(item, dict) and item.get("path") and str(item["path"]) not in text:
            errors.append(f"AGENTIC_SECURITY.md missing skipped file: {item['path']}")


def validate_supply_chain(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["SUPPLY_CHAIN_SIGNALS"]
    if not path.exists():
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="supply chain report")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"SUPPLY_CHAIN_SIGNALS.md invalid artifact: {exc}")
        return
    for signal in SUPPLY_SIGNALS:
        if f"| {signal} |" not in text:
            errors.append(f"SUPPLY_CHAIN_SIGNALS.md missing signal row: {signal}")
    for line in text.splitlines():
        if line.startswith("| ") and "| observed | low |" in line and "ev-" not in line:
            errors.append("SUPPLY_CHAIN_SIGNALS.md low-confidence observed row requires evidence")
        if line.startswith("| ") and "| observed | low |" in line and "heuristic" not in line.lower():
            errors.append("SUPPLY_CHAIN_SIGNALS.md low-confidence observed row requires caveat")


def validate_risk_report(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["RISK_REPORT"]
    if not path.exists():
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="risk report").lower()
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"RISK_REPORT.md invalid artifact: {exc}")
        return
    if "cannot claim absence of vulnerabilities" not in text:
        errors.append("RISK_REPORT.md must state it cannot claim absence of vulnerabilities")
    if "tools skipped" not in text:
        errors.append("RISK_REPORT.md must state tools skipped")


def validate_risk_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    available = available_evidence(evidence_index)
    validate_suspicious(audit_dir, available, errors)
    validate_risk_findings(audit_dir, available, errors)
    validate_agentic(audit_dir, available, errors)
    validate_supply_chain(audit_dir, errors)
    validate_risk_report(audit_dir, errors)
    return errors
