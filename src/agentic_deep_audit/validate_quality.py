"""Validation helpers for performance, quality, test and runtime artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


PHASE_NAMES = {"bootstrap", "inventory", "provenance", "manifest", "graph", "surface", "synthesis", "scientific", "telemetry", "risk_security", "license_binary", "performance_quality"}


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = read_json_capped(path, label="quality validation JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"artifact root must be object: {path}")
        return None
    return payload


def available_evidence(evidence_index: dict[str, Any]) -> set[str]:
    return {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def validate_markdown_evidence(path: Path, available: set[str], errors: list[str]) -> None:
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="quality markdown")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"{path.name} invalid markdown artifact: {exc}")
        return
    for evidence_id in re.findall(r"ev-\d{6,}", text):
        if evidence_id not in available:
            errors.append(f"{path.name} references unreachable evidence id: {evidence_id}")


def validate_performance_report(audit_dir: Path, available: set[str], errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["PERFORMANCE_REVIEW"]
    if not path.exists():
        errors.append(f"missing required performance artifact: {path}")
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="performance report")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"PERFORMANCE_REVIEW.md invalid artifact: {exc}")
        return
    validate_markdown_evidence(path, available, errors)
    lowered = text.lower()
    if "audited project performance" not in lowered:
        errors.append("PERFORMANCE_REVIEW.md must identify audited-project performance scope")
    if "static proxy signals are not runtime benchmarks" not in lowered:
        errors.append("PERFORMANCE_REVIEW.md missing observed/proxy distinction")
    if "proxy benchmark" in lowered or "static benchmark" in lowered:
        errors.append("PERFORMANCE_REVIEW.md must not describe static proxy as benchmark")
    if "claim-only" in lowered and "performance claims from docs" not in lowered:
        errors.append("PERFORMANCE_REVIEW.md claim-only rows require claims section")


def validate_quality_report(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["QUALITY_REVIEW"]
    if not path.exists():
        errors.append(f"missing required quality artifact: {path}")
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="quality report").lower()
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"QUALITY_REVIEW.md invalid artifact: {exc}")
        return
    if "evidence-weighted quality signal" not in text or "not a production readiness score" not in text:
        errors.append("QUALITY_REVIEW.md missing evidence caveat")


def validate_test_coverage_signal(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"]
    if not path.exists():
        errors.append(f"missing required test coverage artifact: {path}")
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="test coverage signal")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"TEST_COVERAGE_SIGNAL.md invalid artifact: {exc}")
        return
    lowered = text.lower()
    if "no runtime coverage percentage is claimed unless a coverage artifact is present" not in lowered:
        errors.append("TEST_COVERAGE_SIGNAL.md missing no-invented-coverage caveat")
    artifact_count = re.search(r"Coverage artifact files observed:\s+(\d+)\b", text)
    if artifact_count is None:
        errors.append("TEST_COVERAGE_SIGNAL.md missing coverage artifact count")
        return
    if int(artifact_count.group(1)) == 0 and re.search(r"\b\d+(?:\.\d+)?%", text):
        errors.append("TEST_COVERAGE_SIGNAL.md invents numeric coverage without coverage artifact")


def validate_non_negative_int(payload: dict[str, Any], key: str, errors: list[str], label: str | None = None) -> None:
    if not isinstance(payload.get(key), int) or payload.get(key) < 0:
        display = label or key
        errors.append(f"AUDIT_RUNTIME_METRICS.json requires non-negative integer {display}")


def validate_runtime_metrics(audit_dir: Path, errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"]
    payload = load_json(path, errors) if path.exists() else None
    if payload is None:
        errors.append(f"missing required runtime metrics artifact: {path}")
        return
    if "audit plugin, not the audited project" not in " ".join(str(note) for note in payload.get("notes", [])):
        errors.append("AUDIT_RUNTIME_METRICS.json missing plugin-vs-project scope note")
    for key in ["files_processed", "bytes_processed", "output_bytes", "cache_hits", "cache_misses", "tool_failures"]:
        validate_non_negative_int(payload, key, errors)
    token_proxy = payload.get("token_proxy")
    if not isinstance(token_proxy, dict):
        errors.append("AUDIT_RUNTIME_METRICS.json requires token_proxy object")
    else:
        for key in ["bytes_read", "estimated_tokens", "bytes_sent_to_agent"]:
            validate_non_negative_int(token_proxy, key, errors, f"token_proxy.{key}")
    memory = payload.get("memory_peak")
    if not isinstance(memory, dict):
        errors.append("AUDIT_RUNTIME_METRICS.json requires memory_peak object")
    else:
        status = memory.get("status")
        if status not in {"skipped", "observed"}:
            errors.append("AUDIT_RUNTIME_METRICS.json memory_peak status must be skipped or observed")
        if status == "skipped":
            if not isinstance(memory.get("skipped_reason"), str) or not memory.get("skipped_reason"):
                errors.append("AUDIT_RUNTIME_METRICS.json skipped memory_peak requires skipped_reason")
            if memory.get("value") == 0:
                errors.append("AUDIT_RUNTIME_METRICS.json memory skipped metric must not be encoded as zero")
        if status == "observed" and (not isinstance(memory.get("value"), int) or memory.get("value") < 0):
            errors.append("AUDIT_RUNTIME_METRICS.json observed memory_peak requires non-negative integer value")
    phases = payload.get("phase_durations_ms")
    if not isinstance(phases, dict):
        errors.append("AUDIT_RUNTIME_METRICS.json requires phase_durations_ms object")
        return
    missing = sorted(PHASE_NAMES - set(phases))
    if missing:
        errors.append(f"AUDIT_RUNTIME_METRICS.json missing phase entries: {missing}")
    for name, value in phases.items():
        if isinstance(value, int):
            continue
        if not isinstance(value, dict):
            errors.append(f"AUDIT_RUNTIME_METRICS.json phase {name} must be object or integer")
            continue
        has_duration = isinstance(value.get("duration_ms"), int)
        has_skip = isinstance(value.get("skipped_reason"), str) and bool(value.get("skipped_reason"))
        if not has_duration and not has_skip:
            errors.append(f"AUDIT_RUNTIME_METRICS.json phase {name} requires duration_ms or skipped_reason")

def validate_performance_quality_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    available = available_evidence(evidence_index)
    validate_performance_report(audit_dir, available, errors)
    validate_quality_report(audit_dir, errors)
    validate_test_coverage_signal(audit_dir, errors)
    validate_runtime_metrics(audit_dir, errors)
    return errors
