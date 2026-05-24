"""Validation helpers for license, SBOM and binary artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .audit_license_binary import SCOPED_LICENSE_KINDS, record_path
from .models import ARTIFACT_PATHS


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


def available_evidence(evidence_index: dict[str, Any]) -> set[str]:
    return {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def validate_evidence_ids(location: str, evidence_ids: Any, available: set[str], errors: list[str]) -> None:
    if not isinstance(evidence_ids, list) or not evidence_ids:
        errors.append(f"{location} requires non-empty evidence_ids")
        return
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or not re.fullmatch(r"ev-\d{6}", evidence_id):
            errors.append(f"{location} invalid evidence id: {evidence_id!r}")
        elif evidence_id not in available:
            errors.append(f"{location} references unreachable evidence id: {evidence_id}")


def license_denominator(file_index: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for record in file_index.get("records", []):
        if isinstance(record, dict) and record.get("kind") in SCOPED_LICENSE_KINDS and record.get("binary") is False:
            paths.add(record_path(record))
    return paths


def validate_license_artifacts(audit_dir: Path, evidence_index: dict[str, Any], file_index: dict[str, Any], errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"]
    matrix_path = audit_dir / ARTIFACT_PATHS["LICENSE_MATRIX"]
    if not path.exists() and not matrix_path.exists():
        return
    payload = load_json(path, errors) if path.exists() else None
    if payload is None:
        errors.append(f"missing required license cards artifact: {path}")
        return
    available = available_evidence(evidence_index)
    cards = payload.get("cards")
    if not isinstance(cards, list):
        errors.append("LICENSE_CARDS.json requires cards array")
        cards = []
    covered_paths: set[str] = set()
    for index, card in enumerate(cards):
        if not isinstance(card, dict):
            errors.append(f"LICENSE_CARDS.json cards[{index}] must be object")
            continue
        for key in ["card_id", "kind", "confidence", "detection_method", "requires_human_decision"]:
            if key not in card:
                errors.append(f"LICENSE_CARDS.json card {index} missing {key}")
        if card.get("kind") == "file":
            path_value = str(card.get("path") or "")
            covered_paths.add(path_value)
            validate_evidence_ids(f"LICENSE_CARDS.json cards[{index}].evidence_ids", card.get("evidence_ids"), available, errors)
            if card.get("declared_license") is None and not card.get("skipped_reason"):
                errors.append(f"LICENSE_CARDS.json file card {path_value} without license requires skipped_reason")
        if card.get("kind") == "dependency":
            if not card.get("component"):
                errors.append(f"LICENSE_CARDS.json dependency card {index} missing component")
            validate_evidence_ids(f"LICENSE_CARDS.json cards[{index}].evidence_ids", card.get("evidence_ids"), available, errors)
    missing = sorted(license_denominator(file_index) - covered_paths)
    if missing:
        errors.append(f"LICENSE_CARDS.json missing file coverage for denominator paths: {missing}")
    summary = payload.get("summary")
    if isinstance(summary, dict):
        denominator_paths = license_denominator(file_index)
        denominator_cards = [card for card in cards if isinstance(card, dict) and card.get("kind") == "file" and card.get("path") in denominator_paths]
        denominator = len(denominator_cards)
        known = len([card for card in denominator_cards if card.get("declared_license") and not str(card.get("detection_method", "")).startswith("skipped:")])
        expected = round(known / denominator, 3) if denominator else 1.0
        if summary.get("file_denominator") != denominator or summary.get("file_license_known") != known or summary.get("file_license_known_rate") != expected:
            errors.append("LICENSE_CARDS.json summary denominator/numerator/rate mismatch")
    if not matrix_path.exists():
        errors.append(f"missing required license matrix: {matrix_path}")
    else:
        text = matrix_path.read_text(encoding="utf-8").lower()
        if "legal review required for reuse" not in text or "not a final legal opinion" not in text:
            errors.append("LICENSE_MATRIX.md missing legal-review caveat")


def validate_sbom_state(audit_dir: Path, errors: list[str]) -> None:
    sbom = audit_dir / ARTIFACT_PATHS["SBOM"]
    skipped = audit_dir / ARTIFACT_PATHS["SBOM_SKIPPED"]
    if sbom.exists() == skipped.exists():
        errors.append("exactly one of SBOM.cdx.json or SBOM_SKIPPED.md must exist")
    if skipped.exists() and "No promoted SBOM adapter" not in skipped.read_text(encoding="utf-8"):
        errors.append("SBOM_SKIPPED.md missing promoted-adapter skip reason")


def validate_binary_artifacts(audit_dir: Path, evidence_index: dict[str, Any], run_config: dict[str, Any], errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["BINARY_ARTIFACTS"]
    if not path.exists():
        return
    payload = load_json(path, errors)
    if payload is None:
        return
    available = available_evidence(evidence_index)
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("BINARY_ARTIFACTS.json requires artifacts array")
        artifacts = []
    consent = run_config.get("binary_triage_consent") is True
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"BINARY_ARTIFACTS.json artifacts[{index}] must be object")
            continue
        for key in ["artifact_id", "path", "kind", "size_bytes", "triage_triggered", "requires_operator_consent"]:
            if key not in artifact:
                errors.append(f"BINARY_ARTIFACTS.json artifact {index} missing {key}")
        validate_evidence_ids(f"BINARY_ARTIFACTS.json artifacts[{index}].evidence_ids", artifact.get("evidence_ids"), available, errors)
        if artifact.get("triage_triggered") is True and not consent:
            errors.append("BINARY_ARTIFACTS.json triage_triggered without binary_triage_consent")
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        errors.append("BINARY_ARTIFACTS.json requires summary object")
        return
    total_bytes = sum(int(artifact.get("size_bytes") or 0) for artifact in artifacts if isinstance(artifact, dict))
    native_count = sum(1 for artifact in artifacts if isinstance(artifact, dict) and artifact.get("kind") == "native_binary")
    mismatch_count = sum(1 for artifact in artifacts if isinstance(artifact, dict) and artifact.get("mime_mismatch") is True)
    if summary.get("blob_count") != len(artifacts):
        errors.append("BINARY_ARTIFACTS.json blob_count mismatch")
    if summary.get("total_binary_bytes") != total_bytes:
        errors.append("BINARY_ARTIFACTS.json total_binary_bytes mismatch")
    if summary.get("native_binary_count") != native_count:
        errors.append("BINARY_ARTIFACTS.json native_binary_count mismatch")
    if summary.get("mime_mismatch_count") != mismatch_count:
        errors.append("BINARY_ARTIFACTS.json mime_mismatch_count mismatch")
    if summary.get("triage_triggered") is True and not consent:
        errors.append("BINARY_ARTIFACTS.json summary triage_triggered without binary_triage_consent")


def validate_license_binary_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"], errors)
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], errors)
    if file_index is None or run_config is None:
        return errors
    validate_license_artifacts(audit_dir, evidence_index, file_index, errors)
    if any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in ["LICENSE_CARDS", "LICENSE_MATRIX", "BINARY_ARTIFACTS", "SBOM", "SBOM_SKIPPED"]):
        validate_sbom_state(audit_dir, errors)
    validate_binary_artifacts(audit_dir, evidence_index, run_config, errors)
    return errors
