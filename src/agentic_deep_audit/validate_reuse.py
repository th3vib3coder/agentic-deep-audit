"""Validation helpers for context-aware reuse artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .audit_reuse import DECISIONS, RECOMMENDATIONS, is_strong_copyleft_license, target_context_from
from .config import ConfigError
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = read_json_capped(path, label="reuse validation JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
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
        if not isinstance(evidence_id, str) or not re.fullmatch(r"ev-\d{6,}", evidence_id):
            errors.append(f"{location} invalid evidence id: {evidence_id!r}")
        elif evidence_id not in available:
            errors.append(f"{location} references unreachable evidence id: {evidence_id}")


def validate_target_context(location: str, value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{location} requires target_context object")
        return
    allowed = value.get("allowed_languages")
    if not isinstance(allowed, list) or not allowed:
        errors.append(f"{location} target_context.allowed_languages must be non-empty")


def validate_card(index: int, card: Any, available: set[str], errors: list[str]) -> None:
    if not isinstance(card, dict):
        errors.append(f"REUSE_CARDS.json cards[{index}] must be object")
        return
    for key in [
        "reuse_id",
        "candidate_id",
        "name",
        "problem_solved",
        "files",
        "license_status",
        "target_context",
        "recommendation",
        "decision",
        "requires_human_decision",
        "legal_caveat",
        "security_caveat",
        "performance_caveat",
        "score_inputs",
        "evidence_ids",
    ]:
        if key not in card:
            errors.append(f"REUSE_CARDS.json card {index} missing {key}")
    if card.get("decision") not in DECISIONS:
        errors.append(f"REUSE_CARDS.json card {index} invalid decision: {card.get('decision')}")
    if card.get("recommendation") not in RECOMMENDATIONS:
        errors.append(f"REUSE_CARDS.json card {index} invalid recommendation: {card.get('recommendation')}")
    if card.get("decision") != "pending":
        errors.append(f"REUSE_CARDS.json card {index} decision must be 'pending'; the tool recommends, humans decide")
    if card.get("requires_human_decision") is True and card.get("recommendation") == "adopt":
        errors.append(f"REUSE_CARDS.json card {index} cannot recommend adopt while requires_human_decision is true")
    validate_target_context(f"REUSE_CARDS.json card {index}", card.get("target_context"), errors)
    validate_evidence_ids(f"REUSE_CARDS.json cards[{index}].evidence_ids", card.get("evidence_ids"), available, errors)
    score_inputs = card.get("score_inputs")
    if not isinstance(score_inputs, dict):
        errors.append(f"REUSE_CARDS.json card {index} requires score_inputs object")
        return
    reasons = score_inputs.get("requires_human_reasons")
    if not isinstance(reasons, list):
        errors.append(f"REUSE_CARDS.json card {index} score_inputs.requires_human_reasons must be array")
        reasons = []
    if any(str(reason).startswith(("license_unknown", "strong_copyleft_conflict", "high_risk", "missing_evidence", "binary_only_dependency")) for reason in reasons):
        if card.get("requires_human_decision") is not True:
            errors.append(f"REUSE_CARDS.json card {index} blocker reason requires human decision")
        if card.get("recommendation") == "adopt":
            errors.append(f"REUSE_CARDS.json card {index} blocker reason cannot produce adopt recommendation")
    structural_blockers: list[str] = []
    license_status = str(card.get("license_status") or score_inputs.get("license_status") or "")
    if license_status in {"unknown", "conflict"}:
        structural_blockers.append(f"license_status:{license_status}")
    target_context = card.get("target_context") if isinstance(card.get("target_context"), dict) else {}
    tolerance = str(target_context.get("license_tolerance") or "")
    if is_strong_copyleft_license(score_inputs.get("license_spdx")) and tolerance != "strong-copyleft-ok":
        structural_blockers.append("strong_copyleft_spdx")
    if score_inputs.get("risk_reasons"):
        structural_blockers.append("risk_reasons")
    if score_inputs.get("binary_dependency_reasons"):
        structural_blockers.append("binary_dependency_reasons")
    if not card.get("evidence_ids"):
        structural_blockers.append("missing_evidence")
    if structural_blockers:
        if card.get("requires_human_decision") is not True:
            errors.append(f"REUSE_CARDS.json card {index} structural blocker requires human decision: {structural_blockers}")
        if card.get("recommendation") == "adopt":
            errors.append(f"REUSE_CARDS.json card {index} structural blocker cannot produce adopt recommendation: {structural_blockers}")
    for caveat_key in ["legal_caveat", "security_caveat", "performance_caveat"]:
        if not isinstance(card.get(caveat_key), str) or not card.get(caveat_key):
            errors.append(f"REUSE_CARDS.json card {index} missing non-empty {caveat_key}")


def validate_candidate_coverage(special: dict[str, Any], payload: dict[str, Any], errors: list[str]) -> None:
    candidates = special.get("candidates")
    if not isinstance(candidates, list):
        errors.append("SPECIAL_IMPLEMENTATIONS.json requires candidates array for reuse validation")
        return
    covered = {str(card.get("candidate_id")) for card in payload.get("cards", []) if isinstance(card, dict) and card.get("candidate_id")}
    skipped = {str(item.get("candidate_id")) for item in payload.get("skipped_candidates", []) if isinstance(item, dict) and item.get("candidate_id") and item.get("skipped_reason")}
    missing = [str(candidate.get("candidate_id")) for candidate in candidates if isinstance(candidate, dict) and str(candidate.get("candidate_id")) not in covered and str(candidate.get("candidate_id")) not in skipped]
    if missing:
        errors.append(f"REUSE_CARDS.json missing reuse card or skipped reason for candidates: {missing}")


def validate_scoring_sources(payload: dict[str, Any], errors: list[str]) -> None:
    sources = payload.get("scoring_input_sources")
    required = {"special_implementations", "license_status", "risk_severity", "suspicious_behaviors", "performance_notes", "tests", "binary_dependencies", "target_context"}
    if not isinstance(sources, dict):
        errors.append("REUSE_CARDS.json requires scoring_input_sources object")
        return
    missing = sorted(required - set(sources))
    if missing:
        errors.append(f"REUSE_CARDS.json missing scoring input sources: {missing}")
    for key in required & set(sources):
        if not isinstance(sources.get(key), str) or not sources.get(key):
            errors.append(f"REUSE_CARDS.json scoring_input_sources.{key} must map to artifact path")


def validate_map(audit_dir: Path, payload: dict[str, Any], errors: list[str]) -> None:
    path = audit_dir / ARTIFACT_PATHS["REUSE_MAP"]
    if not path.exists():
        errors.append(f"missing required reuse map: {path}")
        return
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="reuse map")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"REUSE_MAP.md invalid artifact: {exc}")
        return
    lowered = text.lower()
    if "legal caveat" not in lowered or "not a legal opinion" not in lowered:
        errors.append("REUSE_MAP.md missing legal caveat")
    if "target context" not in lowered or "allowed languages" not in lowered:
        errors.append("REUSE_MAP.md missing target context explanation")
    for card in payload.get("cards", []) if isinstance(payload.get("cards"), list) else []:
        if isinstance(card, dict) and card.get("name") and str(card["name"]) not in text:
            errors.append(f"REUSE_MAP.md missing reuse card: {card['name']}")


def validate_reuse_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    cards_path = audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]
    map_path = audit_dir / ARTIFACT_PATHS["REUSE_MAP"]
    if not cards_path.exists() and not map_path.exists():
        return errors
    payload = load_json(cards_path, errors) if cards_path.exists() else None
    if payload is None:
        errors.append(f"missing required reuse cards artifact: {cards_path}")
        return errors
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], errors)
    special = load_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"], errors)
    available = available_evidence(evidence_index)
    validate_scoring_sources(payload, errors)
    validate_target_context("REUSE_CARDS.json", payload.get("target_context"), errors)
    if run_config is not None:
        try:
            expected_context = target_context_from(run_config)
        except ConfigError as exc:
            errors.append(f"RUN_CONFIG.json target_context invalid for reuse validation: {exc}")
        else:
            if payload.get("target_context") != expected_context:
                errors.append("REUSE_CARDS.json target_context does not match canonical RUN_CONFIG target_context")
    cards = payload.get("cards")
    if not isinstance(cards, list):
        errors.append("REUSE_CARDS.json requires cards array")
        cards = []
    for index, card in enumerate(cards):
        validate_card(index, card, available, errors)
    if special is not None:
        validate_candidate_coverage(special, payload, errors)
    license_cards = load_json(audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"], errors)
    if license_cards is not None:
        summary = license_cards.get("summary") if isinstance(license_cards.get("summary"), dict) else {}
        root = summary.get("root_license")
        tolerance = (payload.get("target_context") or {}).get("license_tolerance") if isinstance(payload.get("target_context"), dict) else None
        if is_strong_copyleft_license(root) and tolerance != "strong-copyleft-ok":
            for index, card in enumerate(cards):
                if isinstance(card, dict) and card.get("requires_human_decision") is not True:
                    errors.append(f"REUSE_CARDS.json card {index} strong copyleft conflict must require human decision")
    validate_map(audit_dir, payload, errors)
    return errors
