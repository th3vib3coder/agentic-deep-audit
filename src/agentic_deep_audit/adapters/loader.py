"""Adapter promotion-gate loader."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .base import AdapterError, ToolAdapter
from ..limits import FileSizeLimitError, read_json_capped


CORE_CLASS = "core"
KNOWN_PROVENANCE_CLASSES = {CORE_CLASS, "source-claim", "industry-known"}
PREPROMOTION_CLASSES = {"source-claim", "industry-known"}
DEFERRED_BY_DEFAULT = {"graphify", "madge", "pydeps", "osv", "osv-scanner"}
CORE_ADAPTER_IDS = {"python_probe", "cwd_probe"}
MIN_DECISION_DATE = date(2026, 1, 1)


class AdapterBlockedPrePromotion(AdapterError):
    """Raised when an optional adapter lacks a promote decision."""


@dataclass(frozen=True)
class AdapterDecision:
    adapter_id: str
    decision: str
    path: Path
    payload: dict[str, Any]


def adapter_decision_path(plugin_root: Path, adapter_id: str) -> Path:
    return plugin_root / "docs" / "adapters" / adapter_id / "adapter_decision.json"


def load_adapter_decision(plugin_root: Path, adapter_id: str) -> AdapterDecision:
    path = adapter_decision_path(plugin_root, adapter_id)
    if not path.exists():
        raise AdapterBlockedPrePromotion(f"adapter_blocked_pre_promotion: missing decision JSON for {adapter_id}")
    try:
        payload = read_json_capped(path, label="adapter decision JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
        raise AdapterBlockedPrePromotion(f"adapter_blocked_pre_promotion: invalid decision JSON for {adapter_id}: {exc}") from exc
    try:
        validate_adapter_decision_payload(payload)
    except ValueError as exc:
        raise AdapterBlockedPrePromotion(f"adapter_blocked_pre_promotion: schema-invalid decision JSON for {adapter_id}: {exc}") from exc
    if payload["adapter_id"] != adapter_id:
        raise AdapterBlockedPrePromotion(
            f"adapter_blocked_pre_promotion: decision JSON adapter_id {payload['adapter_id']} does not match {adapter_id}"
        )
    decision = str(payload.get("decision"))
    if decision != "promote":
        raise AdapterBlockedPrePromotion(f"adapter_blocked_pre_promotion: {adapter_id} decision is {decision}")
    return AdapterDecision(adapter_id=adapter_id, decision=decision, path=path, payload=payload)


def normalize_provenance_class(provenance_class: Any) -> str:
    if not isinstance(provenance_class, str):
        raise AdapterBlockedPrePromotion("adapter_blocked_pre_promotion: provenance_class must be a string")
    normalized = provenance_class.strip().lower()
    if normalized not in KNOWN_PROVENANCE_CLASSES:
        raise AdapterBlockedPrePromotion(f"adapter_blocked_pre_promotion: unknown provenance_class {provenance_class!r}")
    return normalized


def validate_adapter_promotion(plugin_root: Path, adapter_id: str, provenance_class: str) -> AdapterDecision | None:
    normalized_class = normalize_provenance_class(provenance_class)
    if normalized_class == CORE_CLASS and adapter_id not in CORE_ADAPTER_IDS:
        return load_adapter_decision(plugin_root, adapter_id)
    if normalized_class in PREPROMOTION_CLASSES or adapter_id in DEFERRED_BY_DEFAULT:
        return load_adapter_decision(plugin_root, adapter_id)
    return None


def load_adapter(adapter: ToolAdapter, plugin_root: Path) -> ToolAdapter:
    validate_adapter_promotion(plugin_root, adapter.adapter_id, adapter.provenance_class)
    return adapter


def validate_adapter_decision_payload(payload: dict[str, Any]) -> None:
    required = [
        "adapter_id",
        "installability",
        "license",
        "version_pinning",
        "command_readonly",
        "policy_applied",
        "schema_output_observed",
        "fallback",
        "decision",
        "reviewer",
        "decision_date",
    ]
    for key in required:
        if key not in payload:
            raise ValueError(f"missing {key}")
    installability = payload["installability"]
    if not isinstance(installability, dict) or not isinstance(installability.get("os"), list) or not installability["os"] or not isinstance(installability.get("notes"), str):
        raise ValueError("installability must contain non-empty os list and notes")
    license_info = payload["license"]
    if not isinstance(license_info, dict) or not isinstance(license_info.get("spdx"), str) or not isinstance(license_info.get("compatible_with_target_context"), bool):
        raise ValueError("license must contain spdx and compatible_with_target_context")
    version = payload["version_pinning"]
    if not isinstance(version, dict) or version.get("strategy") not in {"exact", "minimum", "range", "system", "bundled"} or "min_version" not in version:
        raise ValueError("version_pinning must contain valid strategy and min_version")
    if not isinstance(payload.get("command_readonly"), str) or not payload["command_readonly"]:
        raise ValueError("command_readonly must be non-empty string")
    allowed_policies = {"no-exec", "read-only", "network-deny-default", "redaction", "sandbox", "path-containment"}
    policies = payload["policy_applied"]
    if not isinstance(policies, list) or not policies or any(policy not in allowed_policies for policy in policies):
        raise ValueError("policy_applied must contain known policy values")
    observed = payload["schema_output_observed"]
    if not isinstance(observed, dict) or not isinstance(observed.get("sample_path"), str) or not isinstance(observed.get("hash"), str):
        raise ValueError("schema_output_observed must contain sample_path and hash")
    if payload.get("decision") not in {"promote", "defer", "reject"}:
        raise ValueError("decision must be promote, defer or reject")
    if not isinstance(payload.get("reviewer"), str) or not payload["reviewer"]:
        raise ValueError("reviewer must be non-empty string")
    if not isinstance(payload.get("decision_date"), str) or not payload["decision_date"]:
        raise ValueError("decision_date must be non-empty string")
    try:
        decision_date = date.fromisoformat(payload["decision_date"])
    except ValueError as exc:
        raise ValueError("decision_date must be ISO date YYYY-MM-DD") from exc
    if decision_date < MIN_DECISION_DATE:
        raise ValueError(f"decision_date must be on or after {MIN_DECISION_DATE.isoformat()}")
