"""Context-aware reuse card and reuse map generation."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from .audit_canonical_graph import run_canonical_graph_outputs
from .config import canonicalize_target_context
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS
from .sanitize import markdown_table_cell


# C6-06: the tool only RECOMMENDS; the human DECIDES. `recommendation` is the tool's call;
# `decision` is human-gated and stays "pending" in tool output.
RECOMMENDATIONS = {"adopt", "adapt", "study", "avoid"}
DECISIONS = {"pending"}
PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}
STRONG_COPYLEFT_LICENSES = {"AGPL-3.0", "AGPL-1.0", "GPL-3.0", "GPL-2.0", "SSPL-1.0"}
BINARY_DEPENDENCY_KINDS = {"native_binary", "model_checkpoint", "archive", "wasm", "unknown_binary"}
LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".c": "c",
    ".h": "c",
}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return read_json_capped(path, label="reuse input")


def markdown_cell(value: Any) -> str:
    return markdown_table_cell(value)


def target_context_from(run_config: dict[str, Any]) -> dict[str, Any]:
    return canonicalize_target_context(run_config.get("target_context"))


def license_summary(license_cards: dict[str, Any], target_context: dict[str, Any]) -> dict[str, Any]:
    summary = license_cards.get("summary") if isinstance(license_cards.get("summary"), dict) else {}
    root = summary.get("root_license")
    tolerance = str(target_context.get("license_tolerance") or "none")
    if not root:
        return {"status": "unknown", "spdx": None, "reason": "license unknown"}
    root_value = str(root)
    if is_strong_copyleft_license(root_value) and tolerance != "strong-copyleft-ok":
        return {"status": "conflict", "spdx": root_value, "reason": "strong copyleft conflict with target context"}
    if tolerance == "permissive-only" and root_value not in PERMISSIVE_LICENSES:
        return {"status": "needs_review", "spdx": root_value, "reason": "license outside permissive-only target context"}
    return {"status": "compatible", "spdx": root_value, "reason": "license compatible with target context"}


def is_strong_copyleft_license(value: Any) -> bool:
    normalized = str(value or "").strip().upper()
    if not normalized:
        return False
    if normalized in {item.upper() for item in STRONG_COPYLEFT_LICENSES}:
        return True
    return normalized.startswith(("GPL-", "AGPL-", "SSPL-")) or normalized.startswith(("GPL_", "AGPL_", "SSPL_"))


def high_risk_reasons(risk_findings: dict[str, Any], suspicious: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for source_key, items_key in [("risk", "findings"), ("suspicious", "behaviors")]:
        source = risk_findings if source_key == "risk" else suspicious
        for item in source.get(items_key, []) if isinstance(source.get(items_key), list) else []:
            if isinstance(item, dict) and str(item.get("severity") or "").lower() in {"high", "critical"}:
                identifier = item.get("finding_id") or item.get("behavior_id") or len(reasons) + 1
                reasons.append(f"{source_key}:{identifier}")
    return reasons


def binary_dependency_reasons(binary_artifacts: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for artifact in binary_artifacts.get("artifacts", []) if isinstance(binary_artifacts.get("artifacts"), list) else []:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("kind") in BINARY_DEPENDENCY_KINDS and not artifact.get("source_counterpart"):
            reasons.append(str(artifact.get("path") or artifact.get("artifact_id") or "binary"))
    return reasons


def candidate_languages(files: list[str]) -> list[str]:
    languages = sorted({LANGUAGE_BY_SUFFIX[Path(path).suffix.lower()] for path in files if Path(path).suffix.lower() in LANGUAGE_BY_SUFFIX})
    return languages or ["unknown"]


def language_match(languages: list[str], target_context: dict[str, Any]) -> bool:
    allowed = [str(item).lower() for item in target_context.get("allowed_languages") or ["*"]]
    return "*" in allowed or any(language in allowed for language in languages)


def porting_effort(candidate: dict[str, Any], languages_match: bool) -> str:
    dependency_count = len(candidate.get("dependencies") or [])
    coupling = str(candidate.get("coupling") or "unknown")
    if not languages_match or coupling == "high" or dependency_count >= 4:
        return "high"
    if coupling == "medium" or dependency_count:
        return "medium"
    if coupling == "low":
        return "low"
    return "unknown"


def observed_tests(coverage_text: str) -> int:
    match = re.search(r"Test files observed:\s+(\d+)", coverage_text)
    return int(match.group(1)) if match else 0


def recommendation_for(reasons: list[str], effort: str, tests_observed: int, target_context: dict[str, Any]) -> str:
    if any(reason.startswith(("strong_copyleft_conflict", "high_risk", "binary_only_dependency")) for reason in reasons):
        return "avoid"
    if reasons:
        return "study"
    if effort in {"high", "unknown"}:
        return "adapt"
    if effort == "medium" or (target_context.get("production_required") and tests_observed == 0):
        return "adapt"
    return "adopt"


def build_cards(run_config: dict[str, Any], audit_dir: Path) -> dict[str, Any]:
    special = load_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"])
    license_cards = load_json(audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"])
    risk_findings = load_json(audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"])
    suspicious = load_json(audit_dir / ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"])
    binary_artifacts = load_json(audit_dir / ARTIFACT_PATHS["BINARY_ARTIFACTS"])
    coverage_path = audit_dir / ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"]
    try:
        coverage_text = read_text_auto_capped(coverage_path, encoding="utf-8", errors="replace", label="coverage signal") if coverage_path.exists() else ""
    except (OSError, FileSizeLimitError):
        coverage_text = ""
    performance_text_present = (audit_dir / ARTIFACT_PATHS["PERFORMANCE_REVIEW"]).exists()
    target_context = target_context_from(run_config)
    license_info = license_summary(license_cards, target_context)
    risk_reasons = high_risk_reasons(risk_findings, suspicious)
    binary_reasons = binary_dependency_reasons(binary_artifacts)
    tests_observed = observed_tests(coverage_text)
    cards: list[dict[str, Any]] = []
    skipped_candidates: list[dict[str, Any]] = []

    for candidate in special.get("candidates", []) if isinstance(special.get("candidates"), list) else []:
        if not isinstance(candidate, dict):
            skipped_candidates.append({"candidate_id": None, "skipped_reason": "candidate record is not an object"})
            continue
        candidate_id = str(candidate.get("candidate_id") or f"candidate-{len(cards) + 1:06d}")
        files = [str(path) for path in candidate.get("files", []) if isinstance(path, str)]
        evidence_ids = [str(item) for item in candidate.get("evidence_ids", []) if isinstance(item, str)]
        languages = candidate_languages(files)
        matches_language = language_match(languages, target_context)
        effort = porting_effort(candidate, matches_language)
        human_reasons: list[str] = []
        if license_info["status"] == "unknown":
            human_reasons.append("license_unknown")
        if license_info["status"] == "conflict":
            human_reasons.append("strong_copyleft_conflict")
        if license_info["status"] == "needs_review":
            human_reasons.append("license_needs_review")
        if risk_reasons:
            human_reasons.append("high_risk:" + ",".join(risk_reasons[:3]))
        if not evidence_ids:
            human_reasons.append("missing_evidence")
        if binary_reasons:
            human_reasons.append("binary_only_dependency:" + ",".join(binary_reasons[:3]))
        if not matches_language:
            human_reasons.append("target_language_mismatch")
        if target_context.get("production_required") and tests_observed == 0:
            human_reasons.append("production_context_without_test_signal")
        recommendation = recommendation_for(human_reasons, effort, tests_observed, target_context)
        score_inputs = {
            "license_status": license_info["status"],
            "license_spdx": license_info["spdx"],
            "license_reason": license_info["reason"],
            "coupling": candidate.get("coupling") or "unknown",
            "dependency_count": len(candidate.get("dependencies") or []),
            "tests_observed": tests_observed,
            "performance_note": candidate.get("performance_note") or ("performance artifact present" if performance_text_present else "performance artifact missing"),
            "risk_reasons": risk_reasons,
            "binary_dependency_reasons": binary_reasons,
            "languages": languages,
            "target_languages": target_context.get("allowed_languages") or ["*"],
            "porting_effort": effort,
            "requires_human_reasons": human_reasons,
        }
        cards.append(
            {
                "reuse_id": f"reuse-card-{len(cards) + 1:06d}",
                "candidate_id": candidate_id,
                "name": str(candidate.get("name") or candidate_id),
                "problem_solved": str(candidate.get("problem_solved") or f"Reusable {candidate.get('kind') or 'component'} identified by static symbol synthesis."),
                "files": files,
                "dependencies": [str(item) for item in candidate.get("dependencies", []) if isinstance(item, str)],
                "license_status": license_info["status"],
                "target_context": target_context,
                "coupling": str(candidate.get("coupling") or "unknown") if str(candidate.get("coupling") or "unknown") in {"low", "medium", "high", "unknown"} else "unknown",
                "porting_effort": effort,
                "recommendation": recommendation,
                "decision": "pending",
                "requires_human_decision": bool(human_reasons),
                "legal_caveat": f"Legal review required before reuse; current status: {license_info['reason']}.",
                "security_caveat": "Security review required before reuse; high-risk findings force human decision." if risk_reasons else "Security review still required before reuse; no high-risk reuse blocker was observed in generated risk artifacts.",
                "performance_caveat": "Performance notes are static audit signals, not runtime benchmark proof.",
                "limitations": [str(item) for item in candidate.get("limitations", []) if isinstance(item, str)],
                "score_inputs": score_inputs,
                "evidence_ids": evidence_ids,
            }
        )

    return {
        "schema_version": "1.0",
        "run_id": run_config.get("run_id"),
        "source_artifacts": [
            ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"],
            ARTIFACT_PATHS["LICENSE_CARDS"],
            ARTIFACT_PATHS["RISK_FINDINGS"],
            ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"],
            ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
            ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"],
            ARTIFACT_PATHS["BINARY_ARTIFACTS"],
            ARTIFACT_PATHS["RUN_CONFIG"],
        ],
        "scoring_input_sources": {
            "special_implementations": ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"],
            "license_status": ARTIFACT_PATHS["LICENSE_CARDS"],
            "risk_severity": ARTIFACT_PATHS["RISK_FINDINGS"],
            "suspicious_behaviors": ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"],
            "performance_notes": ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
            "tests": ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"],
            "binary_dependencies": ARTIFACT_PATHS["BINARY_ARTIFACTS"],
            "target_context": ARTIFACT_PATHS["RUN_CONFIG"],
        },
        "target_context": target_context,
        "cards": cards,
        "skipped_candidates": skipped_candidates,
        "skipped": bool(special.get("skipped")) and not cards,
        "skip_reason": special.get("skip_reason") if not cards else None,
    }


def reuse_map(payload: dict[str, Any]) -> str:
    context = payload.get("target_context") if isinstance(payload.get("target_context"), dict) else {}
    lines = [
        "# Reuse Map",
        "",
        "Legal caveat: this map is not a legal opinion; every reuse action requires license review before adoption.",
        "Security caveat: recommendations are contextual audit signals and require security review before production use.",
        "Performance caveat: static audit signals do not prove runtime performance.",
        "",
        "## Target Context",
        "",
        f"- Reuse policy: {context.get('reuse_policy') or 'unknown'}",
        f"- Allowed languages: {', '.join(context.get('allowed_languages') or ['*'])}",
        f"- License tolerance: {context.get('license_tolerance') or 'unknown'}",
        f"- Production required: {bool(context.get('production_required'))}",
        "",
    ]
    cards = [card for card in payload.get("cards", []) if isinstance(card, dict)]
    # C6-06: the sections below are the tool's RECOMMENDATION; every card's `decision` stays
    # human-gated ("pending"). The "Human Review" column flags cards that force explicit sign-off.
    for recommendation in ["adopt", "adapt", "study", "avoid"]:
        lines.extend([f"## Recommended: {recommendation.title()}", "", "| Candidate | Files | Decision | Human Review | Caveat | Evidence |", "|---|---|---|---|---|---|"])
        bucket = [card for card in cards if card.get("recommendation") == recommendation]
        if not bucket:
            lines.append("|  |  |  |  |  |  |")
        for card in bucket:
            files = ", ".join(f"`{path}`" for path in card.get("files", []))
            evidence = ", ".join(f"`{item}`" for item in card.get("evidence_ids", []))
            caveat = markdown_cell(card.get("legal_caveat"))
            lines.append(f"| {markdown_cell(card.get('name'))} | {files} | {markdown_cell(card.get('decision'))} | {card.get('requires_human_decision')} | {caveat} | {evidence} |")
        lines.append("")
    if payload.get("skipped"):
        lines.extend(["## Skipped", "", f"- {payload.get('skip_reason') or 'No reusable candidates.'}", ""])
    return "\n".join(lines)


def invalidate_downstream_wiki_corpus(audit_dir: Path) -> None:
    wiki_dir = audit_dir / "wiki"
    if wiki_dir.exists():
        shutil.rmtree(wiki_dir)
    for key in ["CORPUS_INDEX", "CORPUS_SQLITE", "CORPUS_SQLITE_SKIPPED"]:
        path = audit_dir / ARTIFACT_PATHS[key]
        if path.exists():
            path.unlink()


def run_reuse(run_config: dict[str, Any], audit_dir: Path) -> None:
    payload = build_cards(run_config, audit_dir)
    write_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"], payload)
    (audit_dir / ARTIFACT_PATHS["REUSE_MAP"]).write_text(reuse_map(payload), encoding="utf-8")
    invalidate_downstream_wiki_corpus(audit_dir)
    if (audit_dir / ARTIFACT_PATHS["GRAPH"]).exists():
        run_canonical_graph_outputs(run_config, audit_dir)
