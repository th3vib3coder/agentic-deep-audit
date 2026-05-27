"""Risk, agentic security and supply-chain signal extraction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .audit_canonical_graph import run_canonical_graph_outputs
from .limits import FileSizeLimitError, read_text_auto_capped
from .models import ARTIFACT_PATHS
from .sanitize import sanitize_markdown


BEHAVIOR_KINDS = ["eval", "exec", "postinstall", "network_call", "dynamic_import", "obfuscation", "binary_drop", "secret_pressure"]
AGENTIC_CODES = {"E001", "E002", "E003", "E004", "W007", "W008", "W009", "W010", "W011", "W012", "W013", "W014", "W015", "W016", "W017", "W018"}
AGENTIC_NAMES = {"agents.md", "claude.md", "gemini.md", "skill.md", "plugin.json", ".mcp.json"}
SUPPLY_SIGNALS = ["typosquatting", "dependency_confusion", "starjacking", "maintainer_compromise", "yanked_or_deprecated", "lifecycle_downloads"]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def repo_path_from(file_index: dict[str, Any], run_config: dict[str, Any]) -> Path:
    return Path(str((file_index.get("repo") or run_config.get("repo") or {}).get("path") or ".")).resolve()


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def text_records(file_index: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for record in file_index.get("records", []):
        if isinstance(record, dict) and not record.get("binary") and record.get("kind") != "vendored":
            records.append(record)
    return records


def behavior_patterns() -> dict[str, list[tuple[str, str, str, str]]]:
    return {
        "eval": [(r"\beval\s*\(|\bexec\s*\(", "high", "medium", "Avoid eval/exec and use explicit parsers or fixed dispatch.")],
        "exec": [(r"child_process\.exec|subprocess\.(run|Popen|call)|os\.system", "high", "medium", "Audit shell command construction and keep target commands observed-only.")],
        "postinstall": [(r'"postinstall"\s*:', "medium", "medium", "Review lifecycle scripts before installing dependencies.")],
        "network_call": [(r"\b(fetch|axios|get|post)\s*\(|requests\.(get|post)|curl\s+https?://|wget\s+https?://", "medium", "medium", "Review outbound network behavior and data sent.")],
        "dynamic_import": [(r"\bimport\s*\(|require\s*\([^'\"`]|__import__\s*\(", "medium", "medium", "Prefer static imports or validate dynamic module names.")],
        "obfuscation": [(r"\batob\s*\(|b64decode\s*\(|[A-Za-z0-9+/]{32,}={0,2}", "medium", "low", "Decode and review encoded payloads before reuse.")],
        "binary_drop": [(r"\.(exe|dll|so|dylib)\b|chmod\s+\+x|curl\s+.+\s+-o\s+|wget\s+.+\s+-O\s+", "high", "medium", "Treat downloaded or dropped binaries as untrusted until scanned.")],
        "secret_pressure": [(r"process\.env|os\.environ|GITHUB_TOKEN|AWS_SECRET|API_KEY|SECRET", "medium", "medium", "Verify that secrets are never logged, exfiltrated or embedded in artifacts.")],
    }


def suspicious_behaviors(file_index: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str]) -> list[dict[str, Any]]:
    behaviors: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in text_records(file_index):
        path_value = str(record.get("path") or "")
        evidence_id = evidence_lookup.get(path_value)
        if not evidence_id:
            continue
        try:
            text = read_text_auto_capped(repo_path / path_value, encoding="utf-8", errors="replace", label="risk source")
        except (OSError, FileSizeLimitError):
            continue
        for kind, patterns in behavior_patterns().items():
            for pattern, severity, confidence, recommendation in patterns:
                if not re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
                    continue
                key = (kind, path_value)
                if key in seen:
                    continue
                seen.add(key)
                behaviors.append(
                    {
                        "behavior_id": f"susp-{len(behaviors) + 1:06d}",
                        "kind": kind,
                        "subkind": pattern,
                        "path": path_value,
                        "evidence_ids": [evidence_id],
                        "severity": severity,
                        "confidence": confidence,
                        "source": "heuristic",
                        "linked_findings": [],
                        "recommendation": recommendation,
                    }
                )
    return behaviors


def risk_findings_payload(run_config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "run_id": run_config.get("run_id"),
        "findings": [],
        "limitations": ["heuristic suspicious behaviors are not promoted without external tool confirmation"],
    }


def is_agentic_target(path_value: str) -> bool:
    lowered = path_value.lower()
    name = Path(path_value).name.lower()
    return name in AGENTIC_NAMES or lowered.startswith((".github/", ".claude/", ".codex/", "hooks/")) or "mcp" in lowered


def agentic_security(file_index: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
    scanned: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for record in text_records(file_index):
        path_value = str(record.get("path") or "")
        if not is_agentic_target(path_value):
            continue
        evidence_id = evidence_lookup.get(path_value)
        if not evidence_id:
            skipped.append({"path": path_value, "reason": "missing evidence id"})
            continue
        try:
            text = read_text_auto_capped(repo_path / path_value, encoding="utf-8", errors="replace", label="agentic security source")
        except (OSError, FileSizeLimitError) as exc:
            skipped.append({"path": path_value, "reason": str(exc)})
            continue
        sanitized = sanitize_markdown(path_value, text, evidence_id=evidence_id) if Path(path_value).suffix.lower() in {".md", ".txt"} else None
        scanned.append({"path": path_value, "sanitizer_decision": sanitized.decision if sanitized else "not_markdown"})
        checks = [
            ("E004", r"ignore\s+previous|system\s+prompt|developer\s+message|developer\s+messages", "high", "Remove prompt override or system/developer-message extraction instructions."),
            ("W015", r"<!--|hidden:|do\s+not\s+disclose|bypass\s+the\s+sanitizer", "medium", "Quote and sanitize hidden or non-disclosure instruction markers before LLM use."),
        ]
        for code, pattern, severity, recommendation in checks:
            if re.search(pattern, text, flags=re.IGNORECASE):
                findings.append(
                    {
                        "finding_id": f"agentic-{len(findings) + 1:06d}",
                        "code": code,
                        "target": path_value,
                        "pattern_matched": pattern,
                        "severity": severity,
                        "confidence": "high",
                        "evidence_ids": [evidence_id],
                        "source": "agentic_security_scanner",
                        "recommendation": recommendation,
                        "requires_human_decision": True,
                    }
                )
    return findings, scanned, skipped


def agentic_security_markdown(findings: list[dict[str, Any]], scanned: list[dict[str, str]], skipped: list[dict[str, str]]) -> str:
    lines = ["# Agentic Security", "", "## Scanned Files", "", "| Path | Status |", "|---|---|"]
    lines.extend(f"| {item['path']} | scanned:{item['sanitizer_decision']} |" for item in scanned)
    if not scanned:
        lines.append("|  | none |")
    lines.extend(["", "## Skipped Files", "", "| Path | Reason |", "|---|---|"])
    lines.extend(f"| {item['path']} | {item['reason']} |" for item in skipped)
    if not skipped:
        lines.append("|  | none |")
    lines.extend(["", "## Findings", "", "| Code | Target | Severity | Evidence | Recommendation |", "|---|---|---|---|---|"])
    lines.extend(f"| {finding['code']} | {finding['target']} | {finding['severity']} | {', '.join(finding['evidence_ids'])} | {finding['recommendation']} |" for finding in findings)
    if not findings:
        lines.append("|  |  |  |  | no agentic security findings observed |")
    return "\n".join(lines) + "\n"


def dependency_names(manifests: dict[str, Any]) -> list[tuple[str, list[str]]]:
    names: list[tuple[str, list[str]]] = []
    for record in manifests.get("records", []):
        if not isinstance(record, dict) or record.get("skipped"):
            continue
        evidence_ids = [str(item) for item in record.get("evidence_ids") or [] if isinstance(item, str)]
        for dep in record.get("dependencies") or []:
            if isinstance(dep, dict) and dep.get("name"):
                names.append((str(dep["name"]), evidence_ids))
    return names


def manifest_scripts(manifests: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    scripts: list[tuple[str, str, list[str]]] = []
    for record in manifests.get("records", []):
        if not isinstance(record, dict) or record.get("skipped"):
            continue
        evidence_ids = [str(item) for item in record.get("evidence_ids") or [] if isinstance(item, str)]
        for script in record.get("scripts") or []:
            if isinstance(script, dict):
                scripts.append((str(script.get("source") or record.get("path") or ""), str(script.get("command") or ""), evidence_ids))
    return scripts


def supply_chain_markdown(manifests: dict[str, Any]) -> str:
    deps = dependency_names(manifests)
    scripts = manifest_scripts(manifests)
    rows: list[dict[str, str]] = []
    dep_text = " ".join(name for name, _ in deps).lower()
    script_text = " ".join(command for _, command, _ in scripts).lower()
    evidence = sorted({ev for _, ids in deps for ev in ids} | {ev for _, _, ids in scripts for ev in ids})
    heuristics = {
        "typosquatting": any(name.lower() in {"reqeusts", "expres", "lodahs"} for name, _ in deps),
        "dependency_confusion": any(name.startswith(("internal-", "private-", "@internal/")) for name, _ in deps),
        "starjacking": False,
        "maintainer_compromise": False,
        "yanked_or_deprecated": "deprecated" in dep_text or "yanked" in dep_text,
        "lifecycle_downloads": bool(re.search(r"(curl|wget)\s+https?://|\.exe\b|chmod\s+\+x", script_text)),
    }
    for signal in SUPPLY_SIGNALS:
        observed = heuristics[signal]
        caveat = "heuristic signal requires registry/tool confirmation" if observed else "not assessed without registry metadata or external tool"
        rows.append({"signal": signal, "status": "observed" if observed else "skipped", "confidence": "low", "evidence": ", ".join(evidence) if observed and evidence else "", "caveat": caveat})
    lines = ["# Supply Chain Signals", "", "| Signal | Status | Confidence | Evidence | Caveat |", "|---|---|---|---|---|"]
    lines.extend(f"| {row['signal']} | {row['status']} | {row['confidence']} | {row['evidence']} | {row['caveat']} |" for row in rows)
    return "\n".join(lines) + "\n"


def risk_report(behaviors: list[dict[str, Any]], findings: dict[str, Any], agentic: list[dict[str, Any]]) -> str:
    return "\n".join(
        [
            "# Risk Report",
            "",
            "External vulnerability tools skipped or not promoted in this phase; this report cannot claim absence of vulnerabilities.",
            "",
            f"- Suspicious behavior count: {len(behaviors)}",
            f"- Confirmed/promoted risk finding count: {len(findings.get('findings') or [])}",
            f"- Agentic security finding count: {len(agentic)}",
            "",
            "Heuristic suspicious behaviors remain separate from confirmed risk findings unless an external tool confirms them.",
            "",
        ]
    )


def run_risk_security(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"]) if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() else {"records": []}
    repo_path = repo_path_from(file_index, run_config)
    evidence_lookup = evidence_by_path(audit_dir)
    behaviors = suspicious_behaviors(file_index, repo_path, evidence_lookup)
    risk_findings = risk_findings_payload(run_config)
    agentic_findings, scanned, skipped = agentic_security(file_index, repo_path, evidence_lookup)
    write_json(audit_dir / ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"], {"schema_version": "1.0", "run_id": run_config.get("run_id"), "behaviors": behaviors})
    write_json(audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"], risk_findings)
    write_json(audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY_FINDINGS"], {"schema_version": "1.0", "run_id": run_config.get("run_id"), "findings": agentic_findings, "scanned_files": scanned, "skipped_files": skipped})
    (audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY"]).write_text(agentic_security_markdown(agentic_findings, scanned, skipped), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["SUPPLY_CHAIN_SIGNALS"]).write_text(supply_chain_markdown(manifests), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["RISK_REPORT"]).write_text(risk_report(behaviors, risk_findings, agentic_findings), encoding="utf-8")
    if (audit_dir / ARTIFACT_PATHS["GRAPH"]).exists():
        run_canonical_graph_outputs(run_config, audit_dir)
