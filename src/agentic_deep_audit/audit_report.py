"""Final report and adversarial review packet generation."""

from __future__ import annotations

import json
import re
import fnmatch
from pathlib import Path
from typing import Any

from .config import sha256_file
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS, PLUGIN_ROOT
from .resources import template_dir


class ReportGateError(ValueError):
    """Raised when final report artifacts cannot be generated safely."""


GOAL_SECTION_IDS = [
    "GQ01",
    "GQ02",
    "GQ03",
    "GQ04",
    "GQ05",
    "GQ06",
    "GQ07",
    "GQ08",
    "GQ09",
    "GQ10",
]

SKIPPED_KEYS = [
    "CALL_GRAPH_SKIPPED",
    "GRAPH_HTML_SKIPPED",
    "GRAPHIFY_SKIPPED",
    "CORPUS_SQLITE_SKIPPED",
    "SBOM_SKIPPED",
    "MCP_DEFERRED",
    "MCP_COLLISION_REPORT",
]
COMPLETION_REQUIRED_KEYS = [
    "FILE_INDEX",
    "EVIDENCE_INDEX",
    "MODULE_GRAPH",
    "SYMBOL_INDEX",
    "ARCHITECTURE",
    "FEATURE_CATALOG",
    "PATTERNS",
    "SPECIAL_IMPLEMENTATIONS",
    "RISK_REPORT",
    "PROJECT_TELEMETRY",
    "PERFORMANCE_REVIEW",
    "QUALITY_REVIEW",
    "REUSE_CARDS",
    "REUSE_MAP",
    "WIKI_HOME",
    "GRAPH",
    "CORPUS_INDEX",
]
COMPLETION_ALTERNATIVES = [
    ["CALL_GRAPH", "CALL_GRAPH_SKIPPED"],
    ["SBOM", "SBOM_SKIPPED"],
    ["MCP_CONFIG", "MCP_DEFERRED", "MCP_COLLISION_REPORT"],
]
MAX_REPORT_WALK_DEPTH = 256
SECRET_ARTIFACT_PATTERNS = (
    ".env",
    ".env.*",
    "*.env",
    "*.key",
    "*.pem",
    "id_*",
    "credentials*",
    "*credentials*",
    "*secret*",
    "*token*",
)


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return read_text_auto_capped(path, encoding="utf-8", errors="replace", label="report input")


def load_optional_json(audit_dir: Path, key: str) -> dict[str, Any]:
    path = audit_dir / ARTIFACT_PATHS[key]
    if not path.exists():
        return {}
    try:
        payload = read_json_capped(path, label="report JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def count_items(payload: dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def validation_blocker_count(text: str) -> int | None:
    match = re.search(r"Blocker count:\s*`(\d+)`", text)
    if match is None:
        return None
    return int(match.group(1))


def validation_passed(audit_dir: Path) -> bool:
    structured_path = audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT_JSON"]
    if not structured_path.exists():
        return False
    try:
        payload = read_json_capped(structured_path, label="validation report JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError):
        return False
    return payload.get("status") == "pass" and payload.get("blocker_count") == 0


def validation_blockers(audit_dir: Path) -> list[str]:
    text = read_text(audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"])
    blockers: list[str] = []
    in_blockers = False
    for line in text.splitlines():
        if line.startswith("## Blockers"):
            in_blockers = True
            continue
        if in_blockers and line.startswith("## "):
            break
        if in_blockers and line.startswith("- ") and line.strip() != "- None.":
            blockers.append(line[2:].strip())
    return blockers


def extract_validation_commands(audit_dir: Path) -> list[str]:
    text = read_text(audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"])
    commands: list[str] = []
    in_commands = False
    for line in text.splitlines():
        if line.startswith("## Commands Run"):
            in_commands = True
            continue
        if in_commands and line.startswith("## "):
            break
        if in_commands and line.startswith("- `") and line.endswith("`"):
            commands.append(line[3:-1])
    return commands


def first_non_heading_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped.lstrip("- ").strip()
    return "reason recorded in artifact"


def skipped_artifacts(audit_dir: Path) -> list[tuple[str, str]]:
    skipped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key in SKIPPED_KEYS:
        relative = ARTIFACT_PATHS[key]
        path = audit_dir / relative
        if path.exists():
            skipped.append((relative, first_non_heading_line(read_text(path))))
            seen.add(relative)
    for path in sorted(audit_dir.rglob("*_SKIPPED.md")):
        relative = path.relative_to(audit_dir).as_posix()
        if relative not in seen:
            skipped.append((relative, first_non_heading_line(read_text(path))))
    return skipped


def low_confidence_records(audit_dir: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(audit_dir.rglob("*.json")):
        try:
            payload = read_json_capped(path, label="report low-confidence JSON")
        except (OSError, FileSizeLimitError, json.JSONDecodeError):
            continue
        walk_low_confidence(payload, path.relative_to(audit_dir).as_posix(), "$", findings)
        if len(findings) >= 25:
            break
    return findings[:25]


def walk_low_confidence(value: Any, artifact: str, location: str, findings: list[str]) -> None:
    stack: list[tuple[Any, str, int]] = [(value, location, 0)]
    while stack and len(findings) < 25:
        current, current_location, depth = stack.pop()
        if depth > MAX_REPORT_WALK_DEPTH:
            continue
        if isinstance(current, dict):
            if str(current.get("confidence", "")).lower() == "low":
                findings.append(f"{artifact}:{current_location}")
                if len(findings) >= 25:
                    break
            for key, child in reversed(list(current.items())):
                stack.append((child, f"{current_location}.{key}", depth + 1))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{current_location}[{index}]", depth + 1))


def completion_missing_artifacts(audit_dir: Path) -> list[str]:
    missing = [ARTIFACT_PATHS[key] for key in COMPLETION_REQUIRED_KEYS if not (audit_dir / ARTIFACT_PATHS[key]).exists()]
    for alternatives in COMPLETION_ALTERNATIVES:
        if not any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in alternatives):
            missing.append(" or ".join(ARTIFACT_PATHS[key] for key in alternatives))
    return missing


def completion_ready(audit_dir: Path) -> bool:
    return not completion_missing_artifacts(audit_dir)


def artifact_inventory(audit_dir: Path, excluded: set[str] | None = None) -> list[tuple[str, int, str]]:
    excluded = excluded or set()
    records: list[tuple[str, int, str]] = []
    for path in sorted(audit_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(audit_dir).as_posix()
        if relative in excluded:
            continue
        parts = [path.name.casefold(), *(part.casefold() for part in path.relative_to(audit_dir).parts)]
        if any(fnmatch.fnmatchcase(part, pattern) for part in parts for pattern in SECRET_ARTIFACT_PATTERNS):
            continue
        records.append((relative, path.stat().st_size, sha256_file(path)))
    return records


def tool_status_summary(audit_dir: Path) -> tuple[dict[str, int], list[str]]:
    payload = load_optional_json(audit_dir, "TOOL_STATUS")
    counts: dict[str, int] = {}
    limitations: list[str] = []
    for tool in payload.get("tools", []):
        if not isinstance(tool, dict):
            continue
        status = str(tool.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
        if status in {"skipped", "deferred", "degraded"}:
            reason = tool.get("skipped_reason") or tool.get("degradation_reason") or "reason not recorded"
            limitations.append(f"`{tool.get('tool')}` status `{status}`: {reason}")
    return counts, limitations


def report_scope_section(audit_dir: Path) -> str:
    run_config = load_optional_json(audit_dir, "RUN_CONFIG")
    repo = run_config.get("repo") if isinstance(run_config.get("repo"), dict) else {}
    validation_text = read_text(audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"])
    blocker_count = validation_blocker_count(validation_text)
    return "\n".join(
        [
            "## Scope And Validation",
            "",
            f"- Run id: `{run_config.get('run_id', 'unknown')}`",
            f"- Profile: `{run_config.get('profile', 'unknown')}`",
            f"- Mode: `{run_config.get('mode', 'unknown')}`",
            f"- Repo kind: `{repo.get('kind', 'unknown')}`",
            f"- Repo path: `{repo.get('path', 'unknown')}`",
            f"- Validation status: `{'pass' if validation_passed(audit_dir) else 'not_passed'}`",
            f"- Validation blocker count: `{blocker_count if blocker_count is not None else 'unknown'}`",
            "- Coverage statement: this report is limited to artifacts generated and validated in this audit run.",
            "- Safety statement: this report cannot claim absence of vulnerabilities or legal compatibility.",
        ]
    )


def report_sections(audit_dir: Path) -> dict[str, str]:
    module_graph = load_optional_json(audit_dir, "MODULE_GRAPH")
    symbol_index = load_optional_json(audit_dir, "SYMBOL_INDEX")
    special = load_optional_json(audit_dir, "SPECIAL_IMPLEMENTATIONS")
    risk = load_optional_json(audit_dir, "RISK_FINDINGS")
    suspicious = load_optional_json(audit_dir, "SUSPICIOUS_BEHAVIORS")
    telemetry = load_optional_json(audit_dir, "PROJECT_TELEMETRY")
    reuse = load_optional_json(audit_dir, "REUSE_CARDS")
    license_cards = load_optional_json(audit_dir, "LICENSE_CARDS")
    metrics = load_optional_json(audit_dir, "AUDIT_RUNTIME_METRICS")
    wiki_pages = list((audit_dir / "wiki").rglob("*.md")) if (audit_dir / "wiki").exists() else []
    skipped = skipped_artifacts(audit_dir)
    low_conf = low_confidence_records(audit_dir)
    tool_counts, limitations = tool_status_summary(audit_dir)
    commands = extract_validation_commands(audit_dir)
    return {
        "GQ01_ARCHITECTURE": "\n".join(
            [
                f"- Architecture artifacts: `{ARTIFACT_PATHS['ARCHITECTURE']}`, `{ARTIFACT_PATHS['MODULE_GRAPH']}`, `{ARTIFACT_PATHS['SYMBOL_INDEX']}`, `{ARTIFACT_PATHS['GRAPH']}`.",
                f"- Observed module graph: `{count_items(module_graph, 'nodes')}` nodes and `{count_items(module_graph, 'edges')}` edges.",
                f"- Observed symbol records: `{count_items(symbol_index, 'symbols')}`.",
            ]
        ),
        "GQ02_PATTERNS_FEATURES": "\n".join(
            [
                f"- Pattern and feature artifacts: `{ARTIFACT_PATHS['PATTERNS']}`, `{ARTIFACT_PATHS['FEATURE_CATALOG']}`, `{ARTIFACT_PATHS['SPECIAL_IMPLEMENTATIONS']}`.",
                f"- Reuse candidate records: `{count_items(special, 'candidates')}`.",
                "- Low-confidence feature or pattern items remain in open questions instead of being promoted as facts.",
            ]
        ),
        "GQ03_PERFORMANCE": "\n".join(
            [
                f"- Performance artifacts: `{ARTIFACT_PATHS['PERFORMANCE_REVIEW']}`, `{ARTIFACT_PATHS['QUALITY_REVIEW']}`, `{ARTIFACT_PATHS['PROJECT_TELEMETRY']}`.",
                f"- Runtime metric phases recorded: `{count_items(metrics, 'phases')}`.",
                "- Benchmark-backed and static proxy observations are kept distinct.",
            ]
        ),
        "GQ04_NAVIGATION": "\n".join(
            [
                f"- Navigation artifacts: `wiki/*`, `{ARTIFACT_PATHS['GRAPH']}`, `{ARTIFACT_PATHS['CORPUS_INDEX']}`, `{ARTIFACT_PATHS['CORPUS_SQLITE']}`.",
                f"- Wiki pages generated: `{len(wiki_pages)}`.",
                f"- Skipped or deferred navigation artifacts: `{sum(1 for item, _ in skipped if 'GRAPH' in item or 'CORPUS' in item)}`.",
            ]
        ),
        "GQ05_REUSE": "\n".join(
            [
                f"- Reuse artifacts: `{ARTIFACT_PATHS['REUSE_CARDS']}`, `{ARTIFACT_PATHS['REUSE_MAP']}`, `{ARTIFACT_PATHS['LICENSE_CARDS']}`.",
                f"- Reuse cards: `{count_items(reuse, 'cards')}`.",
                f"- License cards: `{count_items(license_cards, 'cards')}`.",
                "- Reuse suitability remains conditional on target context and human license review.",
            ]
        ),
        "GQ06_RISK": "\n".join(
            [
                f"- Risk artifacts: `{ARTIFACT_PATHS['RISK_REPORT']}`, `{ARTIFACT_PATHS['RISK_FINDINGS']}`, `{ARTIFACT_PATHS['SUSPICIOUS_BEHAVIORS']}`.",
                f"- Promoted risk findings: `{count_items(risk, 'findings')}`.",
                f"- Suspicious behavior records: `{count_items(suspicious, 'records')}`.",
                "- The audit cannot claim absence of vulnerabilities; it reports observed signals and limitations.",
            ]
        ),
        "GQ07_UNKNOWN": "\n".join(
            [
                f"- Unknowns artifact: `{ARTIFACT_PATHS['OPEN_QUESTIONS']}`.",
                f"- Skipped/deferred artifacts: `{len(skipped)}`.",
                f"- Low-confidence records: `{len(low_conf)}`.",
                f"- Tool limitations: `{len(limitations)}`.",
            ]
        ),
        "GQ08_DECISIONS": "\n".join(
            [
                f"- Decision artifacts: `{ARTIFACT_PATHS['ARCHITECTURE']}`, `{ARTIFACT_PATHS['PATTERNS']}`, `wiki/decisions/*.md`.",
                f"- Decision wiki pages: `{len(list((audit_dir / 'wiki' / 'decisions').glob('*.md'))) if (audit_dir / 'wiki' / 'decisions').exists() else 0}`.",
                "- Undocumented decisions are not inferred; absent ADR or decision docs are listed as skipped/open questions.",
            ]
        ),
        "GQ09_MAINTENANCE": "\n".join(
            [
                f"- Maintenance artifacts: `{ARTIFACT_PATHS['PROJECT_TELEMETRY']}`, `{ARTIFACT_PATHS['PROJECT_TELEMETRY_MD']}`.",
                f"- Telemetry record groups: `{len([value for value in telemetry.values() if isinstance(value, list)])}`.",
                f"- Tool status counts: `{json.dumps(tool_counts, sort_keys=True)}`.",
            ]
        ),
        "GQ10_COMPATIBILITY": "\n".join(
            [
                f"- Compatibility artifacts: `{ARTIFACT_PATHS['PROJECT_TELEMETRY']}`, `{ARTIFACT_PATHS['FEATURE_CATALOG']}`, `{ARTIFACT_PATHS['REPORT']}`.",
                "- Backward compatibility and deprecation are reported only when semver, changelog, API docs or annotations provide evidence.",
                "- No compatibility guarantee is inferred from missing markers.",
            ]
        ),
        "RESIDUAL_RISKS": "\n".join(
            [
                f"- Open question count after consolidation: `{len(consolidated_open_questions(audit_dir))}`.",
                f"- Validation commands recorded: `{len(commands)}`.",
                "- External adversarial review should inspect `ADVERSARIAL_REVIEW_PACKET.md` before relying on conclusions.",
            ]
        ),
    }


def render_report(audit_dir: Path) -> str:
    template_path = template_dir() / "report.md"
    template = template_path.read_text(encoding="utf-8")
    rendered = template.replace("{{SCOPE_AND_VALIDATION}}", report_scope_section(audit_dir))
    for token, value in report_sections(audit_dir).items():
        rendered = rendered.replace("{{" + token + "}}", value)
    return rendered.rstrip() + "\n"


def existing_open_question_lines(audit_dir: Path) -> list[str]:
    text = read_text(audit_dir / ARTIFACT_PATHS["OPEN_QUESTIONS"])
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "- No synthesis open questions.":
            continue
        lines.append(stripped)
    return lines


def consolidated_open_questions(audit_dir: Path) -> list[str]:
    questions = existing_open_question_lines(audit_dir)
    for artifact, reason in skipped_artifacts(audit_dir):
        questions.append(f"- Skipped artifact `{artifact}` requires review: {reason}.")
    for limitation in tool_status_summary(audit_dir)[1]:
        questions.append(f"- Tool limitation requires review: {limitation}.")
    for location in low_confidence_records(audit_dir):
        questions.append(f"- Low-confidence record requires review: `{location}`.")
    for blocker in validation_blockers(audit_dir):
        questions.append(f"- Validation blocker remains unresolved: {blocker}.")
    questions.append("- Human decision required: reuse, license compatibility and deployment suitability require owner review in the target context.")
    deduped: list[str] = []
    seen: set[str] = set()
    for question in questions:
        if question not in seen:
            deduped.append(question)
            seen.add(question)
    return deduped


def write_open_questions(audit_dir: Path) -> Path:
    path = audit_dir / ARTIFACT_PATHS["OPEN_QUESTIONS"]
    lines = ["# Open Questions", ""]
    questions = consolidated_open_questions(audit_dir)
    lines.extend(questions or ["- No unresolved questions were emitted by generated artifacts."])
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_review_ledger(audit_dir: Path) -> Path:
    path = audit_dir / ARTIFACT_PATHS["REVIEW_LEDGER"]
    commands = extract_validation_commands(audit_dir)
    tool_counts = tool_status_summary(audit_dir)[0]
    lines = [
        "# Review Ledger",
        "",
        "## Decisions",
        "",
        "| Artifact | Author | Reviewer | Decision | Evidence |",
        "|---|---|---|---|---|",
        f"| `{ARTIFACT_PATHS['VALIDATION_REPORT']}` | validation_engine | artifact_validator | VALIDATION_PASS | blocker_count=0 |",
        f"| `{ARTIFACT_PATHS['REPORT']}` | report_generator | external_reviewer_pending | PENDING_EXTERNAL_REVIEW | generated from validated artifacts |",
        f"| `{ARTIFACT_PATHS['ADVERSARIAL_REVIEW_PACKET']}` | report_generator | external_reviewer_pending | PENDING_EXTERNAL_REVIEW | packet prepared for Claude Code or equivalent reviewer |",
        "",
        "## Tool Status Summary",
        "",
        f"- Counts: `{json.dumps(tool_counts, sort_keys=True)}`",
        "",
        "## Validation Commands",
        "",
    ]
    lines.extend([f"- `{command}`" for command in commands] or ["- No validation command recorded."])
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_report(audit_dir: Path) -> Path:
    path = audit_dir / ARTIFACT_PATHS["REPORT"]
    path.write_text(render_report(audit_dir), encoding="utf-8")
    return path


def write_review_packet(audit_dir: Path) -> Path:
    if not validation_passed(audit_dir):
        raise ReportGateError("ADVERSARIAL_REVIEW_PACKET.md requires VALIDATION_REPORT.md with zero blockers")
    if not completion_ready(audit_dir):
        missing = ", ".join(completion_missing_artifacts(audit_dir))
        raise ReportGateError(f"ADVERSARIAL_REVIEW_PACKET.md requires completion-ready audit artifacts; missing: {missing}")
    path = audit_dir / ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]
    if path.exists():
        path.unlink()
    inventory = artifact_inventory(audit_dir, excluded={ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]})
    skipped = skipped_artifacts(audit_dir)
    commands = extract_validation_commands(audit_dir)
    residual = consolidated_open_questions(audit_dir)
    lines = [
        "# Adversarial Review Packet",
        "",
        "Scope: generated audit artifacts only. Target repository source is not executed by this packet.",
        "Inventory note: `ADVERSARIAL_REVIEW_PACKET.md` is excluded from its own inventory because a self-hash would be recursive.",
        "",
        "## Validation Gate",
        "",
        "- Status: `pass`",
        "- Blocker count: `0`",
        "",
        "## Artifact Inventory",
        "",
        "| Artifact | Size Bytes | SHA256 |",
        "|---|---:|---|",
    ]
    lines.extend(f"| `{artifact}` | {size} | `{digest}` |" for artifact, size, digest in inventory)
    lines.extend(["", "## Skipped Artifacts", ""])
    lines.extend([f"- `{artifact}`: {reason}" for artifact, reason in skipped] or ["- None recorded."])
    lines.extend(["", "## Commands Run", ""])
    lines.extend([f"- `{command}`" for command in commands] or ["- No command recorded."])
    lines.extend(
        [
            "",
            "## Fixture Results",
            "",
            "- Target audit validation gate: pass via `VALIDATION_REPORT.md` blocker count 0.",
            "- Plugin regression fixture results are external to this target audit and should be supplied from plugin CI for release review.",
            "",
            "## Residual Risks",
            "",
        ]
    )
    lines.extend(residual or ["- None recorded."])
    lines.extend(
        [
            "",
            "## Expected External Verdict Format",
            "",
            "- `ACCEPT`: no blockers; residual risks are explicit.",
            "- `REDIRECT`: audit artifacts are usable but require targeted remediation.",
            "- `BLOCK`: audit artifacts are contradictory, unsafe or not reviewable.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def remove_stale_review_packet(audit_dir: Path) -> None:
    path = audit_dir / ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]
    if path.exists():
        path.unlink()


def refresh_open_question_dependents(audit_dir: Path) -> None:
    """Regenerate derived artifacts whose source hashes include the open-question artifact."""
    run_config_path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
    if not run_config_path.exists():
        return
    run_config = read_json_capped(run_config_path, label="run config")
    if (audit_dir / "wiki").exists():
        from .audit_wiki import run_wiki

        run_wiki(run_config, audit_dir)
    if (audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"]).exists() or (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists() or (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE_SKIPPED"]).exists():
        from .audit_corpus import run_corpus

        run_corpus(run_config, audit_dir)


def generate_report_artifacts(audit_dir: Path, command: str | None = None) -> list[Path]:
    from .audit_validate import validate_audit
    from .validation_report import write_validation_report

    actual_command = command or f"python -m agentic_deep_audit.cli validate --audit-dir {audit_dir}"
    initial = validate_audit(audit_dir)
    write_validation_report(audit_dir, initial, actual_command)
    if not initial.ok:
        remove_stale_review_packet(audit_dir)
        raise ReportGateError("final report artifacts require VALIDATION_REPORT.md with zero blockers")
    if not completion_ready(audit_dir):
        remove_stale_review_packet(audit_dir)
        missing = ", ".join(completion_missing_artifacts(audit_dir))
        raise ReportGateError(f"final report artifacts require completion-ready audit artifacts; missing: {missing}")
    open_questions = write_open_questions(audit_dir)
    refresh_open_question_dependents(audit_dir)
    report = write_report(audit_dir)
    ledger = write_review_ledger(audit_dir)
    final = validate_audit(audit_dir)
    write_validation_report(audit_dir, final, actual_command)
    if not final.ok:
        remove_stale_review_packet(audit_dir)
        raise ReportGateError("final report artifacts failed fresh validation: " + "; ".join(final.errors))
    packet = write_review_packet(audit_dir)
    return [report, open_questions, ledger, packet]
