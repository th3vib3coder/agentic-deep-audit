"""Validation helpers for generated Obsidian wiki pages."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .audit_wiki import ROOT_PAGES, selected_module_slugs
from .models import ARTIFACT_PATHS


REQUIRED_FRONTMATTER = {"title", "type", "repo", "commit", "slug", "tags", "source_artifacts", "evidence_ids", "status"}
REQUIRED_CATEGORY_PAGES = [
    "wiki/modules/index.md",
    "wiki/features/index.md",
    "wiki/patterns/index.md",
    "wiki/risks/index.md",
    "wiki/reuse/index.md",
    "wiki/decisions/index.md",
]
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
OBSIDIAN_LINK = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def parse_frontmatter(path: Path, text: str, errors: list[str]) -> dict[str, Any]:
    if not text.startswith("---\n"):
        errors.append(f"{path.name} missing YAML frontmatter")
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        errors.append(f"{path.name} has unterminated YAML frontmatter")
        return {}
    payload: dict[str, Any] = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            errors.append(f"{path.name} has invalid frontmatter line: {line}")
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        raw = value.strip()
        try:
            payload[key] = json.loads(raw)
        except json.JSONDecodeError:
            payload[key] = raw.strip('"')
    missing = REQUIRED_FRONTMATTER - set(payload)
    if missing:
        errors.append(f"{path.name} frontmatter missing keys: {', '.join(sorted(missing))}")
    return payload


def safe_markdown_target(value: str) -> bool:
    if not value or value.startswith(("http://", "https://", "mailto:")):
        return True
    if "\\" in value or "\x00" in value:
        return False
    target = value.split("#", 1)[0]
    if not target:
        return True
    posix = PurePosixPath(target)
    return not posix.is_absolute()


def wiki_pages(audit_dir: Path) -> list[Path]:
    root = audit_dir / "wiki"
    return sorted(root.rglob("*.md")) if root.exists() else []


def obsidian_targets(audit_dir: Path) -> set[str]:
    result: set[str] = set()
    for path in wiki_pages(audit_dir):
        relative = path.relative_to(audit_dir / "wiki").with_suffix("").as_posix()
        result.add(relative)
        result.add(path.stem)
    return result


def validate_links(audit_dir: Path, path: Path, text: str, errors: list[str]) -> None:
    for match in MARKDOWN_LINK.finditer(text):
        target = match.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        if not safe_markdown_target(target):
            errors.append(f"{path.relative_to(audit_dir).as_posix()} has unsafe markdown link: {target}")
            continue
        target_path = target.split("#", 1)[0]
        resolved = (path.parent / target_path).resolve() if target_path else path
        if target_path:
            try:
                resolved.relative_to(audit_dir.resolve())
            except ValueError:
                errors.append(f"{path.relative_to(audit_dir).as_posix()} has unsafe markdown link: {target}")
                continue
        if target_path and not resolved.exists():
            errors.append(f"{path.relative_to(audit_dir).as_posix()} has broken markdown link: {target}")
    available = obsidian_targets(audit_dir)
    for match in OBSIDIAN_LINK.finditer(text):
        target = match.group(1).strip()
        if not safe_markdown_target(target):
            errors.append(f"{path.relative_to(audit_dir).as_posix()} has unsafe obsidian link: {target}")
        elif target not in available:
            errors.append(f"{path.relative_to(audit_dir).as_posix()} has broken obsidian link: {target}")


def type_matches_directory(relative: str, page_type: str) -> bool:
    if relative in ROOT_PAGES:
        return page_type in {"home", "repo_summary", "architecture", "reuse_index", "risk_index"}
    folder = PurePosixPath(relative).parts[1] if len(PurePosixPath(relative).parts) > 1 else ""
    if folder in {"modules", "features", "patterns", "risks", "reuse", "decisions"}:
        return page_type.startswith(folder.rstrip("s")) or page_type.endswith("_index")
    return True


def validate_page(audit_dir: Path, path: Path, available_evidence: set[str], errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    relative = path.relative_to(audit_dir).as_posix()
    front = parse_frontmatter(path, text, errors)
    validate_frontmatter_types(audit_dir, path, front, errors)
    page_type = str(front.get("type") or "")
    if not type_matches_directory(relative, page_type):
        errors.append(f"{relative} frontmatter type does not match directory")
    evidence_ids = front.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        errors.append(f"{relative} frontmatter evidence_ids must be an array")
        evidence_ids = []
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or not re.fullmatch(r"ev-\d{6,}", evidence_id):
            errors.append(f"{relative} contains invalid evidence id: {evidence_id!r}")
        elif evidence_id not in available_evidence:
            errors.append(f"{relative} references unreachable evidence id: {evidence_id}")
    status = front.get("status")
    if status not in {"observed", "skipped"}:
        errors.append(f"{relative} frontmatter status must be observed or skipped")
    if status == "observed" and not evidence_ids:
        errors.append(f"{relative} observed page lacks frontmatter evidence ids")
    if status == "skipped" and "skipped:" not in text and "Open Questions" not in text:
        errors.append(f"{relative} skipped page lacks skipped/open-question note")
    for evidence_id in re.findall(r"ev-\d{6,}", text):
        if evidence_id not in available_evidence:
            errors.append(f"{relative} body references unreachable evidence id: {evidence_id}")
    validate_links(audit_dir, path, text, errors)


def validate_frontmatter_types(audit_dir: Path, path: Path, front: dict[str, Any], errors: list[str]) -> None:
    relative = path.relative_to(audit_dir).as_posix()
    for key in ["title", "type", "slug", "status", "repo", "commit"]:
        if key in front and (not isinstance(front[key], str) or not front[key].strip()):
            errors.append(f"{relative} frontmatter {key} must be a non-empty string")
    tags = front.get("tags")
    if not isinstance(tags, list) or not tags or not all(isinstance(item, str) and item.strip() for item in tags):
        errors.append(f"{relative} frontmatter tags must be a non-empty array of strings")
    elif "agentic-deep-audit" not in tags:
        errors.append(f"{relative} frontmatter tags must include agentic-deep-audit")
    sources = front.get("source_artifacts")
    if not isinstance(sources, list) or not all(isinstance(item, str) and item.strip() for item in sources):
        errors.append(f"{relative} frontmatter source_artifacts must be an array of strings")
    evidence_ids = front.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not all(isinstance(item, str) for item in evidence_ids):
        errors.append(f"{relative} frontmatter evidence_ids must be an array of strings")
    expected_slug = path.relative_to(audit_dir / "wiki").with_suffix("").as_posix()
    if front.get("slug") != expected_slug:
        errors.append(f"{relative} frontmatter slug must match deterministic wiki path")


def module_page_has_valid_evidence(audit_dir: Path, path: Path, available_evidence: set[str]) -> bool:
    local_errors: list[str] = []
    front = parse_frontmatter(path, path.read_text(encoding="utf-8"), local_errors)
    validate_frontmatter_types(audit_dir, path, front, local_errors)
    evidence_ids = front.get("evidence_ids")
    return (
        not local_errors
        and front.get("status") == "observed"
        and isinstance(evidence_ids, list)
        and bool(evidence_ids)
        and all(isinstance(item, str) and item in available_evidence for item in evidence_ids)
    )


def validate_wiki_coverage(audit_dir: Path, run_config: dict[str, Any], available_evidence: set[str], errors: list[str]) -> None:
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], errors)
    profile = str(run_config.get("profile") or "minimal")
    required = selected_module_slugs(module_graph, profile)
    if not required:
        return
    existing = {path.stem for path in (audit_dir / "wiki" / "modules").glob("*.md") if path.name != "index.md" and module_page_has_valid_evidence(audit_dir, path, available_evidence)}
    covered = len(required & existing)
    ratio = covered / len(required)
    threshold = 0.8 if profile == "standard" else 0.7
    if ratio + 1e-9 < threshold:
        errors.append(f"wiki module coverage below {math.ceil(threshold * 100)}%: {covered}/{len(required)}")


def validate_wiki_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    root = audit_dir / "wiki"
    if not root.exists():
        return errors
    for relative in ROOT_PAGES:
        if not (audit_dir / relative).exists():
            errors.append(f"missing wiki root page: {relative}")
    for relative in REQUIRED_CATEGORY_PAGES:
        if not (audit_dir / relative).exists():
            errors.append(f"missing wiki category page: {relative}")
    decision_pages = [path for path in (root / "decisions").glob("*.md") if path.name != "index.md"] if (root / "decisions").exists() else []
    if not decision_pages:
        errors.append("wiki decisions requires at least one decision page or skipped/open-question page")
    elif all("skipped:" not in path.read_text(encoding="utf-8", errors="replace") for path in decision_pages):
        # Real decision pages carry evidence; the skipped fallback must be explicit when no evidence is present.
        if not any(re.search(r"ev-\d{6,}", path.read_text(encoding="utf-8", errors="replace")) for path in decision_pages):
            errors.append("wiki decisions pages require evidence or explicit skipped note")
    available = {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}
    for path in wiki_pages(audit_dir):
        validate_page(audit_dir, path, available, errors)
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], errors)
    validate_wiki_coverage(audit_dir, run_config, available, errors)
    return errors
