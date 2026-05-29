"""Evidence-linked validation checks for audit artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .audit_evidence import sha256_range
from .audit_validate_common import ValidationResult, load_json
from .limits import FileSizeLimitError, read_bytes_capped, read_text_auto_capped, resolve_repo_file
from .mcp_policy import looks_secret
from .models import ARTIFACT_PATHS


MAX_JSON_TRAVERSAL_DEPTH = 256


def read_markdown_artifact(path: Path, errors: list[str], label: str) -> str | None:
    if path.is_symlink():
        errors.append(f"{label}: symlink artifacts are not allowed: {path}")
        return None
    try:
        return read_text_auto_capped(path, encoding="utf-8", errors="replace", label=label)
    except FileSizeLimitError as exc:
        errors.append(f"{label}: {exc}")
        return None


def markdown_evidence_ids(path: Path, errors: list[str], label: str) -> list[str]:
    if not path.exists():
        return []
    text = read_markdown_artifact(path, errors, label)
    if text is None:
        return []
    return re.findall(r"ev-\d{6,}", text)


def markdown_section(text: str, heading: str) -> str:
    start = text.find(heading)
    if start < 0:
        return ""
    match = re.search(r"\n## ", text[start + len(heading) :])
    if match is None:
        return text[start:]
    end = start + len(heading) + match.start()
    return text[start:end]


def validate_license_status_source(source: Any, candidate_index: int, evidence_index: dict[str, Any], available: set[str], errors: list[str]) -> None:
    if not isinstance(source, str) or not source:
        errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidate {candidate_index} missing license_status_source")
        return
    if source == "unknown_requires_license_card":
        return
    match = re.fullmatch(r"(root_license|file_evidence|dependency_evidence):(ev-\d{6,})", source)
    if match is None:
        errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidate {candidate_index} invalid license_status_source: {source}")
        return
    source_kind, evidence_id = match.groups()
    if evidence_id not in available:
        errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidate {candidate_index} license_status_source references unreachable evidence id: {evidence_id}")
        return
    if source_kind == "root_license":
        evidence_by_id = {str(item.get("id")): item for item in evidence_index.get("evidence", []) if isinstance(item, dict)}
        path_value = str((evidence_by_id.get(evidence_id) or {}).get("path") or "")
        if not path_value.upper().startswith("LICENSE"):
            errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidate {candidate_index} root_license source is not root license evidence: {evidence_id}")


def validate_synthesis_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> ValidationResult:
    errors: list[str] = []
    available = {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}
    markdown_keys = ["ARCHITECTURE", "FEATURE_CATALOG", "PATTERNS", "OPEN_QUESTIONS"]
    for key in markdown_keys:
        path = audit_dir / ARTIFACT_PATHS[key]
        if not path.exists():
            if key in {"FEATURE_CATALOG", "PATTERNS"}:
                errors.append(f"missing required synthesis artifact: {path}")
            continue
        text = read_markdown_artifact(path, errors, ARTIFACT_PATHS[key])
        if text is None:
            continue
        for evidence_id in re.findall(r"ev-\d{6,}", text):
            if evidence_id not in available:
                errors.append(f"{ARTIFACT_PATHS[key]} references unreachable evidence id: {evidence_id}")
        if key == "ARCHITECTURE":
            synthesis = markdown_section(text, "## Evidence-Backed Synthesis")
            for line in synthesis.splitlines():
                if line.startswith("- ") and "skipped" not in line.lower() and not re.search(r"ev-\d{6,}", line):
                    errors.append("ARCHITECTURE.md synthesis claim lacks evidence id")
    feature_path = audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]
    if feature_path.exists():
        feature_text = read_markdown_artifact(feature_path, errors, "FEATURE_CATALOG.md")
        if feature_text is not None:
            for line in feature_text.splitlines():
                if line.startswith("| ") and not line.startswith("| Feature") and not line.startswith("|---") and "skipped" not in line:
                    if not re.search(r"ev-\d{6,}", line):
                        errors.append("FEATURE_CATALOG.md feature row lacks evidence id")
    patterns_path = audit_dir / ARTIFACT_PATHS["PATTERNS"]
    if patterns_path.exists():
        patterns_text = read_markdown_artifact(patterns_path, errors, "PATTERNS.md")
        if patterns_text is not None:
            for line in patterns_text.splitlines():
                if line.startswith("| ") and not line.startswith("| Pattern") and not line.startswith("|---") and "skipped" not in line:
                    if not re.search(r"ev-\d{6,}", line):
                        errors.append("PATTERNS.md pattern row lacks evidence id")
    special_path = audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"]
    special = load_json(special_path, errors) if special_path.exists() else None
    if special_path.exists() and special is not None:
        candidates = special.get("candidates")
        if not isinstance(candidates, list):
            errors.append("SPECIAL_IMPLEMENTATIONS.json requires candidates array")
        else:
            for index, candidate in enumerate(candidates):
                if not isinstance(candidate, dict):
                    errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidates[{index}] must be object")
                    continue
                for key in ["coupling", "dependencies", "license_status_source", "performance_note", "limitations", "evidence_ids"]:
                    if key not in candidate:
                        errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidate {index} missing {key}")
                if not candidate.get("evidence_ids"):
                    errors.append(f"SPECIAL_IMPLEMENTATIONS.json candidate {index} missing evidence_ids")
                validate_license_status_source(candidate.get("license_status_source"), index, evidence_index, available, errors)
    return ValidationResult(ok=not errors, errors=errors)


def validate_evidence_provenance_drift(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    provenance_path = audit_dir / ARTIFACT_PATHS["PROVENANCE"]
    if not provenance_path.exists():
        return errors
    provenance = load_json(provenance_path, errors)
    if provenance is None:
        return errors
    evidence_commit = (evidence_index.get("repo") or {}).get("commit")
    git = provenance.get("git") if isinstance(provenance.get("git"), dict) else {}
    provenance_commit = git.get("commit")
    evidence_repo_path = Path(str((evidence_index.get("repo") or {}).get("path") or ".")).resolve()
    provenance_target = git.get("target_path") or git.get("repo_root")
    if provenance_target and evidence_repo_path != Path(str(provenance_target)).resolve():
        errors.append("EVIDENCE_INDEX.json repo.path differs from PROVENANCE.json target path")
    limitations = git.get("limitations")
    no_git_explicit = provenance_commit is None and isinstance(limitations, list) and bool(limitations)
    if evidence_commit != provenance_commit:
        if not (evidence_commit is None and no_git_explicit):
            errors.append("EVIDENCE_INDEX.json repo.commit differs from PROVENANCE.json git.commit")
    if evidence_commit and provenance_commit == evidence_commit:
        for item in evidence_index.get("evidence", []):
            if not isinstance(item, dict) or "start_byte" not in item or "end_byte" not in item:
                continue
            if not isinstance(item.get("start_byte"), int) or not isinstance(item.get("end_byte"), int):
                continue
            path_value = str(item.get("path") or "")
            source = resolve_evidence_source(Path(str((evidence_index.get("repo") or {}).get("path") or ".")), path_value)
            if source is None:
                continue
            if not source.exists():
                continue
            try:
                data = read_bytes_capped(source, label="evidence validation source")
            except FileSizeLimitError as exc:
                errors.append(f"evidence source exceeds validation size cap: {path_value}: {exc}")
                continue
            if item.get("sha256") != sha256_range(data, int(item["start_byte"]), int(item["end_byte"])):
                errors.append(f"evidence drift for same provenance input: {path_value}")
    return errors


def validate_cross_artifact_evidence_references(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    available = {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}
    errors: list[str] = []
    evidence_index_path = (audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).resolve()
    audit_root = audit_dir.resolve()
    for path in sorted(audit_dir.rglob("*.json")):
        relative = path.relative_to(audit_dir).as_posix()
        if path.is_symlink():
            errors.append(f"{relative} is a symlink JSON artifact")
            continue
        try:
            path.resolve().relative_to(audit_root)
        except (OSError, ValueError):
            errors.append(f"{relative} escapes audit directory")
            continue
        if path.resolve() == evidence_index_path:
            continue
        try:
            payload = json.loads(read_text_auto_capped(path, encoding="utf-8", label="cross-artifact JSON"))
        except FileSizeLimitError as exc:
            errors.append(f"{relative} exceeds validation size cap: {exc}")
            continue
        except RecursionError as exc:
            errors.append(f"{relative} exceeds validation JSON depth budget while parsing: {exc}")
            continue
        except json.JSONDecodeError:
            continue
        artifact_name = relative
        collect_unreachable_evidence_ids(payload, artifact_name, available, errors)
    return errors


def collect_unreachable_evidence_ids(value: Any, path: str, available: set[str], errors: list[str], max_depth: int = MAX_JSON_TRAVERSAL_DEPTH) -> None:
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    depth_error_paths: set[str] = set()
    while stack:
        current, current_path, depth = stack.pop()
        if depth > max_depth:
            if current_path not in depth_error_paths:
                errors.append(f"{current_path} exceeds maximum JSON traversal depth: {max_depth}")
                depth_error_paths.add(current_path)
            continue
        if isinstance(current, dict):
            for key, item in reversed(list(current.items())):
                next_path = f"{current_path}.{key}"
                if key == "evidence_ids":
                    if not isinstance(item, list):
                        errors.append(f"{next_path} must be an array")
                        continue
                    for evidence_id in item:
                        if not isinstance(evidence_id, str) or not re.fullmatch(r"ev-\d{6,}", evidence_id):
                            errors.append(f"{next_path} contains invalid evidence id: {evidence_id!r}")
                        elif evidence_id not in available:
                            errors.append(f"{next_path} references unreachable evidence id: {evidence_id}")
                    continue
                stack.append((item, next_path, depth + 1))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{current_path}[{index}]", depth + 1))


def resolve_evidence_source(repo_path: Path, path_value: str) -> Path | None:
    return resolve_repo_file(repo_path, path_value)


def validate_provenance_artifact(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    provenance = load_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"], errors)
    if provenance is None:
        return ValidationResult(ok=False, errors=errors)
    git = provenance.get("git")
    if not isinstance(git, dict):
        errors.append("PROVENANCE.json requires git object")
        return ValidationResult(ok=False, errors=errors)
    commit = git.get("commit")
    limitations = git.get("limitations")
    if commit is None:
        if not isinstance(limitations, list) or not limitations:
            errors.append("PROVENANCE.json requires commit SHA or explicit no-git limitation")
    elif not (isinstance(commit, str) and len(commit) == 40):
        errors.append("PROVENANCE.json git.commit must be a 40-character SHA or null")
    secret_paths: list[str] = []
    collect_secret_paths(provenance, "PROVENANCE", secret_paths)
    for secret_path in secret_paths:
        errors.append(f"PROVENANCE.json contains unredacted secret-like value at {secret_path}")
    for remote in git.get("remotes", []):
        if isinstance(remote, dict) and isinstance(remote.get("url"), str):
            if any(secret in remote["url"] for secret in ["ghp_", "github_pat_", "Bearer", "AKIA", "ASIA"]):
                errors.append("PROVENANCE.json contains unredacted remote credential")
    return ValidationResult(ok=not errors, errors=errors)


def collect_secret_paths(value: Any, path: str, results: list[str], max_depth: int = MAX_JSON_TRAVERSAL_DEPTH) -> None:
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    while stack:
        current, current_path, depth = stack.pop()
        if depth > max_depth:
            results.append(f"{current_path} <depth-limit:{max_depth}>")
            continue
        if isinstance(current, dict):
            for key, item in reversed(list(current.items())):
                stack.append((item, f"{current_path}.{key}", depth + 1))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{current_path}[{index}]", depth + 1))
        elif isinstance(current, str) and looks_secret(current):
            results.append(current_path)
