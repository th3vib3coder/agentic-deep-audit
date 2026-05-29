"""Phase 1 filesystem inventory for target repositories."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from .artifact_io import write_json_artifact
from .audit_evidence import evidence_for_records
from .audit_provenance import sanitize_for_provenance
from .limits import FileSizeLimitError, MAX_AUDIT_FILE_BYTES, read_bytes_capped
from .models import ARTIFACT_PATHS
from .time_utils import current_utc_iso


KIND_VALUES = {"code", "test", "docs", "config", "data", "asset", "generated", "vendored", "binary", "unknown"}
ROOT_DOC_STEMS = ["README", "LICENSE", "CONTRIBUTING", "SECURITY", "CHANGELOG", "AGENTS", "CLAUDE", "GEMINI"]
CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php"}
DOC_EXTENSIONS = {".md", ".rst", ".txt", ".adoc"}
CONFIG_NAMES = {
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "requirements.txt",
    "package.json",
    "tsconfig.json",
    "cargo.toml",
    "go.mod",
    "dockerfile",
    ".gitignore",
}
DATA_EXTENSIONS = {".csv", ".tsv", ".jsonl", ".parquet", ".feather", ".h5", ".hdf5", ".sqlite", ".db"}
ASSET_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".mp4", ".webm"}
GENERATED_DIRS = {"generated", "dist", "build", "coverage"}
VENDORED_DIRS = {"vendor", "vendored", "third_party", "third-party", "node_modules"}
TEXT_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


def normalize_relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def match_pattern(path_normalized: str, pattern: str) -> bool:
    normalized_pattern = pattern.replace("\\", "/")
    if normalized_pattern == "**/*":
        return True
    if fnmatch.fnmatch(path_normalized, normalized_pattern):
        return True
    if normalized_pattern.endswith("/**"):
        prefix = normalized_pattern[:-3]
        return path_normalized == prefix or path_normalized.startswith(prefix + "/")
    return False


def should_include(path_normalized: str, includes: list[str], excludes: list[str]) -> tuple[bool, str | None]:
    for pattern in excludes:
        if match_pattern(path_normalized, pattern):
            return False, f"excluded by {pattern}"
    if not any(match_pattern(path_normalized, pattern) for pattern in includes):
        return False, "not matched by include filters"
    return True, None


def exclusion_reason(path_normalized: str, excludes: list[str]) -> str | None:
    for pattern in excludes:
        if match_pattern(path_normalized, pattern):
            return f"excluded by {pattern}"
    return None


def is_probably_binary(data: bytes) -> bool:
    if data.startswith(TEXT_BOMS):
        return False
    if b"\x00" in data:
        return True
    if not data:
        return False
    non_text = sum(byte < 9 or (13 < byte < 32) for byte in data[:4096])
    return non_text / min(len(data), 4096) > 0.30


def classify_kind(path_normalized: str, binary: bool) -> str:
    path = Path(path_normalized)
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    suffix = path.suffix.lower()
    if binary:
        return "binary"
    if parts & VENDORED_DIRS:
        return "vendored"
    if parts & GENERATED_DIRS or "generated" in name or name.endswith(".min.js"):
        return "generated"
    if "test" in parts or "tests" in parts or name.startswith("test_") or name.endswith("_test.py"):
        return "test"
    if name in CONFIG_NAMES or suffix in {".toml", ".yaml", ".yml", ".ini", ".cfg", ".lock"}:
        return "config"
    if suffix in DOC_EXTENSIONS or any(name == stem.lower() for stem in ROOT_DOC_STEMS):
        return "docs"
    if suffix in CODE_EXTENSIONS:
        return "code"
    if suffix in DATA_EXTENSIONS:
        return "data"
    if suffix in ASSET_EXTENSIONS:
        return "asset"
    return "unknown"


def root_doc_status(root: Path) -> list[dict[str, Any]]:
    files = [path for path in root.iterdir() if path.is_file() and not path.is_symlink()]
    results: list[dict[str, Any]] = []
    for stem in ROOT_DOC_STEMS:
        found = next((path for path in files if path.stem.upper() == stem or path.name.upper() == stem), None)
        results.append({"name": stem, "status": "found" if found else "missing", "path": found.name if found else None})
    return results


def iter_inventory_paths(repo_path: Path, excludes: list[str]):
    for dirpath, dirnames, filenames in os.walk(repo_path, topdown=True, followlinks=False):
        directory = Path(dirpath)
        dirnames.sort()
        filenames.sort()
        for dirname in list(dirnames):
            child = directory / dirname
            path_normalized = normalize_relative(child, repo_path)
            reason = exclusion_reason(path_normalized, excludes)
            if reason is not None:
                yield child, reason
                dirnames.remove(dirname)
                continue
            try:
                if child.is_symlink():
                    yield child, "symlink skipped"
                    dirnames.remove(dirname)
            except OSError:
                yield child, "unreadable directory"
                dirnames.remove(dirname)
        for filename in filenames:
            yield directory / filename, None


def scan_files(run_config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]], Path]:
    repo_path = Path(str((run_config.get("repo") or {}).get("path") or ".")).resolve()
    scope = run_config.get("scope_filters") or {}
    includes = list(scope.get("include") or ["**/*"])
    excludes = list(scope.get("exclude") or [])
    output_dir = Path(str(run_config.get("output_dir") or "audit"))
    resolved_output = output_dir.resolve() if output_dir.is_absolute() else (repo_path / output_dir).resolve()
    try:
        output_relative = resolved_output.relative_to(repo_path).as_posix()
    except ValueError:
        output_relative = output_dir.as_posix().strip("./")
    if output_relative:
        excludes.append(f"{output_relative}/**")

    records: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for path, prune_reason in iter_inventory_paths(repo_path, excludes):
        path_normalized = normalize_relative(path, repo_path)
        if prune_reason is not None:
            skipped.append({"path": path_normalized, "reason": prune_reason})
            continue
        include, reason = should_include(path_normalized, includes, excludes)
        if not include:
            skipped.append({"path": path_normalized, "reason": reason or "excluded"})
            continue
        try:
            if path.is_symlink():
                skipped.append({"path": path_normalized, "reason": "symlink skipped"})
                continue
            if not path.is_file():
                continue
            data = read_bytes_capped(path, MAX_AUDIT_FILE_BYTES, "inventory file")
        except (OSError, PermissionError, FileSizeLimitError) as exc:
            skipped.append({"path": path_normalized, "reason": str(exc)})
            continue
        binary = is_probably_binary(data)
        records.append(
            {
                "path": path_normalized,
                "path_normalized": path_normalized,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "extension": path.suffix.lower(),
                "language": path.suffix.lower().lstrip(".") or None,
                "kind": classify_kind(path_normalized, binary),
                "binary": binary,
            }
        )
    return records, skipped, repo_path


def inventory_markdown(records: list[dict[str, Any]], skipped: list[dict[str, str]], docs: list[dict[str, Any]]) -> str:
    kind_counts = Counter(str(record["kind"]) for record in records)
    extension_counts = Counter(str(record["extension"] or "[none]") for record in records)
    binary_count = sum(1 for record in records if record["binary"])
    binary_bytes = sum(int(record["size_bytes"]) for record in records if record["binary"])
    lines = [
        "# Inventory",
        "",
        "## Counts By Kind",
        "",
        "| Kind | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {kind} | {kind_counts[kind]} |" for kind in sorted(KIND_VALUES))
    lines.extend(["", "## Language Extensions", "", "| Extension | Count |", "|---|---:|"])
    lines.extend(f"| {extension} | {count} |" for extension, count in sorted(extension_counts.items()))
    lines.extend(["", "## Root Documents", "", "| Document | Status | Path |", "|---|---|---|"])
    lines.extend(f"| {doc['name']} | {doc['status']} | {doc['path'] or ''} |" for doc in docs)
    lines.extend(["", "## Skipped Paths", "", "| Path | Reason |", "|---|---|"])
    if skipped:
        lines.extend(f"| {item['path']} | {item['reason']} |" for item in skipped)
    else:
        lines.append("|  | none |")
    lines.extend(["", "## Binary Summary", "", f"- Binary file count: {binary_count}", f"- Binary bytes: {binary_bytes}", ""])
    return "\n".join(lines)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json_artifact(path, payload)


def run_inventory(run_config: dict[str, Any], audit_dir: Path) -> None:
    records, skipped, repo_path = scan_files(run_config)
    docs = root_doc_status(repo_path)
    now = current_utc_iso()
    repo_payload = sanitize_for_provenance(run_config.get("repo") or {"path": str(repo_path), "commit": None})
    write_json(
        audit_dir / ARTIFACT_PATHS["FILE_INDEX"],
        {
            "schema_version": "1.0",
            "run_id": run_config.get("run_id"),
            "repo": repo_payload,
            "generated_at": now,
            "source_artifacts": [ARTIFACT_PATHS["RUN_CONFIG"]],
            "records": records,
            "skipped": False,
            "skip_reason": None,
            "skipped_paths": skipped,
            "root_documents": docs,
        },
    )
    (audit_dir / ARTIFACT_PATHS["INVENTORY"]).write_text(inventory_markdown(records, skipped, docs), encoding="utf-8")
    write_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], evidence_for_records(records, repo_path, run_config))
