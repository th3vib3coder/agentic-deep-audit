"""License, SBOM skipped state and binary artifact accounting."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .limits import FileSizeLimitError, read_bytes_capped, read_json_capped, read_text_auto_capped, resolve_repo_file
from .models import ARTIFACT_PATHS


LICENSE_NAMES = {"license", "license.md", "license.txt", "copying", "copying.md", "copying.txt"}
LICENSE_NAME_PRECEDENCE = {"license": 0, "license.txt": 1, "license.md": 2, "copying": 3, "copying.txt": 4, "copying.md": 5}
LICENSE_REUSE_COMPATIBLE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}
SCOPED_LICENSE_KINDS = {"code", "config", "docs"}
GENERATED_PARTS = {"generated", "dist", "build"}
VENDORED_PARTS = {"vendor", "vendored", "third_party", "third-party", "node_modules"}
MODEL_EXTENSIONS = {".pt", ".pth", ".onnx", ".h5", ".ckpt", ".safetensors"}
NATIVE_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".whl"}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return read_json_capped(path, label="license input")


def repo_path_from(file_index: dict[str, Any], run_config: dict[str, Any]) -> Path:
    return Path(str((file_index.get("repo") or run_config.get("repo") or {}).get("path") or ".")).resolve()


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def record_path(record: dict[str, Any]) -> str:
    return str(record.get("path_normalized") or record.get("path") or "")


def path_depth(path_value: str) -> int:
    return len(PurePosixPath(path_value).parts)


def read_repo_text(repo_path: Path, path_value: str, label: str) -> str:
    source = resolve_repo_file(repo_path, path_value)
    if source is None:
        raise PermissionError(f"unsafe repository path: {path_value}")
    return read_text_auto_capped(source, encoding="utf-8", errors="replace", label=label)


def spdx_from_text(text: str) -> str | None:
    # C7-02: capture the FULL SPDX expression, not just the first token, so legally-significant
    # `OR`/`AND`/`WITH <exception>` operators are preserved (e.g. `Apache-2.0 OR MIT`,
    # `GPL-2.0-only WITH Classpath-exception-2.0`). Stop at end-of-line or a closing comment marker.
    match = re.search(r"SPDX-License-Identifier:\s*(.+?)\s*(?:\*/|-->|$)", text, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return None
    expression = match.group(1).strip()
    return expression or None


def heuristic_license_from_text(text: str) -> tuple[str | None, str]:
    # C7-01: copyleft families MUST be detected. Previously only MIT/Apache/BSD-2 were recognised and
    # GPL/AGPL/LGPL/MPL/ISC/BSD-3 fell through to "unknown" — a legal hazard, because downstream reuse
    # gating treats "unknown" (not in LICENSE_REUSE_COMPATIBLE only by membership) the same as no
    # conflict. Detect copyleft first so a GPL repo can never be silently classified license-free.
    method = "root_license_heuristic"
    lowered = text.lower()
    if "affero general public license" in lowered:
        return "AGPL-3.0", method
    if "lesser general public license" in lowered:
        return ("LGPL-3.0" if "version 3" in lowered else "LGPL-2.1"), method
    if "gnu general public license" in lowered or "gnu gpl" in lowered:
        if "version 3" in lowered:
            return "GPL-3.0", method
        if "version 2" in lowered:
            return "GPL-2.0", method
        return "GPL-3.0", method
    if "mozilla public license" in lowered and "2.0" in lowered:
        return "MPL-2.0", method
    if "apache license" in lowered and "version 2.0" in lowered:
        return "Apache-2.0", method
    if "redistribution and use" in lowered:
        return ("BSD-3-Clause" if "neither the name" in lowered else "BSD-2-Clause"), method
    if "permission to use, copy, modify, and/or distribute" in lowered:
        return "ISC", method
    if "mit license" in lowered or "permission is hereby granted, free of charge" in lowered:
        return "MIT", method
    return None, "unknown"


def license_file_records(file_index: dict[str, Any]) -> list[dict[str, Any]]:
    records = [
        record
        for record in file_index.get("records", [])
        if isinstance(record, dict)
        and record.get("binary") is not True
        and PurePosixPath(record_path(record)).name.lower() in LICENSE_NAMES
    ]
    return sorted(
        records,
        key=lambda record: (
            path_depth(record_path(record)),
            LICENSE_NAME_PRECEDENCE.get(PurePosixPath(record_path(record)).name.lower(), 99),
            record_path(record).casefold(),
        ),
    )


def detect_license_text(text: str) -> tuple[str | None, str, str]:
    spdx = spdx_from_text(text)
    if spdx:
        return spdx, "spdx_header", "high"
    detected, method = heuristic_license_from_text(text)
    if detected:
        return detected, method, "medium"
    return None, "unknown", "low"


def root_license(file_index: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str]) -> tuple[str | None, str | None, str, str, list[dict[str, Any]]]:
    detections: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for record in license_file_records(file_index):
        path_value = record_path(record)
        try:
            text = read_repo_text(repo_path, path_value, "license source")
        except (OSError, PermissionError, FileSizeLimitError) as exc:
            skipped.append({"path": path_value, "scope": "root" if path_depth(path_value) == 1 else "subtree_root", "skipped_reason": str(exc)})
            continue
        detected, method, confidence = detect_license_text(text)
        if detected:
            detections.append(
                {
                    "path": path_value,
                    "scope": "root" if path_depth(path_value) == 1 else "subtree_root",
                    "declared_license": detected,
                    "detection_method": method,
                    "confidence": confidence,
                    "evidence_id": evidence_lookup.get(path_value),
                }
            )
    selected = next((item for item in detections if item["scope"] == "root"), detections[0] if detections else None)
    license_file_detections = detections + skipped
    if selected:
        return selected["declared_license"], selected.get("evidence_id"), selected["detection_method"], selected["confidence"], license_file_detections
    return None, None, "missing_root_license", "low", license_file_detections


def package_metadata(repo_path: Path, file_index: dict[str, Any], evidence_lookup: dict[str, str]) -> tuple[dict[str, Any], str | None]:
    for record in file_index.get("records", []):
        path_value = record_path(record) if isinstance(record, dict) else ""
        if isinstance(record, dict) and path_value.endswith("package.json"):
            try:
                payload = json.loads(read_repo_text(repo_path, path_value, "package metadata"))
            except (OSError, PermissionError, json.JSONDecodeError, FileSizeLimitError):
                return {}, evidence_lookup.get(path_value)
            return (payload if isinstance(payload, dict) else {}), evidence_lookup.get(path_value)
    return {}, None


def path_parts(path_value: str) -> set[str]:
    return {part.lower() for part in Path(path_value).parts}


def file_license_card(card_id: int, record: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str], root_value: str | None) -> dict[str, Any]:
    path_value = record_path(record)
    evidence_id = evidence_lookup.get(path_value)
    parts = path_parts(path_value)
    if parts & GENERATED_PARTS:
        return {"card_id": f"lic-{card_id:06d}", "kind": "file", "path": path_value, "component": None, "declared_license": None, "detected_license": None, "confidence": "low", "detection_method": "skipped:generated_file", "conflicts_with_root": False, "requires_human_decision": True, "evidence_ids": [evidence_id] if evidence_id else [], "skipped_reason": "generated file requires source template review"}
    if parts & VENDORED_PARTS:
        return {"card_id": f"lic-{card_id:06d}", "kind": "file", "path": path_value, "component": None, "declared_license": None, "detected_license": None, "confidence": "low", "detection_method": "skipped:vendored_file", "conflicts_with_root": False, "requires_human_decision": True, "evidence_ids": [evidence_id] if evidence_id else [], "skipped_reason": "vendored file requires upstream license review"}
    try:
        text = read_repo_text(repo_path, path_value, "license source")
    except PermissionError as exc:
        return {"card_id": f"lic-{card_id:06d}", "kind": "file", "path": path_value, "component": None, "declared_license": None, "detected_license": None, "confidence": "low", "detection_method": "skipped:unsafe_repository_path", "conflicts_with_root": False, "requires_human_decision": True, "evidence_ids": [evidence_id] if evidence_id else [], "skipped_reason": str(exc)}
    except (OSError, FileSizeLimitError) as exc:
        return {"card_id": f"lic-{card_id:06d}", "kind": "file", "path": path_value, "component": None, "declared_license": root_value, "detected_license": root_value, "confidence": "low", "detection_method": "skipped:file_read_limit", "conflicts_with_root": False, "requires_human_decision": True, "evidence_ids": [evidence_id] if evidence_id else [], "skipped_reason": str(exc)}
    spdx = spdx_from_text(text)
    if spdx:
        return {"card_id": f"lic-{card_id:06d}", "kind": "file", "path": path_value, "component": None, "declared_license": spdx, "detected_license": spdx, "confidence": "high", "detection_method": "spdx_header", "conflicts_with_root": bool(root_value and spdx != root_value), "requires_human_decision": bool(root_value and spdx != root_value), "evidence_ids": [evidence_id] if evidence_id else []}
    return {"card_id": f"lic-{card_id:06d}", "kind": "file", "path": path_value, "component": None, "declared_license": root_value, "detected_license": root_value, "confidence": "low", "detection_method": "root_license_fallback", "conflicts_with_root": False, "requires_human_decision": True, "evidence_ids": [evidence_id] if evidence_id else [], "skipped_reason": "no file-level SPDX header; root license fallback needs review"}


def scoped_files(file_index: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        record
        for record in file_index.get("records", [])
        if isinstance(record, dict) and record.get("kind") in SCOPED_LICENSE_KINDS and record.get("binary") is False
    ]


def license_file_candidates(file_index: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        record
        for record in file_index.get("records", [])
        if isinstance(record, dict) and record.get("kind") in (SCOPED_LICENSE_KINDS | {"generated", "vendored"}) and record.get("binary") is False
    ]


def dependency_license_cards(start_id: int, manifests: dict[str, Any], package_meta: dict[str, Any]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    license_map = package_meta.get("dependencyLicenses") if isinstance(package_meta.get("dependencyLicenses"), dict) else {}
    for record in manifests.get("records", []):
        if not isinstance(record, dict) or record.get("skipped"):
            continue
        evidence_ids = [str(item) for item in record.get("evidence_ids") or [] if isinstance(item, str)]
        for dep in record.get("dependencies") or []:
            if not isinstance(dep, dict) or not dep.get("name"):
                continue
            name = str(dep["name"])
            declared = license_map.get(name)
            cards.append({"card_id": f"lic-{start_id + len(cards):06d}", "kind": "dependency", "path": record.get("path"), "component": name, "declared_license": declared, "detected_license": declared, "confidence": "medium" if declared else "low", "detection_method": "package_dependency_license_metadata" if declared else "manifest_dependency_without_license_tool", "conflicts_with_root": bool(declared and declared not in LICENSE_REUSE_COMPATIBLE), "requires_human_decision": declared is None or declared not in LICENSE_REUSE_COMPATIBLE, "evidence_ids": evidence_ids})
    return cards


def license_matrix(cards: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    lines = ["# License Matrix", "", "Legal review required for reuse; this is not a final legal opinion.", "", f"- File license known rate: {summary['file_license_known_rate']}", f"- File denominator: {summary['file_denominator']}", "", "| Kind | Path/Component | Declared | Confidence | Method | Review |", "|---|---|---|---|---|---|"]
    for card in cards:
        target = card.get("path") or card.get("component") or ""
        lines.append(f"| {card['kind']} | {target} | {card.get('declared_license') or ''} | {card['confidence']} | {card['detection_method']} | {card['requires_human_decision']} |")
    return "\n".join(lines) + "\n"


def license_cards(run_config: dict[str, Any], audit_dir: Path, file_index: dict[str, Any], manifests: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str]) -> dict[str, Any]:
    root_value, root_evidence, root_method, root_confidence, license_file_detections = root_license(file_index, repo_path, evidence_lookup)
    metadata, metadata_evidence = package_metadata(repo_path, file_index, evidence_lookup)
    if not root_value and isinstance(metadata.get("license"), str):
        root_value = str(metadata["license"])
        root_evidence = metadata_evidence
        root_method = "package_metadata"
        root_confidence = "medium"
    cards: list[dict[str, Any]] = []
    for record in license_file_candidates(file_index):
        cards.append(file_license_card(len(cards) + 1, record, repo_path, evidence_lookup, root_value))
    cards.extend(dependency_license_cards(len(cards) + 1, manifests, metadata))
    denominator_paths = {record_path(record) for record in scoped_files(file_index)}
    denominator_cards = [card for card in cards if card["kind"] == "file" and card.get("path") in denominator_paths]
    known = [card for card in denominator_cards if card.get("declared_license") and not str(card.get("detection_method", "")).startswith("skipped:")]
    incompatible_license_files = [
        item
        for item in license_file_detections
        if root_value and item.get("declared_license") and item.get("declared_license") != root_value
    ]
    summary = {
        "root_license": root_value,
        "root_license_evidence_id": root_evidence,
        "root_detection_method": root_method,
        "root_confidence": root_confidence,
        "license_file_detections": license_file_detections,
        "incompatible_license_files": incompatible_license_files,
        "root_license_conflict_count": len(incompatible_license_files),
        "file_denominator": len(denominator_cards),
        "file_license_known": len(known),
        "file_license_known_rate": round(len(known) / len(denominator_cards), 3) if denominator_cards else 1.0,
    }
    return {"schema_version": "1.0", "run_id": run_config.get("run_id"), "cards": cards, "summary": summary}


def emit_sbom_skip(audit_dir: Path) -> None:
    sbom = audit_dir / ARTIFACT_PATHS["SBOM"]
    skipped = audit_dir / ARTIFACT_PATHS["SBOM_SKIPPED"]
    if sbom.exists():
        sbom.unlink()
    skipped.write_text("# SBOM Skipped\n\nNo promoted SBOM adapter is available; exactly one of SBOM.cdx.json or SBOM_SKIPPED.md is emitted.\n", encoding="utf-8")


def binary_kind(path_value: str) -> str:
    suffix = Path(path_value).suffix.lower()
    if suffix in MODEL_EXTENSIONS:
        return "model_checkpoint"
    if suffix in NATIVE_EXTENSIONS:
        return "native_binary"
    if suffix in ARCHIVE_EXTENSIONS:
        return "archive"
    if suffix in {".wasm"}:
        return "wasm"
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".webm"}:
        return "image_or_media"
    return "unknown_binary"


def detected_mime(data: bytes) -> str | None:
    if data.startswith(b"MZ"):
        return "application/x-msdownload"
    if data.startswith(b"\x89PNG"):
        return "image/png"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip"
    return "application/octet-stream" if b"\x00" in data[:64] else None


def mime_mismatch(path_value: str, mime: str | None) -> bool:
    suffix = Path(path_value).suffix.lower()
    return bool((suffix == ".png" and mime != "image/png") or (suffix == ".exe" and mime != "application/x-msdownload"))


def binary_artifacts(run_config: dict[str, Any], file_index: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str]) -> dict[str, Any]:
    consent = bool(run_config.get("binary_triage_consent") is True)
    artifacts: list[dict[str, Any]] = []
    for record in file_index.get("records", []):
        if not isinstance(record, dict) or record.get("binary") is not True:
            continue
        path_value = record_path(record)
        kind = binary_kind(path_value)
        evidence_ids = [evidence_lookup[path_value]] if evidence_lookup.get(path_value) else []
        if not consent:
            artifacts.append({"artifact_id": f"bin-{len(artifacts) + 1:06d}", "path": path_value, "kind": kind, "size_bytes": int(record.get("size_bytes") or 0), "mime_detected": None, "extension": Path(path_value).suffix.lower(), "source_counterpart": None, "triage_triggered": False, "requires_operator_consent": True, "evidence_ids": evidence_ids, "mime_mismatch": False, "skipped_reason": "operator consent not granted; binary content not read"})
            continue
        source = resolve_repo_file(repo_path, path_value)
        if source is None:
            artifacts.append({"artifact_id": f"bin-{len(artifacts) + 1:06d}", "path": path_value, "kind": kind, "size_bytes": int(record.get("size_bytes") or 0), "mime_detected": None, "extension": Path(path_value).suffix.lower(), "source_counterpart": None, "triage_triggered": False, "requires_operator_consent": True, "evidence_ids": evidence_ids, "mime_mismatch": False, "skipped_reason": f"unsafe repository path: {path_value}"})
            continue
        try:
            data = read_bytes_capped(source, label="binary artifact")
        except (OSError, FileSizeLimitError) as exc:
            artifacts.append({"artifact_id": f"bin-{len(artifacts) + 1:06d}", "path": path_value, "kind": kind, "size_bytes": int(record.get("size_bytes") or 0), "mime_detected": None, "extension": Path(path_value).suffix.lower(), "source_counterpart": None, "triage_triggered": False, "requires_operator_consent": True, "evidence_ids": evidence_ids, "mime_mismatch": False, "skipped_reason": str(exc)})
            continue
        mime = detected_mime(data)
        artifacts.append({"artifact_id": f"bin-{len(artifacts) + 1:06d}", "path": path_value, "kind": kind, "size_bytes": int(record.get("size_bytes") or 0), "mime_detected": mime, "extension": Path(path_value).suffix.lower(), "source_counterpart": None, "triage_triggered": consent, "requires_operator_consent": not consent, "evidence_ids": evidence_ids, "mime_mismatch": mime_mismatch(path_value, mime)})
    summary = {"blob_count": len(artifacts), "total_binary_bytes": sum(item["size_bytes"] for item in artifacts), "native_binary_count": sum(1 for item in artifacts if item["kind"] == "native_binary"), "mime_mismatch_count": sum(1 for item in artifacts if item["mime_mismatch"]), "triage_consent": consent, "triage_triggered": consent and bool(artifacts)}
    return {"schema_version": "1.0", "run_id": run_config.get("run_id"), "artifacts": artifacts, "summary": summary}


def run_license_binary(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"]) if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() else {"records": []}
    repo_path = repo_path_from(file_index, run_config)
    evidence_lookup = evidence_by_path(audit_dir)
    licenses = license_cards(run_config, audit_dir, file_index, manifests, repo_path, evidence_lookup)
    write_json(audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"], licenses)
    (audit_dir / ARTIFACT_PATHS["LICENSE_MATRIX"]).write_text(license_matrix(licenses["cards"], licenses["summary"]), encoding="utf-8")
    emit_sbom_skip(audit_dir)
    write_json(audit_dir / ARTIFACT_PATHS["BINARY_ARTIFACTS"], binary_artifacts(run_config, file_index, repo_path, evidence_lookup))
