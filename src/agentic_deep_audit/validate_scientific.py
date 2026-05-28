"""Scientific provenance validation helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


SCIENTIFIC_CLAIM_PATTERN = re.compile(
    r"\b(GRCh\d+|hg\d+|GENCODE|RefSeq|organism|taxon|random[_ -]?seed|seed\s*[:=]|confounder|covariate|batch[_ -]?key|batch correction|normalization|TPM|CPM|log1p|dataset[_ -]?path|data[_ -]?path|GS[EM]\d{3,}|SR[RX]\d{3,}|PRJEB\d{3,}|ERR\d{3,}|PRJNA\d{3,}|UniProt(?:KB)?|PMID\s*[:=]?\s*\d{6,9}|10\.\d{4,9}/[-._;()/:A-Z0-9]+)\b",
    flags=re.IGNORECASE,
)


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = read_json_capped(path, label="scientific validation JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"artifact root must be object: {path}")
        return None
    return payload


def validate_scientific_markdown_claims(text: str, record_ids: set[str], artifact_name: str, errors: list[str]) -> None:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("|---") or stripped.startswith("| Record"):
            continue
        ids = set(re.findall(r"sci-\d{6}", stripped))
        for record_id in ids:
            if record_id not in record_ids:
                errors.append(f"{artifact_name} references missing scientific record: {record_id}")
        if SCIENTIFIC_CLAIM_PATTERN.search(stripped) and not ids and "no scientific signals detected" not in stripped.lower() and "open question" not in stripped.lower():
            errors.append(f"{artifact_name} scientific claim lacks provenance record or open question")


def validate_scientific_provenance_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    available = {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}
    scientific_path = audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"]
    report_path = audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"]
    scientific = load_json(scientific_path, errors) if scientific_path.exists() else None
    if scientific is None:
        errors.append(f"missing required scientific artifact: {scientific_path}")
        return errors
    records = scientific.get("records")
    if not isinstance(records, list):
        errors.append("SCIENTIFIC_PROVENANCE.json requires records array")
        records = []
    record_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"SCIENTIFIC_PROVENANCE.json records[{index}] must be object")
            continue
        record_id = str(record.get("record_id") or "")
        if not re.fullmatch(r"sci-\d{6}", record_id):
            errors.append(f"SCIENTIFIC_PROVENANCE.json invalid record_id: {record_id or index}")
        record_ids.add(record_id)
        for key in ["category", "observed_value", "confidence", "detection_method", "requires_human_decision"]:
            if key not in record:
                errors.append(f"SCIENTIFIC_PROVENANCE.json record {record_id or index} missing {key}")
        evidence_ids = record.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            errors.append(f"SCIENTIFIC_PROVENANCE.json record {record_id or index} missing evidence_ids")
        else:
            for evidence_id in evidence_ids:
                if evidence_id not in available:
                    errors.append(f"SCIENTIFIC_PROVENANCE.json record {record_id or index} references unreachable evidence id: {evidence_id}")
        if record.get("detection_method") == "heuristic_inference" and record.get("requires_human_decision") is not True:
            errors.append(f"SCIENTIFIC_PROVENANCE.json heuristic record must require human decision: {record_id or index}")
    if not report_path.exists():
        errors.append(f"missing required scientific report: {report_path}")
        return errors
    try:
        text = read_text_auto_capped(report_path, encoding="utf-8", errors="replace", label="scientific report")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"SCIENTIFIC_PROVENANCE.md invalid artifact: {exc}")
        return errors
    if not records and "no scientific signals detected" not in text:
        errors.append("SCIENTIFIC_PROVENANCE.md empty records require no scientific signals detected note")
    validate_scientific_markdown_claims(text, record_ids, "SCIENTIFIC_PROVENANCE.md", errors)
    supplemental_paths = [audit_dir / ARTIFACT_PATHS["REPORT"]]
    wiki_dir = audit_dir / "wiki"
    if wiki_dir.exists():
        supplemental_paths.extend(sorted(wiki_dir.rglob("*.md")))
    for path in supplemental_paths:
        if path.exists():
            try:
                supplemental_text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="scientific supplemental markdown")
            except (OSError, FileSizeLimitError) as exc:
                errors.append(f"{path.relative_to(audit_dir).as_posix()} invalid scientific supplemental artifact: {exc}")
                continue
            validate_scientific_markdown_claims(supplemental_text, record_ids, path.relative_to(audit_dir).as_posix(), errors)
    return errors
