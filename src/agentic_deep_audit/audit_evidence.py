"""Deterministic evidence index and byte-range helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .limits import MAX_AUDIT_FILE_BYTES, decode_text_bytes, read_bytes_capped
from .models import ARTIFACT_PATHS


@dataclass(frozen=True)
class TextView:
    text: str
    normalized_bytes: bytes
    line_ending_original: str
    line_count: int


@dataclass(frozen=True)
class EvidenceResolution:
    ok: bool
    missing_ids: list[str]
    evidence: list[dict[str, Any]]


class EvidenceIdAllocator:
    """Assign stable evidence ids from deterministic source ordering."""

    def __init__(self, prefix: str = "ev-", zero_pad: int = 6) -> None:
        self.prefix = prefix
        self.zero_pad = zero_pad
        self._next = 1
        self._assigned: dict[str, str] = {}

    def allocate(self, source_key: str) -> str:
        if source_key not in self._assigned:
            self._assigned[source_key] = f"{self.prefix}{self._next:0{self.zero_pad}d}"
            self._next += 1
        return self._assigned[source_key]

    @property
    def mapping(self) -> list[dict[str, str]]:
        return [{"source_key": key, "evidence_id": value} for key, value in sorted(self._assigned.items())]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_range(data: bytes, start_byte: int, end_byte: int) -> str:
    return sha256_bytes(data[start_byte:end_byte])


def detect_line_ending(text: str) -> str:
    crlf_count = text.count("\r\n")
    cr_count = text.count("\r") - crlf_count
    lf_count = text.count("\n") - crlf_count
    observed = [name for name, count in [("CRLF", crlf_count), ("CR", cr_count), ("LF", lf_count)] if count > 0]
    if not observed:
        return "none"
    return observed[0] if len(observed) == 1 else "mixed"


def build_text_view(data: bytes) -> TextView | None:
    try:
        original = decode_text_bytes(data)
    except UnicodeDecodeError:
        return None
    line_ending = detect_line_ending(original)
    normalized = original.replace("\r\n", "\n").replace("\r", "\n")
    if normalized == "":
        line_count = 1
    else:
        line_count = normalized.count("\n") + (0 if normalized.endswith("\n") else 1)
    return TextView(
        text=normalized,
        normalized_bytes=normalized.encode("utf-8"),
        line_ending_original=line_ending,
        line_count=max(1, line_count),
    )


def read_file_bytes(path: Path) -> bytes:
    return read_bytes_capped(path, MAX_AUDIT_FILE_BYTES, "evidence file")


def file_evidence_for_record(record: dict[str, Any], repo_path: Path, allocator: EvidenceIdAllocator) -> dict[str, Any]:
    relative = str(record["path"])
    source_key = f"file:{relative}"
    data = read_file_bytes(repo_path / relative)
    start_byte = 0
    end_byte = len(data)
    text_view = None if bool(record.get("binary")) else build_text_view(data)
    if text_view is None:
        return {
            "id": allocator.allocate(source_key),
            "kind": "file_whole",
            "path": relative,
            "start_byte": start_byte,
            "end_byte": end_byte,
            "sha256": sha256_range(data, start_byte, end_byte),
            "binary_safe": True,
            "observed": f"Initial binary-safe file-level inventory record for {record['kind']} file",
        }
    return {
        "id": allocator.allocate(source_key),
        "kind": "file_line",
        "path": relative,
        "start_line": 1,
        "end_line": text_view.line_count,
        "start_byte": start_byte,
        "end_byte": end_byte,
        "sha256": sha256_range(data, start_byte, end_byte),
        "line_ending_original": text_view.line_ending_original,
        "normalized_text_sha256": sha256_bytes(text_view.normalized_bytes),
        "observed": f"Initial file-level inventory record for {record['kind']} file",
    }


def evidence_for_records(records: list[dict[str, Any]], repo_path: Path, run_config: dict[str, Any]) -> dict[str, Any]:
    allocator = EvidenceIdAllocator()
    evidence = [file_evidence_for_record(record, repo_path, allocator) for record in sorted(records, key=lambda item: str(item["path_normalized"]))]
    return {
        "schema_version": "1.1",
        "repo": {"path": str(repo_path), "commit": (run_config.get("repo") or {}).get("commit")},
        "allocator": {"strategy": "stable sorted path_normalized", "prefix": "ev-", "zero_pad": 6, "mapping": allocator.mapping},
        "source_artifacts": [ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["PROVENANCE"]],
        "evidence": evidence,
    }


def sync_evidence_identity_from_provenance(audit_dir: Path, provenance: dict[str, Any]) -> None:
    evidence_path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    if not evidence_path.exists():
        return
    evidence_index = json.loads(evidence_path.read_text(encoding="utf-8"))
    git = provenance.get("git") if isinstance(provenance.get("git"), dict) else {}
    repo = evidence_index.setdefault("repo", {})
    if git.get("commit"):
        repo["commit"] = git["commit"]
    target_path = git.get("target_path")
    if target_path:
        repo["path"] = str(Path(str(target_path)).resolve())
    write_json(evidence_path, evidence_index)


def evidence_ids(evidence_index: dict[str, Any]) -> set[str]:
    items = evidence_index.get("evidence")
    if not isinstance(items, list):
        return set()
    return {str(item.get("id")) for item in items if isinstance(item, dict) and item.get("id")}


def resolve_claim_evidence(claim: dict[str, Any], evidence_index: dict[str, Any]) -> EvidenceResolution:
    available = {str(item.get("id")): item for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}
    requested = claim.get("evidence_ids")
    if not isinstance(requested, list) or not requested:
        return EvidenceResolution(ok=False, missing_ids=["<missing evidence_ids>"], evidence=[])
    missing = [str(item) for item in requested if str(item) not in available]
    return EvidenceResolution(ok=not missing, missing_ids=missing, evidence=[available[str(item)] for item in requested if str(item) in available])


def validate_claims_reach_evidence(claims: Iterable[dict[str, Any]], evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, claim in enumerate(claims):
        claim_id = claim.get("claim_id") or f"claims[{index}]"
        resolution = resolve_claim_evidence(claim, evidence_index)
        if not resolution.ok:
            errors.append(f"claim {claim_id} references unreachable evidence ids: {', '.join(resolution.missing_ids)}")
    return errors


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
