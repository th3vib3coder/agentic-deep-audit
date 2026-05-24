"""Validation helpers for SQLite corpus and retrieval metadata."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .audit_corpus import TABLES, expected_table_counts, no_secret_check, query_corpus, source_artifact_hashes
from .models import ARTIFACT_PATHS


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"artifact root must be object: {path}")
        return None
    return payload


def validate_corpus_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    index_path = audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"]
    sqlite_path = audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]
    skipped_path = audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE_SKIPPED"]
    if not index_path.exists() and not sqlite_path.exists() and not skipped_path.exists():
        return errors
    payload = load_json(index_path, errors) if index_path.exists() else None
    if payload is None:
        errors.append(f"missing required corpus index artifact: {index_path}")
        return errors
    counts = payload.get("table_counts")
    if not isinstance(counts, dict):
        errors.append("CORPUS_INDEX.json requires table_counts object")
        counts = {}
    for table in TABLES:
        if not isinstance(counts.get(table), int):
            errors.append(f"CORPUS_INDEX.json missing table count: {table}")
    secret_check = payload.get("no_secret_check")
    if not isinstance(secret_check, dict) or secret_check.get("status") not in {"pass", "skipped"}:
        errors.append("CORPUS_INDEX.json no-secret check must pass or be explicitly skipped")
    rrf = payload.get("rrf")
    if not isinstance(rrf, dict) or rrf.get("k") != 60 and not rrf.get("override"):
        errors.append("CORPUS_INDEX.json RRF override must be explicit")
    hashes = payload.get("source_artifact_hashes")
    expected_hashes = source_artifact_hashes(audit_dir)
    if not isinstance(hashes, dict):
        errors.append("CORPUS_INDEX.json requires source_artifact_hashes object")
        hashes = {}
    if hashes != expected_hashes:
        errors.append("CORPUS_INDEX.json source_artifact_hashes drift from current source artifacts")
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], errors)
    tool_status = load_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"], errors)
    validate_rrf_override_log(run_config, tool_status, errors)
    if payload.get("skipped") is True:
        if not skipped_path.exists() or not payload.get("skip_reason"):
            errors.append("CORPUS skipped state requires CORPUS_SQLITE_SKIPPED.md and skip_reason")
        if sqlite_path.exists():
            errors.append("CORPUS skipped state must not leave CORPUS.sqlite")
        if payload.get("database_path") is not None:
            errors.append("CORPUS skipped state requires null database_path")
        for table in TABLES:
            if counts.get(table) != 0:
                errors.append(f"CORPUS skipped state requires zero table count: {table}")
        if not isinstance(secret_check, dict) or secret_check.get("status") != "skipped":
            errors.append("CORPUS skipped state requires no-secret status skipped")
        return errors
    if not sqlite_path.exists():
        errors.append(f"missing required corpus sqlite artifact: {sqlite_path}")
        return errors
    if payload.get("database_path") != ARTIFACT_PATHS["CORPUS_SQLITE"]:
        errors.append("CORPUS_INDEX.json database_path must point to CORPUS.sqlite")
    if skipped_path.exists():
        errors.append("CORPUS.sqlite and CORPUS_SQLITE_SKIPPED.md are mutually exclusive")
    expected_counts = expected_table_counts(audit_dir)
    with closing(sqlite3.connect(sqlite_path)) as connection:
        for table in TABLES:
            actual = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            if counts.get(table) != actual:
                errors.append(f"CORPUS_INDEX.json table count mismatch for {table}")
            if actual != expected_counts.get(table):
                errors.append(f"CORPUS.sqlite table count differs from source artifacts for {table}")
        try:
            connection.execute("SELECT rowid FROM corpus_fts LIMIT 1").fetchall()
        except sqlite3.Error as exc:
            errors.append(f"CORPUS.sqlite FTS table unavailable: {exc}")
        recomputed_secret = no_secret_check(connection)
        if recomputed_secret.get("status") != "pass":
            errors.append("CORPUS.sqlite contains raw secret-like text")
        if isinstance(secret_check, dict):
            if secret_check.get("status") != recomputed_secret.get("status"):
                errors.append("CORPUS_INDEX.json no-secret status drift from database")
            if secret_check.get("redacted_tokens") != recomputed_secret.get("redacted_tokens"):
                errors.append("CORPUS_INDEX.json no-secret redacted token count drift from database")
        evidence_rows = connection.execute("SELECT evidence_id, path, start_byte, end_byte, sha256 FROM evidence").fetchall()
        available = {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict)}
        for evidence_id, path, start_byte, end_byte, sha256 in evidence_rows:
            if evidence_id not in available:
                errors.append(f"CORPUS.sqlite evidence row references unknown evidence id: {evidence_id}")
            if not path or start_byte is None or end_byte is None or not sha256:
                errors.append(f"CORPUS.sqlite evidence row missing byte range or sha256: {evidence_id}")
    if counts.get("symbols", 0) > 0:
        symbol_name = first_symbol_name(sqlite_path)
        if symbol_name and not smoke_query_has_evidence(audit_dir, symbol_name):
            errors.append("CORPUS.sqlite smoke query returned no result for known symbol")
    return errors


def validate_rrf_override_log(run_config: dict[str, Any] | None, tool_status: dict[str, Any] | None, errors: list[str]) -> None:
    if run_config is None or tool_status is None:
        return
    rrf_run = ((run_config.get("retrieval") or {}).get("rrf") or {}) if isinstance(run_config.get("retrieval"), dict) else {}
    if rrf_run.get("override"):
        tools = [tool for tool in tool_status.get("tools", []) if isinstance(tool, dict) and tool.get("tool") == "rrf_ranker"]
        if not tools or not any("override_keys=" in " ".join(str(note) for note in tool.get("notes", [])) for tool in tools):
            errors.append("RRF override in RUN_CONFIG.json must be logged in TOOL_STATUS.json")


def first_symbol_name(sqlite_path: Path) -> str | None:
    with closing(sqlite3.connect(sqlite_path)) as connection:
        row = connection.execute("SELECT name FROM symbols ORDER BY symbol_id LIMIT 1").fetchone()
    return str(row[0]) if row else None


def smoke_query_has_evidence(audit_dir: Path, symbol_name: str) -> bool:
    for result in query_corpus(audit_dir, symbol_name, limit=5):
        if result.get("title") != symbol_name:
            continue
        ranges = result.get("evidence_ranges")
        if not isinstance(ranges, list) or not ranges:
            continue
        for item in ranges:
            if not isinstance(item, dict):
                continue
            if item.get("start_byte") is not None and item.get("end_byte") is not None and item.get("sha256"):
                return True
    return False
