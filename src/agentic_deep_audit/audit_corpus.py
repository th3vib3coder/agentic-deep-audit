"""SQLite FTS5 corpus and explainable hybrid retrieval."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .adapters.base import AdapterStatus, append_tool_status
from .config import DEFAULT_RRF, sha256_file
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .mcp_policy import SECRET_PATTERNS, looks_secret, redact_value
from .models import ARTIFACT_PATHS
from .audit_wiki import WIKI_SOURCE_KEYS


TABLES = ["files", "symbols", "evidence", "claims", "graph_nodes", "graph_edges", "wiki_pages"]
TEXT_COLUMNS = {
    "files": ["path", "path_normalized", "kind", "sha256", "evidence_ids", "body"],
    "symbols": ["symbol_id", "name", "kind", "path", "evidence_ids", "body"],
    "evidence": ["evidence_id", "path", "kind", "sha256", "observed"],
    "claims": ["claim_id", "path", "kind", "body", "evidence_ids"],
    "graph_nodes": ["node_id", "type", "label", "path", "evidence_ids", "body"],
    "graph_edges": ["edge_id", "source", "target", "type", "evidence_ids", "body"],
    "wiki_pages": ["path", "title", "type", "evidence_ids", "body"],
    "corpus_fts": ["source", "source_id", "path", "title", "body", "evidence_ids"],
}
REDACTION_MARKER = re.compile(r"<redacted sha256:[0-9a-f]{64}>")
MAX_TEXT_FILE_BODY_BYTES = 1_000_000


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return read_json_capped(path, label="corpus input")


def repo_path_from(file_index: dict[str, Any], run_config: dict[str, Any]) -> Path:
    return Path(str((file_index.get("repo") or run_config.get("repo") or {}).get("path") or ".")).resolve()


def record_path(record: dict[str, Any]) -> str:
    return str(record.get("path_normalized") or record.get("path") or "")


def fts5_available() -> tuple[bool, str | None]:
    try:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("CREATE VIRTUAL TABLE fts_probe USING fts5(body, tokenize='unicode61')")
    except sqlite3.Error as exc:
        return False, str(exc)
    return True, None


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS files(
            path TEXT PRIMARY KEY,
            path_normalized TEXT NOT NULL,
            kind TEXT,
            size_bytes INTEGER,
            sha256 TEXT,
            binary INTEGER,
            evidence_ids TEXT NOT NULL,
            body TEXT
        );
        CREATE TABLE IF NOT EXISTS evidence(
            evidence_id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            kind TEXT,
            start_byte INTEGER,
            end_byte INTEGER,
            start_line INTEGER,
            end_line INTEGER,
            sha256 TEXT,
            observed TEXT
        );
        CREATE TABLE IF NOT EXISTS symbols(
            symbol_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT,
            path TEXT,
            start_byte INTEGER,
            end_byte INTEGER,
            start_line INTEGER,
            end_line INTEGER,
            evidence_ids TEXT NOT NULL,
            body TEXT
        );
        CREATE TABLE IF NOT EXISTS claims(
            claim_id TEXT PRIMARY KEY,
            path TEXT,
            kind TEXT,
            body TEXT NOT NULL,
            evidence_ids TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS graph_nodes(
            node_id TEXT PRIMARY KEY,
            type TEXT,
            label TEXT,
            path TEXT,
            centrality_score REAL,
            evidence_ids TEXT NOT NULL,
            body TEXT
        );
        CREATE TABLE IF NOT EXISTS graph_edges(
            edge_id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            type TEXT,
            weight REAL,
            evidence_ids TEXT NOT NULL,
            body TEXT
        );
        CREATE TABLE IF NOT EXISTS wiki_pages(
            path TEXT PRIMARY KEY,
            title TEXT,
            type TEXT,
            evidence_ids TEXT NOT NULL,
            body TEXT
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS corpus_fts USING fts5(
            source UNINDEXED,
            source_id UNINDEXED,
            path UNINDEXED,
            title,
            body,
            evidence_ids UNINDEXED,
            tokenize='unicode61'
        );
        CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
        CREATE INDEX IF NOT EXISTS idx_graph_nodes_label ON graph_nodes(label);
        CREATE INDEX IF NOT EXISTS idx_files_kind_path ON files(kind, path);
        """
    )


def json_text(value: Any) -> str:
    return json.dumps(value if value is not None else [], sort_keys=True)


def is_safe_repo_relative_path(path_value: str) -> bool:
    if not path_value or "\\" in path_value or ":" in path_value or "\x00" in path_value:
        return False
    posix_path = PurePosixPath(path_value)
    windows_path = PureWindowsPath(path_value)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive or windows_path.root:
        return False
    return ".." not in posix_path.parts and ".." not in windows_path.parts


def resolve_repo_file(repo_path: Path, path_value: str) -> Path | None:
    if not is_safe_repo_relative_path(path_value):
        return None
    root = repo_path.resolve()
    candidate = (root / path_value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _is_link_or_junction(path: Path) -> bool:
    try:
        is_junction = getattr(path, "is_junction", lambda: False)
        return path.is_symlink() or bool(is_junction())
    except OSError:
        return True


def resolve_audit_file_no_links(audit_dir: Path, path_value: str) -> Path:
    if not is_safe_repo_relative_path(path_value):
        raise PermissionError("audit artifact path is not relative")
    root = audit_dir.resolve()
    current = root
    for part in PurePosixPath(path_value).parts:
        current = current / part
        if _is_link_or_junction(current):
            raise PermissionError("audit artifact path contains symlink or junction")
    candidate = (root / path_value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PermissionError("audit artifact path escapes audit directory") from exc
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(path_value)
    return candidate


def text_file_body_result(repo_path: Path, path_value: str, binary: bool, max_bytes: int = MAX_TEXT_FILE_BODY_BYTES) -> tuple[str, str | None]:
    if binary:
        return "", None
    try:
        path = resolve_repo_file(repo_path, path_value)
        if path is None or not path.is_file():
            return "", "missing_or_unsafe"
        return read_text_auto_capped(path, encoding="utf-8", errors="replace", max_bytes=max_bytes, label="corpus source"), None
    except FileSizeLimitError:
        return "", "size_limit"
    except OSError:
        return "", "read_error"


def text_file_body(repo_path: Path, path_value: str, binary: bool, max_bytes: int = MAX_TEXT_FILE_BODY_BYTES) -> str:
    body, _ = text_file_body_result(repo_path, path_value, binary, max_bytes=max_bytes)
    return body


def redact_text(text: str) -> tuple[str, int]:
    redacted = text
    count = 0
    for pattern in SECRET_PATTERNS:
        def replace(match: re.Match[str]) -> str:
            nonlocal count
            count += 1
            return str(redact_value(match.group(0)))

        redacted = pattern.sub(replace, redacted)
    tokens = re.split(r"(\s+)", redacted)
    for index, token in enumerate(tokens):
        if token and not token.isspace() and looks_secret(token):
            tokens[index] = str(redact_value(token))
            count += 1
    return "".join(tokens), count


def contains_raw_secret(text: str) -> bool:
    candidate = REDACTION_MARKER.sub("", text)
    for pattern in SECRET_PATTERNS:
        if pattern.search(candidate):
            return True
    for token in re.split(r"\s+", candidate):
        stripped = token.strip(" \t\r\n'\"`.,;:()[]{}<>")
        if stripped and looks_secret(stripped):
            return True
    return False


def insert_fts(connection: sqlite3.Connection, source: str, source_id: str, path: str, title: str, body: str, evidence_ids: list[str]) -> None:
    if not body and not title and not path:
        return
    connection.execute(
        "INSERT INTO corpus_fts(source, source_id, path, title, body, evidence_ids) VALUES (?, ?, ?, ?, ?, ?)",
        (source, source_id, path, title, body, json_text(evidence_ids)),
    )


def strict_insert(connection: sqlite3.Connection, table: str, pk_name: str, pk_value: Any, sql: str, params: tuple[Any, ...]) -> None:
    try:
        connection.execute(sql, params)
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"duplicate {pk_name} in corpus input for {table}: {pk_value}") from exc


def fts_source_for_file_record(record: dict[str, Any]) -> str:
    return "manifest" if str(record.get("kind") or "") == "manifest" else "files"


def populate_files(connection: sqlite3.Connection, file_index: dict[str, Any], repo_path: Path, read_failures: list[dict[str, str]] | None = None) -> int:
    count = 0
    for record in file_index.get("records", []) if isinstance(file_index.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        path_value = record_path(record)
        evidence_ids = [str(item) for item in record.get("evidence_ids") or [] if isinstance(item, str)]
        raw_body, failure_reason = text_file_body_result(repo_path, path_value, bool(record.get("binary")))
        if failure_reason and read_failures is not None:
            read_failures.append({"path": path_value, "reason": failure_reason})
        body, _ = redact_text(raw_body)
        strict_insert(
            connection,
            "files",
            "path",
            path_value,
            "INSERT INTO files(path, path_normalized, kind, size_bytes, sha256, binary, evidence_ids, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (path_value, str(record.get("path_normalized") or path_value), record.get("kind"), int(record.get("size_bytes") or 0), record.get("sha256"), 1 if record.get("binary") else 0, json_text(evidence_ids), body),
        )
        insert_fts(connection, fts_source_for_file_record(record), path_value, path_value, path_value, body, evidence_ids)
        count += 1
    return count


def populate_evidence(connection: sqlite3.Connection, evidence_index: dict[str, Any]) -> int:
    count = 0
    for item in evidence_index.get("evidence", []) if isinstance(evidence_index.get("evidence"), list) else []:
        if not isinstance(item, dict):
            continue
        observed, _ = redact_text(str(item.get("observed") or ""))
        try:
            connection.execute(
                "INSERT INTO evidence(evidence_id, path, kind, start_byte, end_byte, start_line, end_line, sha256, observed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item.get("id"), item.get("path"), item.get("kind"), item.get("start_byte"), item.get("end_byte"), item.get("start_line"), item.get("end_line"), item.get("sha256"), observed),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"duplicate evidence_id in corpus input: {item.get('id')}") from exc
        insert_fts(connection, "evidence", str(item.get("id")), str(item.get("path") or ""), str(item.get("id")), observed, [str(item.get("id"))] if item.get("id") else [])
        count += 1
    return count


def populate_symbols(connection: sqlite3.Connection, symbol_index: dict[str, Any]) -> int:
    count = 0
    for symbol in symbol_index.get("symbols", []) if isinstance(symbol_index.get("symbols"), list) else []:
        if not isinstance(symbol, dict):
            continue
        evidence_ids = [str(item) for item in symbol.get("evidence_ids") or [] if isinstance(item, str)]
        span = symbol.get("span") if isinstance(symbol.get("span"), dict) else {}
        body = f"{symbol.get('name')} {symbol.get('kind')} {symbol.get('path')}"
        strict_insert(
            connection,
            "symbols",
            "symbol_id",
            symbol.get("symbol_id"),
            "INSERT INTO symbols(symbol_id, name, kind, path, start_byte, end_byte, start_line, end_line, evidence_ids, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (symbol.get("symbol_id"), symbol.get("name"), symbol.get("kind"), symbol.get("path"), span.get("start_byte"), span.get("end_byte"), span.get("start_line"), span.get("end_line"), json_text(evidence_ids), body),
        )
        insert_fts(connection, "symbols", str(symbol.get("symbol_id")), str(symbol.get("path") or ""), str(symbol.get("name") or ""), body, evidence_ids)
        count += 1
    return count


def populate_claims(connection: sqlite3.Connection, evidence_index: dict[str, Any]) -> int:
    count = 0
    for claim in evidence_index.get("claims", []) if isinstance(evidence_index.get("claims"), list) else []:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id") or f"claim-{count + 1:06d}")
        evidence_ids = [str(item) for item in claim.get("evidence_ids") or [] if isinstance(item, str)]
        body, _ = redact_text(str(claim.get("claim") or claim.get("text") or claim))
        strict_insert(
            connection,
            "claims",
            "claim_id",
            claim_id,
            "INSERT INTO claims(claim_id, path, kind, body, evidence_ids) VALUES (?, ?, ?, ?, ?)",
            (claim_id, claim.get("path"), claim.get("kind"), body, json_text(evidence_ids)),
        )
        insert_fts(connection, "claims", claim_id, str(claim.get("path") or ""), claim_id, body, evidence_ids)
        count += 1
    return count


def populate_graph(connection: sqlite3.Connection, graph: dict[str, Any]) -> dict[str, int]:
    node_count = 0
    edge_count = 0
    seen_edges: set[tuple[str, str, str]] = set()
    for node in graph.get("nodes", []) if isinstance(graph.get("nodes"), list) else []:
        if not isinstance(node, dict):
            continue
        evidence_ids = [str(item) for item in node.get("evidence_ids") or [] if isinstance(item, str)]
        body = f"{node.get('id')} {node.get('type')} {node.get('label')}"
        strict_insert(
            connection,
            "graph_nodes",
            "node_id",
            node.get("id"),
            "INSERT INTO graph_nodes(node_id, type, label, path, centrality_score, evidence_ids, body) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (node.get("id"), node.get("type"), node.get("label"), node.get("path"), node.get("centrality_score"), json_text(evidence_ids), body),
        )
        insert_fts(connection, "graph", str(node.get("id")), str(node.get("path") or ""), str(node.get("label") or ""), body, evidence_ids)
        node_count += 1
    for edge in graph.get("edges", []) if isinstance(graph.get("edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        edge_key = (str(edge.get("source") or ""), str(edge.get("target") or ""), str(edge.get("type") or ""))
        if edge_key in seen_edges:
            raise ValueError(f"duplicate edge_id in corpus input for graph_edges: {edge_key[0]}->{edge_key[1]}:{edge_key[2]}")
        seen_edges.add(edge_key)
        edge_id = f"{edge_key[0]}->{edge_key[1]}:{edge_key[2]}"
        evidence_ids = [str(item) for item in edge.get("evidence_ids") or [] if isinstance(item, str)]
        body = f"{edge.get('source')} {edge.get('target')} {edge.get('type')}"
        strict_insert(
            connection,
            "graph_edges",
            "edge_id",
            edge_id,
            "INSERT INTO graph_edges(edge_id, source, target, type, weight, evidence_ids, body) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (edge_id, edge.get("source"), edge.get("target"), edge.get("type"), edge.get("weight"), json_text(evidence_ids), body),
        )
        insert_fts(connection, "graph", edge_id, "", edge_id, body, evidence_ids)
        edge_count += 1
    return {"graph_nodes": node_count, "graph_edges": edge_count}


def markdown_title(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line.removeprefix("# ").strip()
    return path.stem


def wiki_type(path: Path) -> str:
    parts = path.parts
    if len(parts) >= 2:
        return parts[-2]
    return "page"


def trusted_wiki_evidence_ids(text: str) -> list[str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if not line.startswith("evidence_ids:"):
            continue
        raw_value = line.split(":", 1)[1].strip()
        try:
            values = json.loads(raw_value)
        except json.JSONDecodeError:
            return []
        if not isinstance(values, list):
            return []
        return sorted({str(item) for item in values if isinstance(item, str) and re.fullmatch(r"ev-\d{6,}", item)})
    return []


def populate_wiki(connection: sqlite3.Connection, audit_dir: Path) -> int:
    root = audit_dir / "wiki"
    if not root.exists():
        return 0
    count = 0
    for path in sorted(root.rglob("*.md")):
        relative = path.relative_to(audit_dir).as_posix()
        try:
            raw = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="corpus wiki")
        except (OSError, FileSizeLimitError):
            continue
        body, _ = redact_text(raw)
        evidence_ids = trusted_wiki_evidence_ids(body)
        title = markdown_title(body, path)
        kind = wiki_type(path.relative_to(root))
        strict_insert(
            connection,
            "wiki_pages",
            "path",
            relative,
            "INSERT INTO wiki_pages(path, title, type, evidence_ids, body) VALUES (?, ?, ?, ?, ?)",
            (relative, title, kind, json_text(evidence_ids), body),
        )
        insert_fts(connection, "wiki", relative, relative, title, body, evidence_ids)
        count += 1
    return count


def source_artifact_hashes(audit_dir: Path) -> dict[str, str]:
    keys = ["FILE_INDEX", "EVIDENCE_INDEX", "SYMBOL_INDEX", "GRAPH", "MANIFESTS", *WIKI_SOURCE_KEYS]
    result: dict[str, str] = {}
    for key in keys:
        path = audit_dir / ARTIFACT_PATHS[key]
        if path.exists():
            result[ARTIFACT_PATHS[key]] = sha256_file(path)
    wiki_root = audit_dir / "wiki"
    if wiki_root.exists():
        for path in sorted(wiki_root.rglob("*.md")):
            result[path.relative_to(audit_dir).as_posix()] = sha256_file(path)
    return result


def expected_table_counts(audit_dir: Path) -> dict[str, int]:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"])
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])
    wiki_root = audit_dir / "wiki"
    return {
        "files": sum(1 for item in file_index.get("records", []) if isinstance(item, dict)),
        "symbols": sum(1 for item in symbol_index.get("symbols", []) if isinstance(item, dict)),
        "evidence": sum(1 for item in evidence_index.get("evidence", []) if isinstance(item, dict)),
        "claims": sum(1 for item in evidence_index.get("claims", []) if isinstance(item, dict)),
        "graph_nodes": sum(1 for item in graph.get("nodes", []) if isinstance(item, dict)),
        "graph_edges": sum(1 for item in graph.get("edges", []) if isinstance(item, dict)),
        "wiki_pages": sum(1 for path in wiki_root.rglob("*.md")) if wiki_root.exists() else 0,
    }


def no_secret_check(connection: sqlite3.Connection) -> dict[str, Any]:
    raw_count = 0
    redacted_count = 0
    samples: list[str] = []
    for table, columns in TEXT_COLUMNS.items():
        selected = ", ".join(columns)
        for row in connection.execute(f"SELECT {selected} FROM {table}"):
            for column, value in zip(columns, row, strict=True):
                text = str(value or "")
                redacted_count += text.count("<redacted sha256:")
                if contains_raw_secret(text):
                    raw_count += 1
                    if len(samples) < 10:
                        samples.append(f"{table}.{column}")
    payload: dict[str, Any] = {"status": "pass" if raw_count == 0 else "fail", "raw_secret_like_rows": raw_count, "redacted_tokens": redacted_count}
    if samples:
        payload["sample_locations"] = samples
    return payload


def configure_connection_for_bulk_load(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-64000")


def optimize_fts(connection: sqlite3.Connection) -> None:
    connection.execute("INSERT INTO corpus_fts(corpus_fts) VALUES ('optimize')")


def table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in TABLES}


def rrf_config(run_config: dict[str, Any]) -> dict[str, Any]:
    retrieval = run_config.get("retrieval") if isinstance(run_config.get("retrieval"), dict) else {}
    rrf = retrieval.get("rrf") if isinstance(retrieval.get("rrf"), dict) else {}
    weights = {key: float((rrf.get("weights") or {}).get(key, DEFAULT_RRF["weights"][key])) for key in DEFAULT_RRF["weights"]}
    return {"k": int(rrf.get("k") or DEFAULT_RRF["k"]), "weights": weights, "override": bool(rrf.get("override")), "override_keys": list(rrf.get("override_keys") or [])}


def log_rrf_status(run_config: dict[str, Any], audit_dir: Path) -> None:
    config = rrf_config(run_config)
    notes = [f"k={config['k']}", "weights=" + json.dumps(config["weights"], sort_keys=True)]
    if config["override"]:
        notes.append("override_keys=" + ",".join(config["override_keys"]))
    append_tool_status(
        audit_dir,
        AdapterStatus(
            tool="rrf_ranker",
            status="detected",
            policy="allowed",
            available=True,
            version="internal",
            capability="hybrid_retrieval.rrf",
            availability="available",
            provenance_class="core",
            notes=notes,
        ),
    )


def run_corpus(run_config: dict[str, Any], audit_dir: Path) -> None:
    available, reason = fts5_available()
    index_path = audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"]
    sqlite_path = audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]
    skipped_path = audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE_SKIPPED"]
    if not available:
        log_rrf_status(run_config, audit_dir)
        if sqlite_path.exists():
            sqlite_path.unlink()
        skipped_path.write_text(f"# Corpus SQLite Skipped\n\nReason: SQLite FTS5 unavailable: {reason}\n", encoding="utf-8")
        write_json(index_path, {"schema_version": "1.0", "run_id": run_config.get("run_id"), "database_path": None, "skipped": True, "skip_reason": f"SQLite FTS5 unavailable: {reason}", "table_counts": {table: 0 for table in TABLES}, "source_artifact_hashes": source_artifact_hashes(audit_dir), "no_secret_check": {"status": "skipped", "reason": "corpus not built"}, "rrf": rrf_config(run_config)})
        return
    if skipped_path.exists():
        skipped_path.unlink()
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"])
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])
    repo_path = repo_path_from(file_index, run_config)
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    if sqlite_path.exists():
        sqlite_path.unlink()
    read_failures: list[dict[str, str]] = []
    with closing(sqlite3.connect(sqlite_path)) as connection:
        configure_connection_for_bulk_load(connection)
        create_schema(connection)
        connection.execute("BEGIN")
        populate_files(connection, file_index, repo_path, read_failures)
        populate_evidence(connection, evidence_index)
        populate_symbols(connection, symbol_index)
        populate_claims(connection, evidence_index)
        populate_graph(connection, graph)
        populate_wiki(connection, audit_dir)
        optimize_fts(connection)
        counts = table_counts(connection)
        secret_check = no_secret_check(connection)
        connection.commit()
    log_rrf_status(run_config, audit_dir)
    write_json(
        index_path,
        {
            "schema_version": "1.0",
            "run_id": run_config.get("run_id"),
            "database_path": ARTIFACT_PATHS["CORPUS_SQLITE"],
            "skipped": False,
            "skip_reason": None,
            "table_counts": counts,
            "source_artifact_hashes": source_artifact_hashes(audit_dir),
            "no_secret_check": secret_check,
            "read_failures": read_failures,
            "rrf": rrf_config(run_config),
        },
    )


def fts_query(value: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_]+", value[:200])
    return " OR ".join(f'"{token}"' for token in tokens[:8])


def like_query(value: str) -> str:
    escaped = value[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}%"


def evidence_ranges(connection: sqlite3.Connection, evidence_ids: list[str]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for evidence_id in evidence_ids:
        row = connection.execute("SELECT evidence_id, path, start_byte, end_byte, start_line, end_line, sha256 FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if row:
            ranges.append({"evidence_id": row[0], "path": row[1], "start_byte": row[2], "end_byte": row[3], "start_line": row[4], "end_line": row[5], "sha256": row[6]})
    return ranges


def ranked_source_rows(connection: sqlite3.Connection, query: str, limit: int) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {"fts": [], "symbol": [], "graph": [], "manifest": []}
    fts = fts_query(query)
    if fts:
        for rank, row in enumerate(connection.execute("SELECT source, source_id, path, title, evidence_ids, bm25(corpus_fts) AS score FROM corpus_fts WHERE corpus_fts MATCH ? ORDER BY score LIMIT ?", (fts, limit)).fetchall(), start=1):
            rows["fts"].append({"rank": rank, "id": f"{row[0]}:{row[1]}", "source": row[0], "source_id": row[1], "path": row[2], "title": row[3], "evidence_ids": json.loads(row[4] or "[]")})
        for rank, row in enumerate(connection.execute("SELECT s.symbol_id, s.name, s.path, s.evidence_ids, bm25(corpus_fts) AS score FROM corpus_fts JOIN symbols s ON s.symbol_id = corpus_fts.source_id WHERE corpus_fts MATCH ? AND corpus_fts.source = 'symbols' ORDER BY score LIMIT ?", (fts, limit)).fetchall(), start=1):
            rows["symbol"].append({"rank": rank, "id": f"symbols:{row[0]}", "source": "symbols", "source_id": row[0], "path": row[2], "title": row[1], "evidence_ids": json.loads(row[3] or "[]")})
        for rank, row in enumerate(connection.execute("SELECT n.node_id, n.label, n.path, n.evidence_ids, bm25(corpus_fts) AS score FROM corpus_fts JOIN graph_nodes n ON n.node_id = corpus_fts.source_id WHERE corpus_fts MATCH ? AND corpus_fts.source = 'graph' ORDER BY score LIMIT ?", (fts, limit)).fetchall(), start=1):
            rows["graph"].append({"rank": rank, "id": f"graph:{row[0]}", "source": "graph", "source_id": row[0], "path": row[2] or "", "title": row[1], "evidence_ids": json.loads(row[3] or "[]")})
        for rank, row in enumerate(connection.execute("SELECT f.path, f.kind, f.evidence_ids, bm25(corpus_fts) AS score FROM corpus_fts JOIN files f ON f.path = corpus_fts.source_id WHERE corpus_fts MATCH ? AND corpus_fts.source = 'manifest' ORDER BY score LIMIT ?", (fts, limit)).fetchall(), start=1):
            rows["manifest"].append({"rank": rank, "id": f"manifest:{row[0]}", "source": "manifest", "source_id": row[0], "path": row[0], "title": row[1], "evidence_ids": json.loads(row[2] or "[]")})
    return rows


def query_corpus(audit_dir: Path, query: str, limit: int = 10, rrf: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    config = rrf or DEFAULT_RRF
    k = int(config.get("k") or DEFAULT_RRF["k"])
    weights = {key: float((config.get("weights") or {}).get(key, DEFAULT_RRF["weights"][key])) for key in DEFAULT_RRF["weights"]}
    sqlite_path = resolve_audit_file_no_links(audit_dir, ARTIFACT_PATHS["CORPUS_SQLITE"])
    uri = sqlite_path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        source_rows = ranked_source_rows(connection, query, limit * 4)
        combined: dict[str, dict[str, Any]] = {}
        for source, rows in source_rows.items():
            for row in rows:
                item = combined.setdefault(row["id"], {**row, "score": 0.0, "contributions": {}, "evidence_ranges": []})
                contribution = weights[source] / (k + int(row["rank"]))
                item["score"] += contribution
                item["contributions"][source] = {"rank": int(row["rank"]), "weight": weights[source], "score": contribution}
        results = sorted(combined.values(), key=lambda item: (-float(item["score"]), str(item["id"])))[:limit]
        for item in results:
            item["score"] = round(float(item["score"]), 8)
            item["evidence_ranges"] = evidence_ranges(connection, [str(value) for value in item.get("evidence_ids", [])])
        return results
