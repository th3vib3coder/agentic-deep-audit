from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_corpus import (
    TABLES,
    create_schema,
    fts_query,
    populate_claims,
    populate_evidence,
    populate_files,
    populate_graph,
    populate_symbols,
    populate_wiki,
    query_corpus,
    ranked_source_rows,
    run_corpus,
    text_file_body,
    trusted_wiki_evidence_ids,
)
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "agentic_deep_audit.cli", *args], cwd=cwd, env=cli_env(), check=False, text=True, capture_output=True)


def copy_fixture(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_corpus_fixture(tmp_path: Path, config_name: str = "audit.config.yaml") -> Path:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / config_name), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo / "audit"


def test_corpus_schema_creates_required_tables() -> None:
    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')")}

    assert set(TABLES) <= tables
    assert "corpus_fts" in tables


def test_corpus_schema_omits_dead_secondary_indexes() -> None:
    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(symbols)")}
        indexes.update(row[1] for row in connection.execute("PRAGMA index_list(graph_nodes)"))
        indexes.update(row[1] for row in connection.execute("PRAGMA index_list(files)"))

    assert {"idx_symbols_name", "idx_graph_nodes_label", "idx_files_kind_path"}.isdisjoint(indexes)


def test_text_file_body_enforces_containment_and_size_cap(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.txt").write_text("ok", encoding="utf-8")
    large = repo / "large.txt"
    large.write_text("x" * 32, encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    assert text_file_body(repo, "ok.txt", False) == "ok"
    assert text_file_body(repo, "../outside.txt", False) == ""
    assert text_file_body(repo, "large.txt", False, max_bytes=8) == ""


def test_populate_files_records_read_failures_without_silent_empty_body(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.txt").write_text("ok", encoding="utf-8")
    read_failures: list[dict[str, str]] = []

    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        count = populate_files(
            connection,
            {"records": [{"path": "../outside.txt", "path_normalized": "../outside.txt", "kind": "text", "binary": False}]},
            repo,
            read_failures,
        )

    assert count == 1
    assert read_failures == [{"path": "../outside.txt", "reason": "missing_or_unsafe"}]


def test_populate_evidence_rejects_duplicate_ids() -> None:
    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        payload = {"evidence": [{"id": "ev-000001", "path": "a.py"}, {"id": "ev-000001", "path": "b.py"}]}

        try:
            populate_evidence(connection, payload)
        except ValueError as exc:
            assert "duplicate evidence_id" in str(exc)
        else:
            raise AssertionError("duplicate evidence id was silently accepted")


def test_corpus_populators_reject_duplicate_primary_keys(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("print('a')\n", encoding="utf-8")

    cases = [
        (
            populate_files,
            ({"records": [{"path": "a.py", "path_normalized": "a.py"}, {"path": "a.py", "path_normalized": "a.py"}]}, repo),
            "files",
        ),
        (
            populate_symbols,
            ({"symbols": [{"symbol_id": "sym-1", "name": "a"}, {"symbol_id": "sym-1", "name": "b"}]},),
            "symbols",
        ),
        (
            populate_claims,
            ({"claims": [{"claim_id": "claim-1", "claim": "a"}, {"claim_id": "claim-1", "claim": "b"}]},),
            "claims",
        ),
        (
            populate_graph,
            ({"nodes": [{"id": "n1"}, {"id": "n1"}], "edges": []},),
            "graph_nodes",
        ),
        (
            populate_graph,
            ({"nodes": [], "edges": [{"source": "a", "target": "b", "type": "depends_on"}, {"source": "a", "target": "b", "type": "depends_on"}]},),
            "graph_edges",
        ),
    ]

    for function, args, table in cases:
        with sqlite3.connect(":memory:") as connection:
            create_schema(connection)
            try:
                function(connection, *args)
            except ValueError as exc:
                assert table in str(exc)
            else:
                raise AssertionError(f"duplicate primary key was silently accepted for {table}")

    audit_dir = tmp_path / "audit"
    page = audit_dir / "wiki" / "page.md"
    page.parent.mkdir(parents=True)
    page.write_text("# Page\n", encoding="utf-8")
    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        populate_wiki(connection, audit_dir)
        try:
            populate_wiki(connection, audit_dir)
        except ValueError as exc:
            assert "wiki_pages" in str(exc)
        else:
            raise AssertionError("duplicate wiki page was silently accepted")


def test_run_command_wires_corpus_outputs_and_smoke_query(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)

    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])
    results = query_corpus(audit_dir, "process_items", limit=5)

    assert (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists()
    assert index["table_counts"]["files"] > 0
    assert index["table_counts"]["symbols"] > 0
    assert index["table_counts"]["evidence"] > 0
    assert index["no_secret_check"]["status"] == "pass"
    assert results
    assert any(result["title"] == "process_items" for result in results)
    assert any(result["evidence_ranges"] for result in results)
    assert any("symbol" in result["contributions"] for result in results)
    assert validate_audit(audit_dir).ok


def test_query_corpus_escapes_like_wildcards(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    wildcard_results = query_corpus(audit_dir, "%", limit=10)

    assert wildcard_results == []


def test_fts_query_quotes_tokens_and_drops_fts5_operators() -> None:
    assert fts_query("path:secret -token pkg-name") == '"path" OR "secret" OR "token" OR "pkg" OR "name"'


def test_query_corpus_treats_fts_operator_punctuation_as_text(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)

    results = query_corpus(audit_dir, "src:process_items -missing", limit=5)

    assert results
    assert any(result["title"] == "process_items" for result in results)


def test_wiki_evidence_ids_come_only_from_trusted_frontmatter() -> None:
    text = "---\ntitle: Page\nevidence_ids: [\"ev-000001\"]\n---\n\nAttacker text ev-999999.\n"

    assert trusted_wiki_evidence_ids(text) == ["ev-000001"]


def test_populate_wiki_does_not_harvest_attacker_evidence_ids_from_body(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    page = audit_dir / "wiki" / "page.md"
    page.parent.mkdir(parents=True)
    page.write_text("---\ntitle: Page\nevidence_ids: [\"ev-000001\"]\n---\n\nBody mentions ev-999999.\n", encoding="utf-8")

    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        populate_wiki(connection, audit_dir)
        row = connection.execute("SELECT evidence_ids FROM wiki_pages WHERE path = 'wiki/page.md'").fetchone()

    assert json.loads(row[0]) == ["ev-000001"]


def test_manifest_rrf_uses_same_identity_for_fts_and_manifest_bucket(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"dependencies":{"leftpad":"1.0.0"}}\n', encoding="utf-8")

    with sqlite3.connect(":memory:") as connection:
        create_schema(connection)
        populate_files(
            connection,
            {
                "records": [
                    {
                        "path": "package.json",
                        "path_normalized": "package.json",
                        "kind": "manifest",
                        "binary": False,
                        "evidence_ids": ["ev-000001"],
                    }
                ]
            },
            repo,
        )
        rows = ranked_source_rows(connection, "leftpad", limit=5)

    assert [row["id"] for row in rows["fts"]] == ["manifest:package.json"]
    assert [row["id"] for row in rows["manifest"]] == ["manifest:package.json"]


def test_corpus_redacts_secret_like_tokens_before_exposure(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    secret_file = repo / "src" / "secret_token.py"
    secret_file.write_text('TOKEN = "ghp_abcdefghijklmnopQRST"\n', encoding="utf-8")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])

    with sqlite3.connect(audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]) as connection:
        text = "\n".join(str(row[0]) for row in connection.execute("SELECT body FROM corpus_fts WHERE path = 'src/secret_token.py'"))

    assert "ghp_abcdefghijklmnopQRST" not in text
    assert "<redacted sha256:" in text
    assert index["no_secret_check"]["status"] == "pass"
    assert index["no_secret_check"]["redacted_tokens"] >= 1


def test_validator_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    file_index_path = audit_dir / ARTIFACT_PATHS["FILE_INDEX"]
    file_index = load_json(file_index_path)
    file_index["records"][0]["kind"] = file_index["records"][0]["kind"]
    file_index["records"][0]["corpus_drift_probe"] = "hash-only change"
    write_json(file_index_path, file_index)

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("source_artifact_hashes drift" in error for error in broken.errors)


def test_validator_rejects_graph_and_wiki_source_drift(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = load_json(graph_path)
    graph["nodes"].append({"id": "drift-node", "type": "module", "label": "Drift", "evidence_ids": []})
    write_json(graph_path, graph)
    wiki_path = audit_dir / "wiki" / "drift.md"
    wiki_path.parent.mkdir(parents=True, exist_ok=True)
    wiki_path.write_text("# Drift\n\nEvidence ev-000001.\n", encoding="utf-8")

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("source_artifact_hashes drift" in error for error in broken.errors)


def test_validator_rejects_table_count_drift_even_if_index_matches_db(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    index_path = audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"]
    with sqlite3.connect(audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]) as connection:
        connection.execute("DELETE FROM symbols WHERE symbol_id = (SELECT symbol_id FROM symbols ORDER BY symbol_id LIMIT 1)")
        actual = int(connection.execute("SELECT COUNT(*) FROM symbols").fetchone()[0])
    index = load_json(index_path)
    index["table_counts"]["symbols"] = actual
    write_json(index_path, index)

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("table count differs from source artifacts for symbols" in error for error in broken.errors)


def test_validator_requires_smoke_query_evidence_ranges(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    with sqlite3.connect(audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]) as connection:
        symbol_name = connection.execute("SELECT name FROM symbols ORDER BY symbol_id LIMIT 1").fetchone()[0]
        connection.execute("UPDATE symbols SET evidence_ids = '[]' WHERE name = ?", (symbol_name,))
        connection.execute("UPDATE corpus_fts SET evidence_ids = '[]' WHERE title = ?", (symbol_name,))

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("smoke query" in error for error in broken.errors)


def test_validator_rejects_secret_like_text_columns(tmp_path: Path) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    with sqlite3.connect(audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]) as connection:
        connection.execute("UPDATE corpus_fts SET title = 'ghp_abcdefghijklmnopQRST' WHERE rowid = (SELECT rowid FROM corpus_fts LIMIT 1)")

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("raw secret-like text" in error for error in broken.errors)


def test_corpus_skips_cleanly_when_fts5_unavailable(tmp_path: Path, monkeypatch) -> None:
    audit_dir = run_corpus_fixture(tmp_path)
    monkeypatch.setattr("agentic_deep_audit.audit_corpus.fts5_available", lambda: (False, "forced unavailable"))

    run_corpus(load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]), audit_dir)
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])

    assert index["skipped"] is True
    assert "forced unavailable" in index["skip_reason"]
    assert (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE_SKIPPED"]).exists()
    assert not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists()


def test_corpus_skipped_branch_logs_rrf_override_and_validates_strictly(tmp_path: Path, monkeypatch) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    config = {
        "schema_version": "1.0",
        "repo": {"kind": "local", "path": ".", "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": "audit",
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": "MIT downstream",
        "binary_triage_consent": False,
        "retrieval": {"rrf": {"weights": {"fts": 2.0}}},
    }
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    result = run_cli("run", "--config", str(config_path), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    tool_status_path = audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]
    tool_status = load_json(tool_status_path)
    tool_status["tools"] = [tool for tool in tool_status["tools"] if tool.get("tool") != "rrf_ranker"]
    write_json(tool_status_path, tool_status)
    monkeypatch.setattr("agentic_deep_audit.audit_corpus.fts5_available", lambda: (False, "forced unavailable"))

    run_corpus(load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]), audit_dir)
    tool_status = load_json(tool_status_path)

    assert any(tool["tool"] == "rrf_ranker" and any("override_keys=weights.fts" in note for note in tool.get("notes", [])) for tool in tool_status["tools"])
    assert validate_audit(audit_dir).ok

    (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).write_text("stale", encoding="utf-8")
    broken = validate_audit(audit_dir)
    assert not broken.ok
    assert any("skipped state must not leave CORPUS.sqlite" in error for error in broken.errors)


def test_rrf_override_is_logged_and_validated(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    config = {
        "schema_version": "1.0",
        "repo": {"kind": "local", "path": ".", "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": "audit",
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": "MIT downstream",
        "binary_triage_consent": False,
        "retrieval": {"rrf": {"k": 42, "weights": {"fts": 2.0, "symbol": 1.5}}},
    }
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    result = run_cli("run", "--config", str(config_path), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])
    tool_status = load_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"])

    assert index["rrf"]["k"] == 42
    assert index["rrf"]["weights"]["fts"] == 2.0
    assert any(tool["tool"] == "rrf_ranker" and any("override_keys=" in note for note in tool.get("notes", [])) for tool in tool_status["tools"])
    assert validate_audit(audit_dir).ok

    tool_status["tools"] = [tool for tool in tool_status["tools"] if tool.get("tool") != "rrf_ranker"]
    (audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]).write_text(json.dumps(tool_status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    broken = validate_audit(audit_dir)
    assert not broken.ok
    assert any("RRF override" in error for error in broken.errors)


def test_run_dry_run_lists_corpus_artifacts(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")

    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), "--dry-run", cwd=repo)

    assert result.returncode == 0, result.stderr
    planned = set(json.loads(result.stdout)["planned_artifacts"])
    assert {ARTIFACT_PATHS["CORPUS_INDEX"], ARTIFACT_PATHS["CORPUS_SQLITE"]} <= planned
