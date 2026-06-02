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


def test_corpus_secret_check_ignores_code_and_markup_high_entropy() -> None:
    # FIX-2 (Tier-0): README badge URLs and TS/JS code are high-entropy but NOT secrets; the
    # corpus no-secret gate must neither redact nor flag them (Understand-Anything false positive).
    from agentic_deep_audit.audit_corpus import contains_raw_secret, redact_text

    benign = (
        '[![Claude](https://img.shields.io/badge/Claude_Code-8A2BE2)] '
        'expect(result.data!.nodes[1].type).toBe("flow")'
    )
    redacted, count = redact_text(benign)
    assert count == 0
    assert "<redacted" not in redacted
    assert not contains_raw_secret(benign)
    # GUARD: a real provider token is still redacted and still flagged as raw secret-like.
    secret_blob = 'TOKEN = "ghp_abcdefghijklmnopQRST"'
    redacted_secret, secret_count = redact_text(secret_blob)
    assert secret_count >= 1
    assert "ghp_abcdefghijklmnopQRST" not in redacted_secret
    assert contains_raw_secret(secret_blob)


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


def test_artifact_cap_exceeds_untrusted_file_cap() -> None:
    # Scalability fix: own GENERATED artifacts (graph.json, *_index.json) are TRUSTED and sized by the
    # audited repo; they must be readable above the 25MB cap that protects reads of UNTRUSTED
    # target-repo files. Own-artifact readers use MAX_ARTIFACT_FILE_BYTES, not the untrusted cap.
    from agentic_deep_audit.limits import MAX_ARTIFACT_FILE_BYTES, MAX_AUDIT_FILE_BYTES

    assert MAX_ARTIFACT_FILE_BYTES > MAX_AUDIT_FILE_BYTES


def test_corpus_load_json_honors_artifact_cap(tmp_path: Path, monkeypatch) -> None:
    # load_json must read the cap at call time so the own-artifact cap governs corpus input reads,
    # NOT the hardcoded 25MB untrusted default of read_json_capped. (OpenHuman: graph.json was 65MB.)
    import pytest

    import agentic_deep_audit.audit_corpus as corpus
    from agentic_deep_audit.limits import FileSizeLimitError

    artifact = tmp_path / "artifact.json"
    artifact.write_text(json.dumps({"blob": "x" * 4096}), encoding="utf-8")
    monkeypatch.setattr(corpus, "MAX_ARTIFACT_FILE_BYTES", 256, raising=False)
    with pytest.raises(FileSizeLimitError):
        corpus.load_json(artifact)


def test_corpus_skips_when_inputs_exceed_build_budget(tmp_path: Path, monkeypatch) -> None:
    # Large-repo scalability (the OpenHuman case): when the corpus input artifacts exceed the build
    # budget, run_corpus DEGRADES gracefully (writes CORPUS_SQLITE_SKIPPED + a skipped CORPUS_INDEX
    # and returns) so the run completes and REPORT.md is still produced, instead of hard-failing on
    # the file-size cap (exit 5) or hanging on a huge FTS build. A skipped corpus still validates.
    audit_dir = run_corpus_fixture(tmp_path)
    monkeypatch.setattr("agentic_deep_audit.audit_corpus.MAX_CORPUS_INPUT_BYTES", 1, raising=False)

    run_corpus(load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]), audit_dir)
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])

    assert index["skipped"] is True
    assert "build budget" in index["skip_reason"]
    assert (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE_SKIPPED"]).exists()
    assert not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists()
    assert validate_audit(audit_dir).ok


def test_read_json_capped_defaults_to_artifact_cap() -> None:
    # Keystone of the scalability fix: read_json_capped (used by every own-artifact reader, including
    # the validate path) must default to the 256MB artifact cap, not the 25MB untrusted-file cap, so
    # validate_audit does not turn a large own graph.json into a size-cap blocker (which withheld
    # REPORT.md on OpenHuman).
    import inspect

    from agentic_deep_audit.limits import MAX_ARTIFACT_FILE_BYTES, read_json_capped

    default = inspect.signature(read_json_capped).parameters["max_bytes"].default
    assert default == MAX_ARTIFACT_FILE_BYTES


def test_corpus_degrades_on_corrupt_graph_instead_of_crashing(tmp_path: Path) -> None:
    # The corpus must DEGRADE (skip with an honest, distinct reason), not crash the run, on a corrupt
    # own artifact — the same graceful-degradation contract the size guard provides (swarm P2).
    audit_dir = run_corpus_fixture(tmp_path)
    (audit_dir / ARTIFACT_PATHS["GRAPH"]).write_text("{ this is not valid json", encoding="utf-8")

    run_corpus(load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]), audit_dir)
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])

    assert index["skipped"] is True
    assert "not valid JSON" in index["skip_reason"]
    assert not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists()


def test_corpus_degrades_on_pathological_graph_depth(tmp_path: Path) -> None:
    # A pathologically/adversarially deep own artifact must DEGRADE with a DISTINCT depth reason, not
    # be mislabeled as a benign "too large" size skip. JsonDepthLimitError subclasses FileSizeLimitError,
    # so the catch ORDER in run_corpus matters; this proves the ordering at runtime (swarm P2).
    audit_dir = run_corpus_fixture(tmp_path)
    deep = "[" * 50000 + "]" * 50000
    (audit_dir / ARTIFACT_PATHS["GRAPH"]).write_text(deep, encoding="utf-8")

    run_corpus(load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]), audit_dir)
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])

    assert index["skipped"] is True
    assert "nesting depth" in index["skip_reason"]
    assert not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists()


def test_mcp_export_defers_when_corpus_skipped(tmp_path: Path, monkeypatch) -> None:
    # A SKIPPED corpus has no CORPUS.sqlite, so the audit_query MCP tool would 404 at call time;
    # run_mcp_export must DEFER (write MCP_DEFERRED), not advertise a dead tool via MCP_CONFIG (P2).
    from agentic_deep_audit.audit_mcp_export import run_mcp_export

    audit_dir = run_corpus_fixture(tmp_path)
    monkeypatch.setattr("agentic_deep_audit.audit_corpus.MAX_CORPUS_INPUT_BYTES", 1, raising=False)
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"])
    run_corpus(run_config, audit_dir)
    assert load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])["skipped"] is True

    run_mcp_export(run_config, audit_dir)

    assert (audit_dir / ARTIFACT_PATHS["MCP_DEFERRED"]).exists()
    assert not (audit_dir / ARTIFACT_PATHS["MCP_CONFIG"]).exists()
    assert "skip" in (audit_dir / ARTIFACT_PATHS["MCP_DEFERRED"]).read_text(encoding="utf-8").lower()


def test_corpus_skip_marks_rrf_capability_unavailable(tmp_path: Path, monkeypatch) -> None:
    # Honesty (swarm P1): a skipped corpus has no DB to rank over, so the rrf / hybrid-retrieval
    # capability must NOT be advertised as available in TOOL_STATUS — and the honest "skipped" status
    # must NOT itself withhold REPORT.md (validate_audit stays ok, and it is not a tool failure).
    audit_dir = run_corpus_fixture(tmp_path)
    monkeypatch.setattr("agentic_deep_audit.audit_corpus.MAX_CORPUS_INPUT_BYTES", 1, raising=False)
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"])
    run_corpus(run_config, audit_dir)
    assert load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])["skipped"] is True

    tool_status = load_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"])
    rrf_entries = [tool for tool in tool_status["tools"] if tool.get("tool") == "rrf_ranker"]
    assert rrf_entries, "rrf_ranker status must still be recorded on the skip path"
    latest = rrf_entries[-1]
    assert latest["status"] == "skipped"
    assert latest["available"] is False
    assert latest.get("availability") != "available"
    assert latest.get("skipped_reason")
    assert validate_audit(audit_dir).ok


def test_corpus_degrades_on_unreadable_input_instead_of_crashing(tmp_path: Path, monkeypatch) -> None:
    # A corpus input that exists but raises OSError must DEGRADE (skip), not crash run_corpus. A real
    # permission-denied artifact fails BOTH the load AND the hash that write_corpus_skipped computes
    # via source_artifact_hashes — so we make both raise for GRAPH. Without the hash-layer guard
    # (hash_file_or_skip) the degrade handler itself would re-raise OSError and crash (swarm P2).
    import agentic_deep_audit.audit_corpus as corpus_mod

    audit_dir = run_corpus_fixture(tmp_path)
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"])
    graph_rel = ARTIFACT_PATHS["GRAPH"]
    real_load_json = corpus_mod.load_json
    real_sha256_file = corpus_mod.sha256_file

    def explodes_for_graph(path: Path) -> bool:
        return Path(path).as_posix().endswith(graph_rel)

    def exploding_load_json(path: Path):
        if explodes_for_graph(path):
            raise OSError("simulated unreadable corpus input")
        return real_load_json(path)

    def exploding_sha256_file(path: Path):
        if explodes_for_graph(path):
            raise PermissionError("simulated unreadable corpus input")
        return real_sha256_file(path)

    monkeypatch.setattr(corpus_mod, "load_json", exploding_load_json)
    monkeypatch.setattr(corpus_mod, "sha256_file", exploding_sha256_file)
    corpus_mod.run_corpus(run_config, audit_dir)  # must NOT raise even though read AND hash fail

    index = real_load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])
    assert index["skipped"] is True
    assert "could not be read" in index["skip_reason"]
    assert not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists()
    # the unreadable GRAPH is omitted from the source-hash map (degraded, not crashed, not a fake hash)
    assert graph_rel not in index["source_artifact_hashes"]


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
