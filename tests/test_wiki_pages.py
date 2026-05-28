from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.audit_wiki import decision_paths, markdown_text, run_wiki, stable_slug, write_page, write_table_category
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT
from agentic_deep_audit.validate_wiki import REQUIRED_FRONTMATTER, parse_frontmatter


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "agentic_deep_audit.cli", *args], cwd=cwd, env=cli_env(), check=False, text=True, capture_output=True)


def copy_fixture(tmp_path: Path, name: str = "performance_quality_project") -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_wiki_fixture(tmp_path: Path, command: str = "wiki") -> Path:
    repo = copy_fixture(tmp_path)
    result = run_cli(command, "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo / "audit"


def test_wiki_command_generates_pages_and_indexes_corpus(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)

    for key in ["WIKI_HOME", "WIKI_REPO_SUMMARY", "WIKI_ARCHITECTURE", "WIKI_REUSE_INDEX", "WIKI_RISK_INDEX"]:
        text = (audit_dir / ARTIFACT_PATHS[key]).read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert "## Purpose" in text
        assert "## Key Evidence" in text
        assert "## Open Questions" in text
    assert list((audit_dir / "wiki" / "modules").glob("*.md"))
    assert list((audit_dir / "wiki" / "features").glob("*.md"))
    assert list((audit_dir / "wiki" / "reuse").glob("*.md"))

    with sqlite3.connect(audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]) as connection:
        wiki_pages = int(connection.execute("SELECT COUNT(*) FROM wiki_pages").fetchone()[0])

    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])
    assert wiki_pages > 0
    assert index["table_counts"]["wiki_pages"] == wiki_pages
    assert any(path.startswith("wiki/") for path in index["source_artifact_hashes"])
    assert validate_audit(audit_dir).ok


def test_wiki_templates_match_required_frontmatter_contract() -> None:
    for name in ["obsidian_index.md", "module_page.md", "reuse_card.md"]:
        path = PLUGIN_ROOT / "assets" / "templates" / name
        errors: list[str] = []
        frontmatter = parse_frontmatter(path, path.read_text(encoding="utf-8"), errors)

        assert not errors
        assert REQUIRED_FRONTMATTER <= set(frontmatter)


def test_wiki_page_escapes_untrusted_markdown_fragments(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    write_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"], {"schema_version": "1.0", "git": {"commit": "abc"}})
    write_page(
        audit_dir,
        "wiki/modules/evil.md",
        "Module <script>alert(1)</script>",
        "module",
        ["module"],
        [],
        [],
        "Purpose <img src=x onerror=alert(1)>",
        ["- Path: `<script>alert(1)</script>|spoof`."],
    )

    text = (audit_dir / "wiki" / "modules" / "evil.md").read_text(encoding="utf-8")

    assert "<script>" not in text
    assert "<img" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "\\|spoof" in text


def test_run_orders_wiki_before_corpus(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path, command="run")
    index = load_json(audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"])

    assert (audit_dir / ARTIFACT_PATHS["WIKI_HOME"]).exists()
    assert index["table_counts"]["wiki_pages"] > 0
    assert any(path == ARTIFACT_PATHS["WIKI_HOME"] for path in index["source_artifact_hashes"])


def test_wiki_validator_rejects_bad_frontmatter_and_unreachable_evidence(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    page = audit_dir / ARTIFACT_PATHS["WIKI_HOME"]
    text = page.read_text(encoding="utf-8")
    page.write_text(text.replace("evidence_ids:", "bad_evidence_ids:", 1) + "\n`ev-999999`\n", encoding="utf-8")

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("frontmatter missing keys" in error for error in broken.errors)
    assert any("unreachable evidence id" in error for error in broken.errors)


def test_wiki_validator_rejects_bad_frontmatter_types_and_slug(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    page = audit_dir / ARTIFACT_PATHS["WIKI_HOME"]
    text = page.read_text(encoding="utf-8")
    page.write_text(text.replace('tags: ["agentic-deep-audit", "index"]', 'tags: "agentic-deep-audit"', 1), encoding="utf-8")
    broken_tags = validate_audit(audit_dir)
    assert not broken_tags.ok
    assert any("frontmatter tags" in error for error in broken_tags.errors)

    result = run_cli("wiki", "--config", str(audit_dir.parent / "audit.config.yaml"), cwd=audit_dir.parent)
    assert result.returncode == 0, result.stderr
    text = page.read_text(encoding="utf-8")
    page.write_text(text.replace('source_artifacts: ["RUN_CONFIG.json", "FILE_INDEX.json", "EVIDENCE_INDEX.json"]', 'source_artifacts: "RUN_CONFIG.json"', 1), encoding="utf-8")
    broken_sources = validate_audit(audit_dir)
    assert not broken_sources.ok
    assert any("frontmatter source_artifacts" in error for error in broken_sources.errors)

    result = run_cli("wiki", "--config", str(audit_dir.parent / "audit.config.yaml"), cwd=audit_dir.parent)
    assert result.returncode == 0, result.stderr
    text = page.read_text(encoding="utf-8")
    page.write_text(text.replace('slug: "000_home"', 'slug: "not-deterministic"', 1), encoding="utf-8")
    broken_slug = validate_audit(audit_dir)
    assert not broken_slug.ok
    assert any("frontmatter slug" in error for error in broken_slug.errors)


def test_wiki_validator_rejects_broken_markdown_and_obsidian_links(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    page = audit_dir / ARTIFACT_PATHS["WIKI_HOME"]
    page.write_text(page.read_text(encoding="utf-8") + "\n[missing](missing.md)\n[[missing/page]]\n", encoding="utf-8")

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("broken markdown link" in error for error in broken.errors)
    assert any("broken obsidian link" in error for error in broken.errors)


def test_wiki_coverage_fails_when_required_module_page_missing(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    for module_page in (audit_dir / "wiki" / "modules").glob("*.md"):
        if module_page.name != "index.md":
            module_page.unlink()

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("wiki module coverage below" in error for error in broken.errors)


def test_wiki_coverage_requires_observed_module_evidence(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    for module_page in (audit_dir / "wiki" / "modules").glob("*.md"):
        if module_page.name == "index.md":
            continue
        text = module_page.read_text(encoding="utf-8")
        module_page.write_text(text.replace('evidence_ids: ["', 'evidence_ids: []\nold_evidence_ids: ["', 1), encoding="utf-8")

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("wiki module coverage below" in error for error in broken.errors)


def test_minimal_wiki_coverage_uses_top_50_formula(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    audit_dir = tmp_path / "audit"
    run_config = {
        "schema_version": "1.0",
        "run_id": "run-minimal-coverage",
        "repo": {"kind": "local", "path": str(repo), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(audit_dir),
        "scope_filters": {"include": ["**/*"], "exclude": []},
        "target_context": {"reuse_policy": "test", "allowed_languages": ["*"], "license_tolerance": "none"},
        "binary_triage_consent": False,
    }
    audit_dir.mkdir()
    write_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], run_config)
    write_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"], {"schema_version": "1.0", "tools": []})
    write_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"], {"schema_version": "1.0", "git": {"commit": None, "limitations": ["no git"]}})
    evidence = [{"id": "ev-000001", "path": "src/module_0000.py", "kind": "file", "start_byte": 0, "end_byte": 1, "sha256": "0" * 64, "observed": "x"}]
    write_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], {"schema_version": "1.0", "repo": {"path": str(repo), "commit": None}, "evidence": evidence, "claims": []})
    nodes = [{"id": f"module:src/module_{index:04d}.py", "type": "module", "path": f"src/module_{index:04d}.py", "size_bytes": 1000 - index, "evidence_ids": ["ev-000001"]} for index in range(1000)]
    write_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], {"schema_version": "1.0", "nodes": nodes, "edges": []})
    write_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], {"schema_version": "1.0", "symbols": []})
    write_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"], {"schema_version": "1.0", "repo": {"path": str(repo)}, "records": []})
    write_json(audit_dir / ARTIFACT_PATHS["GRAPH"], {"schema_version": "1.0", "nodes": nodes, "edges": []})
    for key, value in {
        "ARCHITECTURE": "# Architecture\n\n- skipped: synthetic.\n",
        "FEATURE_CATALOG": "# Feature Catalog\n\n| Feature | Source | Status | Evidence |\n|---|---|---|---|\n",
        "PATTERNS": "# Patterns\n\n| Pattern | Implementation Loci | Confidence | Reuse Relevance | Evidence |\n|---|---|---|---|---|\n",
        "REUSE_MAP": "# Reuse Map\n\n- skipped.\n",
        "RISK_REPORT": "# Risk Report\n\n- skipped.\n",
        "OPEN_QUESTIONS": "# Open Questions\n\n- synthetic.\n",
    }.items():
        (audit_dir / ARTIFACT_PATHS[key]).write_text(value, encoding="utf-8")
    write_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"], {"schema_version": "1.0", "candidates": []})
    write_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"], {"schema_version": "1.0", "cards": []})
    write_json(audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"], {"schema_version": "1.0", "findings": []})
    write_json(audit_dir / ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"], {"schema_version": "1.0", "records": []})

    run_wiki(run_config, audit_dir)
    modules = sorted(path for path in (audit_dir / "wiki" / "modules").glob("*.md") if path.name != "index.md")
    assert len(modules) == 50
    for module in modules[:16]:
        module.unlink()
    broken = validate_audit(audit_dir)
    assert not broken.ok
    assert any("wiki module coverage below 70%" in error for error in broken.errors)


def test_corpus_hashes_wiki_source_artifacts(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    graph["nodes"][0]["label"] = "drift"
    write_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], graph)
    broken_graph = validate_audit(audit_dir)
    assert not broken_graph.ok
    assert any("source_artifact_hashes drift" in error for error in broken_graph.errors)

    result = run_cli("wiki", "--config", str(audit_dir.parent / "audit.config.yaml"), cwd=audit_dir.parent)
    assert result.returncode == 0, result.stderr
    reuse = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"])
    reuse["cards"].append({"reuse_id": "reuse-drift", "candidate_id": "candidate-drift", "name": "drift", "evidence_ids": []})
    write_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"], reuse)
    broken_reuse = validate_audit(audit_dir)
    assert not broken_reuse.ok
    assert any("source_artifact_hashes drift" in error for error in broken_reuse.errors)


def test_wiki_validator_requires_category_and_decision_pages(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    (audit_dir / "wiki" / "patterns" / "index.md").unlink()
    broken_category = validate_audit(audit_dir)
    assert not broken_category.ok
    assert any("missing wiki category page: wiki/patterns/index.md" in error for error in broken_category.errors)

    result = run_cli("wiki", "--config", str(audit_dir.parent / "audit.config.yaml"), cwd=audit_dir.parent)
    assert result.returncode == 0, result.stderr
    (audit_dir / "wiki" / "decisions" / "000_decisions_skipped.md").unlink()
    broken_decision = validate_audit(audit_dir)
    assert not broken_decision.ok
    assert any("wiki decisions requires" in error for error in broken_decision.errors)


def test_wiki_frontmatter_requires_repo_and_commit(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    page = audit_dir / ARTIFACT_PATHS["WIKI_HOME"]
    text = page.read_text(encoding="utf-8")
    filtered = "\n".join(line for line in text.splitlines() if not line.startswith(("repo:", "commit:"))) + "\n"
    page.write_text(filtered, encoding="utf-8")

    broken = validate_audit(audit_dir)

    assert not broken.ok
    assert any("frontmatter missing keys" in error and "repo" in error and "commit" in error for error in broken.errors)


def test_wiki_slugs_are_deterministic_across_two_runs(tmp_path: Path) -> None:
    first = run_wiki_fixture(tmp_path / "first")
    second = run_wiki_fixture(tmp_path / "second")
    first_modules = sorted(path.name for path in (first / "wiki" / "modules").glob("*.md"))
    second_modules = sorted(path.name for path in (second / "wiki" / "modules").glob("*.md"))

    assert first_modules == second_modules
    assert stable_slug("src/api.py") == stable_slug("src/api.py")
    assert stable_slug("src api.py") != stable_slug("src/api.py")


def test_decisions_page_emits_skipped_open_question_when_no_decision_docs(tmp_path: Path) -> None:
    audit_dir = run_wiki_fixture(tmp_path)
    skipped = audit_dir / "wiki" / "decisions" / "000_decisions_skipped.md"

    assert skipped.exists()
    assert "skipped:" in skipped.read_text(encoding="utf-8")


def test_decision_paths_reject_repo_relative_traversal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "CHANGELOG.md").write_text("# Changelog\n\n- Architecture decision: escape.\n", encoding="utf-8")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    write_json(
        audit_dir / ARTIFACT_PATHS["FILE_INDEX"],
        {
            "schema_version": "1.0",
            "repo": {"path": str(repo)},
            "records": [{"path": "../outside/CHANGELOG.md", "path_normalized": "../outside/CHANGELOG.md"}],
        },
    )
    write_json(
        audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"],
        {"schema_version": "1.0", "evidence": [{"id": "ev-000001", "path": "../outside/CHANGELOG.md"}]},
    )

    assert decision_paths(audit_dir) == []


def test_wiki_page_blocks_markdown_structure_and_codespan_injection(tmp_path: Path) -> None:
    # C6-01: attacker-controlled title/purpose/detail must not forge markdown headings/lists via
    # embedded newlines, nor open a code span via backticks, in the rendered single-line contexts.
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    write_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"], {"schema_version": "1.0", "git": {"commit": "abc"}})
    write_page(
        audit_dir,
        "wiki/modules/inject.md",
        "Mod\n## Forged Heading\n- forged item",
        "module",
        ["module"],
        [],
        [],
        "Purpose\n# Forged Title",
        ["Detail `open span` and\n## forged detail heading"],
    )

    text = (audit_dir / "wiki" / "modules" / "inject.md").read_text(encoding="utf-8")
    lines = text.splitlines()

    # Without the fix the embedded newlines survive and these become standalone markdown lines.
    assert "## Forged Heading" not in lines
    assert "# Forged Title" not in lines
    assert "## forged detail heading" not in lines
    assert "- forged item" not in lines
    # Without the fix the backticks open a real code span; the fix escapes them.
    assert "\\`open span\\`" in text


def test_wiki_table_category_drops_unavailable_evidence_ids(tmp_path: Path) -> None:
    # C6-02: ev- tokens harvested from attacker-influenced source rows must be validated against
    # EVIDENCE_INDEX so a forged "ev-999999" cannot become a fabricated wiki evidence link.
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    write_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"], {"schema_version": "1.0", "git": {"commit": "abc"}})
    write_json(
        audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"],
        {
            "schema_version": "1.0",
            "repo": {"path": str(tmp_path), "commit": None},
            "evidence": [{"id": "ev-000001", "path": "src/a.py", "kind": "file", "start_byte": 0, "end_byte": 1, "sha256": "0" * 64, "observed": "x"}],
        },
    )
    (audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]).write_text(
        "# Feature Catalog\n\n| Feature | Source | Status | Evidence |\n|---|---|---|---|\n"
        "| Feat A | src/a.py | observed | ev-000001 ev-999999 |\n",
        encoding="utf-8",
    )
    run_config = {"repo": {"kind": "local", "path": str(tmp_path), "github": None}}

    write_table_category(audit_dir, run_config, "FEATURE_CATALOG", "features", "Features", "feature")

    pages = [path for path in (audit_dir / "wiki" / "features").glob("*.md") if path.name != "index.md"]
    assert pages
    text = pages[0].read_text(encoding="utf-8")
    match = re.search(r"evidence_ids:\s*(\[[^\]]*\])", text)
    assert match
    ids = json.loads(match.group(1))
    assert "ev-000001" in ids
    assert "ev-999999" not in ids
