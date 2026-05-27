from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_graph import run_graph
from agentic_deep_audit.audit_inventory import run_inventory
from agentic_deep_audit.audit_manifest import run_manifest
from agentic_deep_audit.audit_scientific import run_scientific_provenance, source_method
from agentic_deep_audit.audit_surface import run_surface
from agentic_deep_audit.audit_synthesis import run_synthesis
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.bootstrap import bootstrap_audit
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def copy_fixture(name: str, tmp_path: Path) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def config_for(repo: Path, output: Path) -> dict:
    return {
        "schema_version": "1.0",
        "run_id": "run-scientific",
        "repo": {"kind": "local", "path": str(repo), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(output),
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": {"preset": "MIT downstream"},
        "binary_triage_consent": False,
        "graph": {"centrality": {"algorithm": "weighted_in_degree", "normal_import_weight": 1.0, "conditional_import_weight": 0.5, "tie_break": ["size_bytes_desc", "path_normalized_asc"]}},
    }


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_scientific(repo: Path, output: Path) -> tuple[Path, dict]:
    run_config = config_for(repo, output)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")
    run_config["provenance"] = {"config_path": str(config_path)}
    audit_dir = bootstrap_audit(run_config, cwd=repo)
    run_inventory(run_config, audit_dir)
    run_manifest(run_config, audit_dir)
    run_graph(run_config, audit_dir)
    run_surface(run_config, audit_dir)
    run_synthesis(run_config, audit_dir)
    run_scientific_provenance(run_config, audit_dir)
    return audit_dir, run_config


def test_scientific_fixture_contains_required_evidence_categories(tmp_path: Path) -> None:
    repo = copy_fixture("scientific_data_project", tmp_path)
    audit_dir, _ = build_scientific(repo, repo / "audit-scientific")

    payload = load_json(audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"])
    categories = {record["category"] for record in payload["records"]}
    required = {
        "dataset_provenance",
        "pipeline_version",
        "tool_version",
        "parameters_and_seeds",
        "genome_build",
        "organism_taxon",
        "annotation_version",
        "sample_cell_gene_ids",
        "normalization_assumptions",
        "analysis_confounder",
        "batch_confounder_model",
        "notebook_execution_order",
        "model_checkpoint",
        "reproducibility_makefile",
    }

    assert required <= categories
    for record in payload["records"]:
        assert record["category"]
        assert record["observed_value"]
        assert record["confidence"] in {"high", "medium", "low"}
        assert record["evidence_ids"]
    assert any(record["requires_human_decision"] for record in payload["records"])
    assert validate_audit(audit_dir).ok


def test_readme_scientific_signals_require_human_decision() -> None:
    text = (FIXTURES / "scientific_data_project" / "README.md").read_text(encoding="utf-8")

    assert source_method("README.md", text) == ("comment_or_docstring", "medium", True)


def test_non_scientific_repo_emits_empty_records_and_note(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_scientific(repo, repo / "audit-nonscientific")

    payload = load_json(audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"])
    report = (audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"]).read_text(encoding="utf-8")

    assert payload["records"] == []
    assert "no scientific signals detected" in report
    assert not (audit_dir / "SCIENTIFIC_PROVENANCE_SKIPPED.md").exists()
    assert validate_audit(audit_dir).ok
    assert run_config["run_id"] == "run-scientific"


def test_scientific_values_are_not_inferred_without_textual_evidence(tmp_path: Path) -> None:
    repo = copy_fixture("scientific_data_project", tmp_path)
    config_path = repo / "config" / "analysis.yaml"
    config_text = config_path.read_text(encoding="utf-8")
    config_path.write_text("\n".join(line for line in config_text.splitlines() if "genome_build" not in line and "GRCh38" not in line) + "\n", encoding="utf-8")
    audit_dir, _ = build_scientific(repo, repo / "audit-no-genome")

    payload = load_json(audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"])

    assert "genome_build" not in {record["category"] for record in payload["records"]}


def test_scientific_provenance_claim_without_record_fails_validation(tmp_path: Path) -> None:
    repo = copy_fixture("scientific_data_project", tmp_path)
    audit_dir, _ = build_scientific(repo, repo / "audit-broken-scientific")
    report_path = audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"]
    report_path.write_text(report_path.read_text(encoding="utf-8") + "\nGenome build: GRCh38\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("SCIENTIFIC_PROVENANCE.md scientific claim lacks provenance record or open question" in error for error in result.errors)


def test_report_and_wiki_scientific_claims_without_record_fail_validation(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, _ = build_scientific(repo, repo / "audit-report-wiki-claims")
    (audit_dir / ARTIFACT_PATHS["REPORT"]).write_text("# Report\n\nGenome build: GRCh38\n", encoding="utf-8")
    wiki_dir = audit_dir / "wiki"
    wiki_dir.mkdir()
    (wiki_dir / "science.md").write_text("# Wiki\n\nBatch correction used ComBat.\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("REPORT.md scientific claim lacks provenance record or open question" in error for error in result.errors)
    assert any("wiki/science.md scientific claim lacks provenance record or open question" in error for error in result.errors)


def test_cli_scientific_command_wires_outputs(tmp_path: Path) -> None:
    repo = copy_fixture("scientific_data_project", tmp_path)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(config_for(repo, repo / "audit-cli-scientific"), indent=2) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", "scientific", "--config", str(config_path)],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit-cli-scientific"
    assert (audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"]).exists()
    assert (audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"]).exists()
