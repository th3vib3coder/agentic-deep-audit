from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.config import load_config_file, normalize_run_config, ArgvOverrides
from agentic_deep_audit.config import load_run_config


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def write_config(tmp_path: Path) -> Path:
    config = tmp_path / "audit.config.yaml"
    config.write_text(
        """
schema_version: "1.0"
repo:
  kind: "local"
  path: "."
  github: null
profile: "minimal"
mode: "source-audit"
output_dir: "audit"
target_context: "MIT downstream"
binary_triage_consent: false
graph:
  centrality:
    conditional_import_weight: 0.25
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=cli_env(),
        check=False,
        text=True,
        capture_output=True,
    )


def test_mutual_exclusion_config_and_run_config(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    run_config = tmp_path / "RUN_CONFIG.json"
    run_config.write_text("{}", encoding="utf-8")

    result = run_cli("run", "--config", str(config), "--run-config", str(run_config), cwd=tmp_path)

    assert result.returncode == 2
    assert "--config or --run-config, not both" in result.stderr


def test_help_lists_all_commands() -> None:
    result = run_cli("--help", cwd=PLUGIN_ROOT)

    assert result.returncode == 0
    for command in ["run", "inventory", "graph", "surface", "synthesis", "scientific", "telemetry", "risk", "wiki", "validate"]:
        assert command in result.stdout


def test_yaml_fixture_loads_and_target_context_canonicalizes(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    loaded = load_config_file(config)
    normalized = normalize_run_config(
        loaded,
        ArgvOverrides(command="run", argv=["run", "--config", str(config)]),
        config,
    )

    assert normalized["target_context"]["reuse_policy"] == "MIT downstream"
    assert normalized["target_context"]["allowed_languages"] == ["python"]
    assert normalized["target_context"]["license_tolerance"] == "permissive-only"
    assert normalized["target_context"]["production_required"] is True


def test_empty_allowed_languages_canonicalizes_to_all_languages(tmp_path: Path) -> None:
    config = {
        "schema_version": "1.0",
        "repo": {"kind": "local", "path": ".", "github": None},
        "target_context": {"reuse_policy": "custom", "allowed_languages": [], "license_tolerance": "none"},
    }

    normalized = normalize_run_config(config, ArgvOverrides(command="run", argv=["run"]), None)

    assert normalized["target_context"]["allowed_languages"] == ["*"]


def test_run_config_input_recanonicalizes_empty_allowed_languages(tmp_path: Path) -> None:
    run_config = {
        "schema_version": "1.0",
        "run_id": "run-legacy",
        "repo": {"kind": "local", "path": str(tmp_path), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(tmp_path / "audit"),
        "target_context": {"reuse_policy": "legacy", "allowed_languages": [], "license_tolerance": "none"},
    }
    path = tmp_path / "RUN_CONFIG.json"
    path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")

    loaded = load_run_config(path, ArgvOverrides(command="run", argv=["run", "--run-config", str(path)]))

    assert loaded["target_context"]["allowed_languages"] == ["*"]


def test_centrality_defaults_and_overrides(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    normalized = normalize_run_config(
        load_config_file(config),
        ArgvOverrides(command="run", argv=["run", "--config", str(config)]),
        config,
    )

    centrality = normalized["graph"]["centrality"]
    assert centrality["algorithm"] == "weighted_in_degree"
    assert centrality["normal_import_weight"] == 1.0
    assert centrality["conditional_import_weight"] == 0.25
    assert centrality["tie_break"] == ["size_bytes_desc", "path_normalized_asc"]


def test_retrieval_rrf_defaults_and_config_override_source(tmp_path: Path) -> None:
    config = {
        "schema_version": "1.0",
        "repo": {"kind": "local", "path": ".", "github": None},
        "target_context": "MIT downstream",
        "retrieval": {"rrf": {"k": 42, "weights": {"fts": 2.0}}},
    }

    normalized = normalize_run_config(config, ArgvOverrides(command="run", argv=["run"]), None)

    assert normalized["retrieval"]["rrf"]["k"] == 42
    assert normalized["retrieval"]["rrf"]["weights"] == {"fts": 2.0, "symbol": 1.0, "graph": 1.0, "manifest": 1.0}
    assert normalized["retrieval"]["rrf"]["override"] is True
    assert normalized["override_source"]["retrieval.rrf"] == "config"


def test_argv_overrides_are_recorded_and_run_config_written(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    output_dir = tmp_path / "custom-audit"

    result = run_cli("run", "--config", str(config), "--profile", "standard", "--output-dir", str(output_dir), cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    run_config = json.loads((output_dir / "RUN_CONFIG.json").read_text(encoding="utf-8"))
    assert run_config["profile"] == "standard"
    assert run_config["output_dir"] == str(output_dir)
    assert run_config["override_source"] == {"profile": "argv", "output_dir": "argv"}
    assert run_config["provenance"]["config_sha256"]
    assert "repo.path" in run_config["provenance"]["environment_specific_paths"]


def test_run_config_round_trip_via_run_config_input(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    first_output = tmp_path / "audit-one"
    second_output = tmp_path / "audit-two"
    first = run_cli("run", "--config", str(config), "--output-dir", str(first_output), cwd=tmp_path)
    assert first.returncode == 0, first.stderr

    second = run_cli("run", "--run-config", str(first_output / "RUN_CONFIG.json"), "--output-dir", str(second_output), cwd=tmp_path)

    assert second.returncode == 0, second.stderr
    rerun = json.loads((second_output / "RUN_CONFIG.json").read_text(encoding="utf-8"))
    assert rerun["output_dir"] == str(second_output)
    assert rerun["target_context"]["reuse_policy"] == "MIT downstream"


def test_load_run_config_does_not_mutate_original_dict(tmp_path: Path) -> None:
    original = {
        "schema_version": "1.0",
        "run_id": "run-immutable",
        "repo": {"kind": "local", "path": str(tmp_path), "github": None},
        "output_dir": str(tmp_path / "audit"),
        "target_context": {"reuse_policy": "legacy", "allowed_languages": [], "license_tolerance": "none"},
    }
    preserved = copy.deepcopy(original)
    path = tmp_path / "RUN_CONFIG.json"
    path.write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8")

    load_run_config(path, ArgvOverrides(command="run", argv=["run"]))

    assert original == preserved


def test_dry_run_reports_planned_work_without_writing_artifacts(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    for command in ["run", "inventory", "graph", "surface", "synthesis", "scientific", "telemetry", "risk", "wiki"]:
        output_dir = tmp_path / f"{command}-audit"
        result = run_cli(command, "--config", str(config), "--output-dir", str(output_dir), "--dry-run", cwd=tmp_path)
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["dry_run"] is True
        assert payload["planned_artifacts"]
        if command == "wiki":
            assert {
                "wiki/000_home.md",
                "wiki/001_repo_summary.md",
                "wiki/002_architecture_overview.md",
                "wiki/003_reuse_index.md",
                "wiki/004_risk_index.md",
                "wiki/modules/*.md",
                "wiki/features/*.md",
                "wiki/patterns/*.md",
                "wiki/risks/*.md",
                "wiki/reuse/*.md",
                "wiki/decisions/*.md",
                "CORPUS_INDEX.json",
                "CORPUS.sqlite",
            } <= set(payload["planned_artifacts"])
        assert not (output_dir / "RUN_CONFIG.json").exists()

    validate = run_cli("validate", "--audit-dir", str(tmp_path / "audit"), "--dry-run", cwd=tmp_path)
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["planned_artifacts"] == [
        "RUN_CONFIG.json",
        "TOOL_STATUS.json",
        "PROGRESS.md",
        "VALIDATION_REPORT.md",
        "REPORT.md",
        "OPEN_QUESTIONS.md",
        "REVIEW_LEDGER.md",
        "ADVERSARIAL_REVIEW_PACKET.md",
    ]


def test_optional_cli_overrides_are_wired_into_run_config(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    graph_output = tmp_path / "graph-audit"
    graph = run_cli(
        "graph",
        "--config",
        str(config),
        "--output-dir",
        str(graph_output),
        "--renderer",
        "mermaid",
        "--graphify",
        cwd=tmp_path,
    )
    assert graph.returncode == 0, graph.stderr
    graph_config = json.loads((graph_output / "RUN_CONFIG.json").read_text(encoding="utf-8"))
    assert graph_config["graph"]["html_renderer"] == "mermaid"
    assert graph_config["graph"]["graphify"] == "required"
    assert graph_config["override_source"]["graph.html_renderer"] == "argv"
    assert graph_config["override_source"]["graph.graphify"] == "argv"

    risk_output = tmp_path / "risk-audit"
    risk = run_cli(
        "risk",
        "--config",
        str(config),
        "--output-dir",
        str(risk_output),
        "--network-policy",
        "custom-policy.json",
        cwd=tmp_path,
    )
    assert risk.returncode == 0, risk.stderr
    risk_config = json.loads((risk_output / "RUN_CONFIG.json").read_text(encoding="utf-8"))
    assert risk_config["network_policy_file"] == "custom-policy.json"
    assert risk_config["override_source"]["network_policy_file"] == "argv"

    wiki_output = tmp_path / "wiki-audit"
    wiki = run_cli(
        "wiki",
        "--config",
        str(config),
        "--output-dir",
        str(wiki_output),
        "--graph-source",
        "graph/graph.json",
        cwd=tmp_path,
    )
    assert wiki.returncode == 0, wiki.stderr
    wiki_config = json.loads((wiki_output / "RUN_CONFIG.json").read_text(encoding="utf-8"))
    assert wiki_config["graph_source"] == "graph/graph.json"
    assert wiki_config["override_source"]["graph_source"] == "argv"


def test_missing_config_path_fails_with_clear_error(tmp_path: Path) -> None:
    result = run_cli("run", "--config", str(tmp_path / "does-not-exist.yaml"), cwd=tmp_path)

    assert result.returncode == 2
    assert "error: config file not found:" in result.stderr
    assert "Traceback" not in result.stderr
