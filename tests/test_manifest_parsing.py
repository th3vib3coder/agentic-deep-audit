from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import agentic_deep_audit.audit_manifest as audit_manifest
from agentic_deep_audit.audit_validate import validate_audit, validate_manifest_artifacts
from agentic_deep_audit.models import ARTIFACT_PATHS
from agentic_deep_audit.policy import decide_command


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=cli_env(),
        check=False,
        text=True,
        capture_output=True,
    )


def write_config(repo: Path) -> Path:
    config = repo / "audit.config.yaml"
    config.write_text(
        "\n".join(
            [
                'schema_version: "1.0"',
                "repo:",
                '  kind: "local"',
                '  path: "."',
                "  github: null",
                'profile: "minimal"',
                'mode: "source-audit"',
                'output_dir: "audit"',
                "scope_filters:",
                '  include: ["**/*"]',
                '  exclude: [".git/**", "node_modules/**"]',
                'target_context: "MIT downstream"',
                "binary_triage_consent: false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return config


def prepare_manifest_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    write_config(repo)
    (repo / "pyproject.toml").write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=68"]',
                'build-backend = "setuptools.build_meta"',
                "[project]",
                'name = "polyglot-fixture"',
                'dependencies = ["requests>=2"]',
                "[project.scripts]",
                'fixture-cli = "fixture:main"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("numpy==2.0\n-r constraints.txt\n", encoding="utf-8")
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture-js",
                "dependencies": {"express": "^4.0.0"},
                "devDependencies": {"jest": "^29.0.0"},
                "scripts": {"test": "jest --runInBand", "build": "tsc -p tsconfig.json", "docs": "typedoc src/index.ts"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (repo / "Cargo.toml").write_text('[package]\nname = "fixture-rs"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n', encoding="utf-8")
    (repo / "go.mod").write_text("module example.com/fixture\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n", encoding="utf-8")
    (repo / "pom.xml").write_text(
        '<project><groupId>com.example</groupId><artifactId>fixture</artifactId><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency></dependencies></project>',
        encoding="utf-8",
    )
    (repo / "build.gradle").write_text(
        "rootProject.name = 'fixture-gradle'\ndependencies { implementation 'org.slf4j:slf4j-api:2.0.0' }\ntask smoke { commandLine 'gradle test' }\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text("FROM python:3.12\nRUN pip install -r requirements.txt\n", encoding="utf-8")
    (repo / "compose.yaml").write_text("services:\n  app:\n    image: fixture\n    command: python -m pytest\n", encoding="utf-8")
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        "name: CI\non:\n  push:\njobs:\n  test:\n    steps:\n      - run: python -m pytest\n      - run: npm test\n",
        encoding="utf-8",
    )
    (workflow_dir / "block.yml").write_text(
        "name: Block\non:\n  pull_request:\njobs:\n  test:\n    steps:\n      - run: |\n          npm ci\n          npm test\n",
        encoding="utf-8",
    )
    return repo


def run_inventory_fixture(tmp_path: Path) -> tuple[Path, Path]:
    repo = prepare_manifest_fixture(tmp_path)
    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo, repo / "audit"


def test_manifest_parser_covers_supported_manifest_types(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    manifests = json.loads((audit_dir / ARTIFACT_PATHS["MANIFESTS"]).read_text(encoding="utf-8"))
    records = {record["path"]: record for record in manifests["records"]}

    expected = {"pyproject.toml", "requirements.txt", "package.json", "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "Dockerfile", "compose.yaml"}
    assert expected <= set(records)
    assert records["pyproject.toml"]["ecosystem"] == "python"
    assert records["package.json"]["package_name"] == "fixture-js"
    assert any(dep["name"] == "express" for dep in records["package.json"]["dependencies"])
    assert any(dep["name"] == "github.com/gin-gonic/gin" for dep in records["go.mod"]["dependencies"])
    assert any(dep["name"] == "junit:junit" for dep in records["pom.xml"]["dependencies"])
    for path in expected:
        assert records[path]["evidence_ids"]


def test_build_test_map_records_commands_as_observed_not_executed(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    build_map = (audit_dir / ARTIFACT_PATHS["BUILD_TEST_MAP"]).read_text(encoding="utf-8")

    assert "`jest --runInBand`" in build_map
    assert "`python -m pytest`" in build_map
    command_rows = [line for line in build_map.splitlines() if line.startswith("| ") and "`" in line]
    assert command_rows
    assert all("observed, not executed" in row for row in command_rows)
    assert all("target_repo_manifest_no_exec" in row for row in command_rows)


def test_manifest_commands_are_denied_by_target_repo_origin(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    manifests = json.loads((audit_dir / ARTIFACT_PATHS["MANIFESTS"]).read_text(encoding="utf-8"))
    package = next(record for record in manifests["records"] if record["path"] == "package.json")
    command = package["scripts"][0]

    decision = decide_command(command["command"].split(), origin="target_repo_manifest")

    assert command["policy_decision"] == "block"
    assert command["policy_rule"] == "target_repo_manifest_no_exec"
    assert not decision.allowed
    assert decision.policy_rule == "target_repo_manifest_no_exec"


def test_ci_map_records_workflow_commands_without_executing(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    ci_map = json.loads((audit_dir / ARTIFACT_PATHS["CI_MAP"]).read_text(encoding="utf-8"))

    assert ci_map["records"]
    records = {record["path"]: record for record in ci_map["records"]}
    workflow = records[".github/workflows/ci.yml"]
    assert workflow["path"] == ".github/workflows/ci.yml"
    assert workflow["evidence_ids"]
    assert {command["command"] for command in workflow["commands"]} == {"python -m pytest", "npm test"}
    assert all(command["policy_rule"] == "target_repo_manifest_no_exec" for command in workflow["commands"])
    block = records[".github/workflows/block.yml"]
    assert {command["command"] for command in block["commands"]} == {"npm ci", "npm test"}
    assert "|" not in {command["command"] for command in block["commands"]}


def test_malformed_manifests_are_skipped_without_aborting(tmp_path: Path) -> None:
    repo = prepare_manifest_fixture(tmp_path)
    (repo / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    (repo / "package.json").write_text("{not-json", encoding="utf-8")
    (repo / "Cargo.toml").write_text("[package\n", encoding="utf-8")
    (repo / "pom.xml").write_text("<project>", encoding="utf-8")

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    manifests = json.loads((repo / "audit" / ARTIFACT_PATHS["MANIFESTS"]).read_text(encoding="utf-8"))
    records = {record["path"]: record for record in manifests["records"]}
    for path in ["pyproject.toml", "package.json", "Cargo.toml", "pom.xml"]:
        assert records[path]["skipped"] is True
        assert records[path]["evidence_ids"]
        assert records[path]["skip_reason"].startswith("parse error:")
    assert records["go.mod"]["skipped"] is False


def test_maven_manifest_entities_are_defused_without_aborting(tmp_path: Path) -> None:
    repo = prepare_manifest_fixture(tmp_path)
    (repo / "pom.xml").write_text(
        """<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY payload "expanded">
]>
<project>&payload;</project>
""",
        encoding="utf-8",
    )

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    manifests = json.loads((repo / "audit" / ARTIFACT_PATHS["MANIFESTS"]).read_text(encoding="utf-8"))
    record = {item["path"]: item for item in manifests["records"]}["pom.xml"]
    assert record["skipped"] is True
    assert "EntitiesForbidden" in record["skip_reason"]


def test_ci_workflow_size_cap_skips_commands_without_parsing(tmp_path: Path, monkeypatch) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: CI\non:\n  push:\njobs:\n  test:\n    steps:\n      - run: npm test\n", encoding="utf-8")
    monkeypatch.setattr(audit_manifest, "MAX_MANIFEST_FILE_BYTES", 8)

    record = audit_manifest.parse_ci_workflow(workflow, ".github/workflows/ci.yml", "ev-000001")

    assert record["skipped"] is True
    assert record["commands"] == []
    assert "exceeds size cap" in record["skip_reason"]


def test_shape_malformed_package_json_is_skipped_without_aborting(tmp_path: Path) -> None:
    repo = prepare_manifest_fixture(tmp_path)
    (repo / "package.json").write_text(json.dumps({"scripts": ["npm test"], "dependencies": []}) + "\n", encoding="utf-8")

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    manifests = json.loads((repo / "audit" / ARTIFACT_PATHS["MANIFESTS"]).read_text(encoding="utf-8"))
    records = {record["path"]: record for record in manifests["records"]}
    assert records["package.json"]["skipped"] is True
    assert records["package.json"]["evidence_ids"]
    assert records["package.json"]["skip_reason"].startswith("parse error:")
    assert records["pyproject.toml"]["skipped"] is False


def test_phase2_validator_rejects_command_without_observed_label(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    manifests_path = audit_dir / ARTIFACT_PATHS["MANIFESTS"]
    manifests = json.loads(manifests_path.read_text(encoding="utf-8"))
    package = next(record for record in manifests["records"] if record["path"] == "package.json")
    package["scripts"][0]["label"] = "execute"
    manifests_path.write_text(json.dumps(manifests, indent=2) + "\n", encoding="utf-8")

    validation = validate_manifest_artifacts(audit_dir)

    assert not validation.ok
    assert any("missing observed-only label" in error for error in validation.errors)


def test_phase2_artifacts_validate_with_full_audit(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)

    validation = validate_audit(audit_dir)

    assert validation.ok, validation.errors
