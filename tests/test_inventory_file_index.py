from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from agentic_deep_audit.audit_validate import validate_audit, validate_inventory_artifacts
from agentic_deep_audit.config import sha256_file
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures" / "python_basic"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def prepare_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE_ROOT, target)
    (target / "assets" / "logo.bin").write_bytes(b"\x00\x01\x02")
    git_dir = target / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    return target


def write_config(repo: Path, output_dir: str = "audit") -> Path:
    config = repo / "audit.config.yaml"
    lines = [
        'schema_version: "1.0"',
        "repo:",
        '  kind: "local"',
        '  path: "."',
        "  github: null",
        'profile: "minimal"',
        'mode: "source-audit"',
        f'output_dir: "{output_dir}"',
        "scope_filters:",
        '  include: ["**/*"]',
        '  exclude: [".git/**", "node_modules/**"]',
        'target_context: "MIT downstream"',
        "binary_triage_consent: false",
    ]
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
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


def run_inventory_fixture(tmp_path: Path) -> tuple[Path, Path]:
    repo = prepare_fixture(tmp_path)
    config = write_config(repo)
    result = run_cli("inventory", "--config", str(config), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo, repo / "audit"


def test_python_basic_fixture_has_required_file_categories() -> None:
    assert (FIXTURE_ROOT / "src" / "app.py").exists()
    assert (FIXTURE_ROOT / "README.md").exists()
    assert (FIXTURE_ROOT / "pyproject.toml").exists()
    assert (FIXTURE_ROOT / "tests" / "test_app.py").exists()
    assert (FIXTURE_ROOT / "node_modules" / "pkg" / "index.js").exists()


def test_inventory_respects_scope_filters_and_hashes(tmp_path: Path) -> None:
    repo, audit_dir = run_inventory_fixture(tmp_path)
    file_index = json.loads((audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8"))
    paths = {record["path"]: record for record in file_index["records"]}

    assert ".git/config" not in paths
    assert "node_modules/pkg/index.js" not in paths
    assert "audit/RUN_CONFIG.json" not in paths
    assert paths["src/app.py"]["kind"] == "code"
    assert paths["tests/test_app.py"]["kind"] == "test"
    assert paths["README.md"]["kind"] == "docs"
    assert paths["pyproject.toml"]["kind"] == "config"
    assert paths["generated/client.generated.py"]["kind"] == "generated"
    assert paths["vendor/lib.py"]["kind"] == "vendored"
    assert paths["assets/logo.bin"]["binary"] is True
    assert paths["assets/logo.bin"]["kind"] == "binary"
    assert paths["data/sample.csv"]["kind"] == "data"
    for path, record in paths.items():
        assert record["path_normalized"] == path
        assert record["size_bytes"] == (repo / path).stat().st_size
        assert record["sha256"] == sha256_file(repo / path)


def test_inventory_markdown_derives_counts_and_root_docs(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    file_index = json.loads((audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8"))
    inventory = (audit_dir / ARTIFACT_PATHS["INVENTORY"]).read_text(encoding="utf-8")
    counts = Counter(record["kind"] for record in file_index["records"])

    for kind, count in counts.items():
        assert f"| {kind} | {count} |" in inventory
    assert "| README | found | README.md |" in inventory
    assert "| LICENSE | found | LICENSE |" in inventory
    assert "| SECURITY | missing |  |" in inventory
    assert "| .git/config | excluded by .git/** |" in inventory
    assert "| node_modules/pkg/index.js | excluded by node_modules/** |" in inventory
    assert "- Binary file count: 1" in inventory


def test_evidence_index_has_reachable_root_docs_and_file_records(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    file_index = json.loads((audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8"))
    evidence = json.loads((audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).read_text(encoding="utf-8"))
    evidence_paths = {item["path"] for item in evidence["evidence"]}

    assert {record["path"] for record in file_index["records"]} <= evidence_paths
    for doc in file_index["root_documents"]:
        if doc["status"] == "found":
            assert doc["path"] in evidence_paths
    assert validate_audit(audit_dir).ok


def test_inventory_validation_rejects_invalid_kind(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    file_index_path = audit_dir / ARTIFACT_PATHS["FILE_INDEX"]
    payload = json.loads(file_index_path.read_text(encoding="utf-8"))
    payload["records"][0]["kind"] = "not-a-kind"
    file_index_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_inventory_artifacts(audit_dir)

    assert not validation.ok
    assert any("invalid file kind" in error for error in validation.errors)


def test_inventory_validation_rejects_hash_mismatch_and_orphan(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    file_index_path = audit_dir / ARTIFACT_PATHS["FILE_INDEX"]
    payload = json.loads(file_index_path.read_text(encoding="utf-8"))
    payload["records"][0]["sha256"] = "0" * 64
    payload["records"].append(
        {
            "path": "missing.py",
            "path_normalized": "missing.py",
            "size_bytes": 1,
            "sha256": "0" * 64,
            "extension": ".py",
            "language": "py",
            "kind": "code",
            "binary": False,
        }
    )
    file_index_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_inventory_artifacts(audit_dir)

    assert not validation.ok
    assert any("sha256 mismatch" in error for error in validation.errors)
    assert any("indexed file missing" in error for error in validation.errors)


def test_inventory_excludes_absolute_nested_output_dir(tmp_path: Path) -> None:
    repo = prepare_fixture(tmp_path)
    output_dir = repo / "reports" / "audit"
    config = write_config(repo, output_dir=str(output_dir))

    result = run_cli("inventory", "--config", str(config), cwd=repo)

    assert result.returncode == 0, result.stderr
    file_index = json.loads((output_dir / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8"))
    paths = {record["path"] for record in file_index["records"]}
    assert not any(path.startswith("reports/audit/") for path in paths)
    skipped = {item["path"]: item["reason"] for item in file_index["skipped_paths"]}
    assert skipped["reports/audit/RUN_CONFIG.json"] == "excluded by reports/audit/**"


def test_inventory_dry_run_reports_evidence_index_and_provenance(tmp_path: Path) -> None:
    repo = prepare_fixture(tmp_path)
    config = write_config(repo)

    result = run_cli("inventory", "--config", str(config), "--dry-run", cwd=repo)

    assert result.returncode == 0, result.stderr
    planned = json.loads(result.stdout)["planned_artifacts"]
    assert ARTIFACT_PATHS["EVIDENCE_INDEX"] in planned
    assert ARTIFACT_PATHS["PROVENANCE"] in planned
    assert ARTIFACT_PATHS["MANIFESTS"] in planned
    assert ARTIFACT_PATHS["BUILD_TEST_MAP"] in planned
    assert ARTIFACT_PATHS["CI_MAP"] in planned
