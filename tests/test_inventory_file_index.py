from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import agentic_deep_audit.audit_inventory as audit_inventory
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


def symlink_or_skip(target: Path, link: Path, *, target_is_directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


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
    skipped = {item["path"]: item["reason"] for item in file_index["skipped_paths"]}
    assert skipped[".git"] == "excluded by .git/**"
    assert skipped["node_modules"] == "excluded by node_modules/**"
    assert not any(path.startswith(".git/") for path in skipped)
    assert not any(path.startswith("node_modules/") for path in skipped)
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


def test_inventory_and_provenance_generated_at_honor_source_date_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1704067200")
    _, audit_dir = run_inventory_fixture(tmp_path)

    file_index = json.loads((audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8"))
    provenance = json.loads((audit_dir / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8"))

    assert file_index["generated_at"] == "2024-01-01T00:00:00+00:00"
    assert provenance["generated_at"] == "2024-01-01T00:00:00+00:00"


def test_root_doc_status_degrades_to_missing_on_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_oserror(_path: Path):
        raise OSError("[WinError 206] path too long")

    monkeypatch.setattr(Path, "iterdir", raise_oserror)

    docs = audit_inventory.root_doc_status(tmp_path)

    assert {item["status"] for item in docs} == {"missing"}
    assert all(item["path"] is None for item in docs)


def test_root_doc_status_is_stable_for_duplicate_root_doc_stems(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    readme_md = tmp_path / "README.md"
    readme_rst = tmp_path / "README.rst"
    readme_md.write_text("# md\n", encoding="utf-8")
    readme_rst.write_text("rst\n", encoding="utf-8")
    orders = [[readme_rst, readme_md], [readme_md, readme_rst]]
    results: list[str | None] = []

    def fake_iterdir(_path: Path):
        return iter(orders.pop(0))

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)

    for _ in range(2):
        docs = audit_inventory.root_doc_status(tmp_path)
        results.append(next(item["path"] for item in docs if item["name"] == "README"))

    assert results == ["README.md", "README.md"]


def test_inventory_skips_symlinks_before_hashing_targets(tmp_path: Path) -> None:
    repo = prepare_fixture(tmp_path)
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("outside secret that must not be indexed\n", encoding="utf-8")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "nested_secret.txt").write_text("nested secret\n", encoding="utf-8")
    symlink_or_skip(outside, repo / "linked_secret.txt")
    symlink_or_skip(outside_dir, repo / "linked_dir", target_is_directory=True)
    config = write_config(repo)

    result = run_cli("inventory", "--config", str(config), cwd=repo)

    assert result.returncode == 0, result.stderr
    file_index = json.loads((repo / "audit" / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8"))
    paths = {record["path"] for record in file_index["records"]}
    skipped = {item["path"]: item["reason"] for item in file_index["skipped_paths"]}
    assert "linked_secret.txt" not in paths
    assert not any(path.startswith("linked_dir/") for path in paths)
    assert skipped.get("linked_secret.txt") == "symlink skipped"
    if "linked_dir" in skipped:
        assert skipped["linked_dir"] == "symlink skipped"
    assert sha256_file(outside) not in {record["sha256"] for record in file_index["records"]}


def test_scan_files_prunes_symlink_directory_children_without_os_symlink_privilege(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text("x = 1\n", encoding="utf-8")
    linked_dir = repo / "linked_dir"
    linked_dir.mkdir()
    (linked_dir / "nested_secret.py").write_text("SECRET = True\n", encoding="utf-8")
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(path: Path) -> bool:
        if path == linked_dir:
            return True
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    records, skipped, _ = audit_inventory.scan_files(
        {
            "repo": {"path": str(repo)},
            "scope_filters": {"include": ["**/*"], "exclude": []},
            "output_dir": "audit",
        }
    )

    assert {record["path"] for record in records} == {"safe.py"}
    assert "linked_dir/nested_secret.py" not in {record["path"] for record in records}
    assert {item["path"]: item["reason"] for item in skipped}["linked_dir"] == "symlink skipped"


def test_scan_files_skips_oversized_files_before_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "small.py").write_text("x=1\n", encoding="utf-8")
    (repo / "large.py").write_bytes(b"x" * 9)
    monkeypatch.setattr(audit_inventory, "MAX_AUDIT_FILE_BYTES", 8)

    records, skipped, _ = audit_inventory.scan_files(
        {
            "repo": {"path": str(repo)},
            "scope_filters": {"include": ["**/*"], "exclude": []},
            "output_dir": "audit",
        }
    )

    assert {record["path"] for record in records} == {"small.py"}
    skipped_reasons = {item["path"]: item["reason"] for item in skipped}
    assert "large.py" in skipped_reasons
    assert "exceeds size cap" in skipped_reasons["large.py"]


def test_scan_files_checks_size_cap_before_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    oversized = repo / "large.py"
    oversized.write_bytes(b"x" * 9)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path):
        if path == oversized:
            raise AssertionError("oversized file was read")
        return original_read_bytes(path)

    monkeypatch.setattr(audit_inventory, "MAX_AUDIT_FILE_BYTES", 8)
    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    records, skipped, _ = audit_inventory.scan_files(
        {
            "repo": {"path": str(repo)},
            "scope_filters": {"include": ["**/*"], "exclude": []},
            "output_dir": "audit",
        }
    )

    assert records == []
    assert skipped and skipped[0]["path"] == "large.py"
    assert "exceeds size cap" in skipped[0]["reason"]


def test_scan_files_records_read_errors_without_aborting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "good.py").write_text("x = 1\n", encoding="utf-8")
    bad = repo / "bad.py"
    bad.write_text("raise RuntimeError\n", encoding="utf-8")
    original_read = audit_inventory.read_bytes_capped

    def flaky_read(path: Path, *args: object, **kwargs: object) -> bytes:
        if path == bad:
            raise OSError("simulated read failure")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(audit_inventory, "read_bytes_capped", flaky_read)

    records, skipped, _ = audit_inventory.scan_files(
        {
            "repo": {"path": str(repo)},
            "scope_filters": {"include": ["**/*"], "exclude": []},
            "output_dir": "audit",
        }
    )

    assert {record["path"] for record in records} == {"good.py"}
    skipped_reasons = {item["path"]: item["reason"] for item in skipped}
    assert "simulated read failure" in skipped_reasons["bad.py"]


def test_inventory_repo_payload_redacts_secret_urls(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# Repo\n", encoding="utf-8")
    audit_dir = repo / "audit"
    audit_dir.mkdir()

    audit_inventory.run_inventory(
        {
            "run_id": "run-redact",
            "repo": {"kind": "local", "path": str(repo), "github": "https://ghp_ABCDEFGHIJKLMNOPQRST@github.com/example/private.git"},
            "scope_filters": {"include": ["**/*"], "exclude": []},
            "output_dir": str(audit_dir),
        },
        audit_dir,
    )

    text = (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).read_text(encoding="utf-8")
    payload = json.loads(text)
    assert "ghp_ABCDEFGHIJKLMNOPQRST" not in text
    assert payload["repo"]["github"] == "https://github.com/example/private.git"


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
    assert "| .git | excluded by .git/** |" in inventory
    assert "| node_modules | excluded by node_modules/** |" in inventory
    assert f"- Binary file count: {counts['binary']}" in inventory


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


def test_inventory_validation_rejects_path_traversal(tmp_path: Path) -> None:
    _, audit_dir = run_inventory_fixture(tmp_path)
    file_index_path = audit_dir / ARTIFACT_PATHS["FILE_INDEX"]
    payload = json.loads(file_index_path.read_text(encoding="utf-8"))
    payload["records"][0]["path"] = "../outside.txt"
    payload["records"][0]["path_normalized"] = "../outside.txt"
    file_index_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_inventory_artifacts(audit_dir)

    assert not validation.ok
    assert any("unsafe source path" in error for error in validation.errors)


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
    assert skipped["reports/audit"] == "excluded by reports/audit/**"
    assert not any(path.startswith("reports/audit/") for path in skipped)


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
