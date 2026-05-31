from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import agentic_deep_audit.audit_validate as audit_validate_module
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


def copy_fixture(tmp_path: Path, name: str = "performance_quality_project") -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_full_audit(tmp_path: Path) -> Path:
    repo = copy_fixture(tmp_path)
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo / "audit"


def test_missing_audit_dir() -> None:
    result = run_cli("validate", "--audit-dir", "missing-audit", cwd=PLUGIN_ROOT)

    assert result.returncode != 0
    assert "missing audit dir" in result.stderr


def test_validate_audit_isolates_phase_validator_exceptions(tmp_path: Path, monkeypatch) -> None:
    # OQ-M11: a phase validator raising on a malformed artifact must be reported as a blocker,
    # not abort the whole validation run. Previously only the extension/review-packet validators
    # were exception-guarded; the 11 phase validators ran bare, so one KeyError aborted everything.
    audit_dir = build_full_audit(tmp_path)

    def boom(*args: object, **kwargs: object):
        raise KeyError("simulated malformed artifact")

    monkeypatch.setattr(audit_validate_module, "validate_graph_artifacts", boom)
    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("validation_exception" in error and "KeyError" in error for error in result.errors)


def test_validate_cli_writes_zero_blocker_report(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    result = run_cli("validate", "--audit-dir", str(audit_dir), cwd=audit_dir.parent)
    report = (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).read_text(encoding="utf-8")

    assert result.returncode == 0, result.stderr
    assert "Blocker count: `0`" in report
    assert "## Commands Run" in report


def test_validation_result_has_warnings_channel() -> None:
    from agentic_deep_audit.audit_validate_common import ValidationResult

    result = ValidationResult(ok=True, errors=[])
    assert isinstance(result.warnings, list)
    assert result.warnings == []
    result.warnings.append("example warning")
    assert result.warnings == ["example warning"]


def _write_run_config(audit_dir: Path, **overrides: object) -> None:
    """Write a minimal valid RUN_CONFIG.json (no schema_version/launch_surface unless overridden)."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    payload: dict = {
        "repo": {"kind": "local", "path": ".", "github": None},
        "profile": "standard",
        "mode": "source-audit",
        "output_dir": "audit",
        "target_context": "MIT downstream",
        "binary_triage_consent": False,
        "run_id": "run-test",
    }
    payload.update(overrides)
    (audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_legacy_run_config_passes_with_legacy_warning(tmp_path: Path) -> None:
    # A legacy RUN_CONFIG (no schema_version, no launch_surface) is a WARNING, not a blocker,
    # and the warning is rendered into VALIDATION_REPORT.md.
    from agentic_deep_audit.audit_validate import validate_run_config_launch_surface
    from agentic_deep_audit.audit_validate_common import ValidationResult
    from agentic_deep_audit.validation_report import write_validation_report

    audit_dir = tmp_path / "audit"
    _write_run_config(audit_dir)
    errors: list[str] = []
    warnings: list[str] = []
    validate_run_config_launch_surface(audit_dir, errors, warnings)

    assert errors == []  # legacy is a warning, not a blocker
    assert any("[LEGACY]" in warning for warning in warnings)

    write_validation_report(audit_dir, ValidationResult(ok=True, errors=[], warnings=warnings), "validate")
    report = (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).read_text(encoding="utf-8")
    assert "[LEGACY] RUN_CONFIG.json predates launch_surface schema (run timestamp " in report
    assert "validation proceeded with best-effort adapter inference:" in report


def test_run_config_schema_1_1_missing_launch_surface_fails(tmp_path: Path) -> None:
    # Routed through validate_audit so the helper's wiring into the validator is exercised.
    audit_dir = tmp_path / "audit"
    _write_run_config(audit_dir, schema_version="1.1")  # 1.1 but no launch_surface

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("launch_surface" in error for error in result.errors)


def test_run_config_malformed_schema_version_fails(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    _write_run_config(audit_dir, schema_version="v1.1")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("RUN_CONFIG.json schema_version malformed" in error for error in result.errors)


CLI_ADAPTER_DOC = PLUGIN_ROOT / "docs" / "adapters" / "cli.md"
CLI_DOC_NINE_FIELDS = (
    "adapter id",
    "user entry command",
    "required files",
    "optional files",
    "output directory",
    "security model",
    "expected skipped/deferred behavior",
    "validation command",
    "ownership of docs/tests",
)


def test_cli_adapter_doc_has_9_fields() -> None:
    text = CLI_ADAPTER_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    missing = [field for field in CLI_DOC_NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"docs/adapters/cli.md must declare the nine fields as ## headings; missing: {missing}"


def test_readme_has_no_private_path_leak() -> None:
    import re as _re

    readme = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
    assert "plugins/agentic-deep-audit" not in readme
    assert "piano_doc" not in readme
    assert not _re.search(r"PYTHONPATH=\S*(?:plugins|piano_doc|nuove_skill)", readme)


def test_validate_cli_writes_report_for_malformed_json(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    (audit_dir / ARTIFACT_PATHS["GRAPH"]).write_text("{not-json", encoding="utf-8")

    result = run_cli("validate", "--audit-dir", str(audit_dir), cwd=audit_dir.parent)
    report = (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).read_text(encoding="utf-8")

    assert result.returncode != 0
    assert "json_parse:" in report or "invalid graph JSON artifact" in report
    assert "## Blockers" in report


def test_graph_schema_blocker_is_reported(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph.pop("nodes")
    write_json(graph_path, graph)

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("graph_schema:" in error for error in result.errors)


def test_anti_overclaim_language_blocks_unscoped_final_claim(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    (audit_dir / ARTIFACT_PATHS["REPORT"]).write_text("# Report\n\nThis audit is 100% complete and guaranteed secure.\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("anti_overclaim" in error for error in result.errors)

    # TQ-007: negative case — a properly scoped claim must NOT trip the anti-overclaim guard, so
    # the rule is not simply flagging every "100%".
    (audit_dir / ARTIFACT_PATHS["REPORT"]).write_text("# Report\n\nWithin the analyzed scope, coverage is 100% complete.\n", encoding="utf-8")
    scoped_result = validate_audit(audit_dir)
    assert not any("anti_overclaim" in error for error in scoped_result.errors)
