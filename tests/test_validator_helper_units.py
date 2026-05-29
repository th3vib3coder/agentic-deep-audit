from __future__ import annotations

from pathlib import Path

from agentic_deep_audit.audit_validate_common import load_json
from agentic_deep_audit.limits import is_safe_repo_relative_path, resolve_repo_existing_file, resolve_repo_file
from agentic_deep_audit.models import ARTIFACT_PATHS
from agentic_deep_audit.validate_claim_language import validate_anti_overclaim_language
from agentic_deep_audit import validate_extensions


def test_resolve_repo_file_rejects_traversal_and_platform_absolute_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    safe = repo / "src" / "app.py"
    safe.parent.mkdir()
    safe.write_text("print('ok')\n", encoding="utf-8")

    assert resolve_repo_file(repo, "src/app.py") == safe.resolve()
    for path_value in ["../outside.txt", "/etc/passwd", "C:/Windows/win.ini", "src\\app.py", "safe:stream", ""]:
        assert not is_safe_repo_relative_path(path_value)
        assert resolve_repo_file(repo, path_value) is None


def test_resolve_repo_existing_file_requires_real_contained_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    existing = repo / "docs" / "decision.md"
    existing.parent.mkdir()
    existing.write_text("# Decision\n", encoding="utf-8")
    directory = repo / "docs" / "nested"
    directory.mkdir()

    assert resolve_repo_existing_file(repo, "docs/decision.md") == existing.resolve()
    assert resolve_repo_existing_file(repo, "docs/nested") is None
    assert resolve_repo_existing_file(repo, "../outside.md") is None


def test_path_safety_callers_do_not_reintroduce_local_resolvers() -> None:
    src_root = Path(__file__).resolve().parents[1] / "src" / "agentic_deep_audit"
    forbidden = {
        "audit_validate_evidence.py": ["def is_safe_relative_evidence_path"],
        "audit_wiki.py": ["def resolve_repo_relative_file", "PureWindowsPath", "PurePosixPath"],
        "audit_synthesis.py": ["def resolve_repo_relative_file", "PureWindowsPath", "PurePosixPath"],
    }

    for filename, tokens in forbidden.items():
        text = (src_root / filename).read_text(encoding="utf-8")
        for token in tokens:
            assert token not in text


def test_load_json_reports_non_object_and_corrupt_artifacts(tmp_path: Path) -> None:
    errors: list[str] = []
    array_path = tmp_path / "array.json"
    array_path.write_text("[]\n", encoding="utf-8")

    assert load_json(array_path, errors) is None
    assert any("artifact root must be object" in error for error in errors)

    errors.clear()
    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{not-json", encoding="utf-8")

    assert load_json(corrupt_path, errors) is None
    assert any("invalid JSON artifact" in error for error in errors)


def test_anti_overclaim_flags_unscoped_absolute_claims(tmp_path: Path) -> None:
    report_path = tmp_path / ARTIFACT_PATHS["REPORT"]
    report_path.write_text(
        "The audit is 100% secure.\n"
        "Within the analyzed scope, coverage is 100% complete.\n",
        encoding="utf-8",
    )

    errors = validate_anti_overclaim_language(tmp_path)

    assert len(errors) == 1
    assert "REPORT.md:1" in errors[0]


def test_validate_extensions_dispatches_only_present_artifact_groups(monkeypatch, tmp_path: Path) -> None:
    called: list[str] = []

    def marker(name: str):
        def _validator(*_args, **_kwargs):
            called.append(name)
            return [f"{name}:error"]

        return _validator

    monkeypatch.setattr(validate_extensions, "validate_scientific_provenance_artifacts", marker("scientific"))
    monkeypatch.setattr(validate_extensions, "validate_project_telemetry_artifacts", marker("telemetry"))
    monkeypatch.setattr(validate_extensions, "validate_risk_artifacts", marker("risk"))
    monkeypatch.setattr(validate_extensions, "validate_license_binary_artifacts", marker("license"))
    monkeypatch.setattr(validate_extensions, "validate_performance_quality_artifacts", marker("quality"))
    monkeypatch.setattr(validate_extensions, "validate_reuse_artifacts", marker("reuse"))
    monkeypatch.setattr(validate_extensions, "validate_wiki_artifacts", marker("wiki"))
    monkeypatch.setattr(validate_extensions, "validate_canonical_graph_artifacts", marker("graph"))
    monkeypatch.setattr(validate_extensions, "validate_corpus_artifacts", marker("corpus"))
    monkeypatch.setattr(validate_extensions, "validate_mcp_artifacts", marker("mcp"))
    monkeypatch.setattr(validate_extensions, "validate_report_artifacts", marker("report"))
    (tmp_path / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"]).write_text("{}\n", encoding="utf-8")

    errors = validate_extensions.validate_extension_artifacts(tmp_path, {"evidence": []})

    assert set(called) == {"scientific", "mcp"}
    assert errors == ["scientific:error", "mcp:error"]
