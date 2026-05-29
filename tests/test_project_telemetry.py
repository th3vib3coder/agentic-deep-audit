from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import agentic_deep_audit.audit_telemetry as audit_telemetry
from agentic_deep_audit.audit_telemetry import CATEGORIES, default_parameters, is_bot_author, issue_pr_record, normalize_identity, pseudonymize_identity
from agentic_deep_audit.limits import FileSizeLimitError
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.validate_telemetry import validate_project_telemetry_artifacts
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


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


def write_config(repo: Path, output: str = "audit") -> Path:
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
                f'output_dir: "{output}"',
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


def git_available() -> bool:
    return shutil.which("git") is not None


def run_git(repo: Path, *args: str, name: str = "Dev", email: str = "dev@example.com", date: str | None = None) -> None:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = name
    env["GIT_AUTHOR_EMAIL"] = email
    env["GIT_COMMITTER_NAME"] = name
    env["GIT_COMMITTER_EMAIL"] = email
    if date:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, text=True, capture_output=True)


def prepare_telemetry_repo(tmp_path: Path) -> Path:
    if not git_available():
        pytest.skip("git unavailable")
    repo = tmp_path / "telemetry-repo"
    repo.mkdir()
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "dev@example.com")
    run_git(repo, "config", "user.name", "Dev")
    (repo / "legacy.txt").write_text("outside telemetry window\n", encoding="utf-8")
    run_git(repo, "add", "legacy.txt")
    run_git(repo, "commit", "-m", "chore: legacy history", date="2020-01-01T00:00:00+0000")
    (repo / "README.md").write_text("# Telemetry Repo\n\nSee API docs in docs/api.md.\n", encoding="utf-8")
    docs = repo / "docs"
    docs.mkdir()
    (docs / "api.md").write_text("# API Docs\n", encoding="utf-8")
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("def main():\n    return 'ok'\n", encoding="utf-8")
    (repo / "CHANGELOG.md").write_text("## v1.0.0 - 2024-01-01 security breaking deprecated\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text('[project]\nname = "telemetry-fixture"\ndependencies = ["requests==2.31.0"]\n', encoding="utf-8")
    (repo / ".mailmap").write_text("Dev <dev@example.com> Alias <ALIAS@EXAMPLE.COM>\n", encoding="utf-8")
    write_config(repo)
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "feat: initial #1", name="Dev", email="dev@example.com")
    (repo / "README.md").write_text("# Telemetry Repo\n\nUpdated API docs in docs/api.md.\n", encoding="utf-8")
    (src / "app.py").write_text("def main():\n    return 'updated'\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text('[project]\nname = "telemetry-fixture"\ndependencies = ["requests==2.32.0"]\n', encoding="utf-8")
    run_git(repo, "add", "README.md", "src/app.py", "pyproject.toml")
    run_git(repo, "commit", "-m", "fix: update docs", name="Alias", email="ALIAS@EXAMPLE.COM")
    (repo / "bot.txt").write_text("bot change\n", encoding="utf-8")
    run_git(repo, "add", "bot.txt")
    run_git(repo, "commit", "-m", "chore: bot update", name="dependabot[bot]", email="123+dependabot[bot]@users.noreply.github.com")
    run_git(repo, "tag", "v1.0.0")
    return repo


def telemetry_by_category(audit_dir: Path) -> dict[str, dict]:
    payload = json.loads((audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY"]).read_text(encoding="utf-8"))
    return {record["category"]: record for record in payload["records"]}


def test_telemetry_no_git_records_skipped_parameters_and_limitations(tmp_path: Path) -> None:
    repo = tmp_path / "no-git"
    shutil.copytree(FIXTURES / "no_git_repo", repo)
    config = write_config(repo)

    result = run_cli("telemetry", "--config", str(config), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    records = telemetry_by_category(audit_dir)
    assert set(records) == set(CATEGORIES)
    for record in records.values():
        assert set(record["parameters"]) >= {"time_window_days", "from_ref", "to_ref", "bot_filter", "identity_normalization"}
    for category in ["release_cadence", "contributors_graph", "bus_factor_proxy", "ownership_concentration", "commit_message_quality_signal"]:
        assert records[category]["status"] == "skipped"
        assert records[category]["limitations"] == ["no git history available"]
    assert records["issue_pr_signals"]["status"] == "skipped"
    assert validate_audit(audit_dir).ok


def test_bot_filter_and_identity_normalization_are_deterministic() -> None:
    assert is_bot_author("dependabot[bot]", "123+dependabot[bot]@users.noreply.github.com")
    assert is_bot_author("Build", "bot@example.com")
    assert normalize_identity("Alias", "ALIAS@EXAMPLE.COM", {"alias@example.com": "dev@example.com"}) == "dev@example.com"
    assert normalize_identity("No Email", "", {}) == "no email"
    assert pseudonymize_identity("dev@example.com").startswith("id_")


def test_mailmap_size_limit_degrades_to_empty_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".mailmap").write_text("Dev <dev@example.com> Alias <alias@example.com>\n", encoding="utf-8")

    def raise_size_limit(*_args, **_kwargs):
        raise FileSizeLimitError("test cap")

    monkeypatch.setattr(audit_telemetry, "read_text_auto_capped", raise_size_limit)

    assert audit_telemetry.load_mailmap(repo) == {}


def test_git_telemetry_changelog_identity_and_manifest_caveats(tmp_path: Path) -> None:
    repo = prepare_telemetry_repo(tmp_path)

    result = run_cli("telemetry", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    records = telemetry_by_category(audit_dir)
    changelog = records["changelog_parsing"]
    assert changelog["status"] == "observed"
    assert {"security", "breaking", "deprecated"} <= set(changelog["value"]["entries"][0]["type"])
    cadence = records["release_cadence"]
    assert cadence["value"]["commit_count"] == 3
    assert cadence["parameters"]["time_window_start"] < cadence["parameters"]["time_window_end"]
    contributors = records["contributors_graph"]["value"]["contributors"]
    assert contributors[0]["identity"] == pseudonymize_identity("dev@example.com")
    assert "dev@example.com" not in json.dumps(records["contributors_graph"])
    assert contributors[0]["commit_count"] == 2
    assert contributors[0]["code_touch_count"] == 2
    assert records["bus_factor_proxy"]["value"]["min_contributors_50pct"] == 1
    assert records["bus_factor_proxy"]["value"]["basis"] == "code_touch_count"
    assert records["ownership_concentration"]["value"]["top_1"] == 1.0
    assert records["commit_message_quality_signal"]["value"]["conventional"] == 2
    dependency = records["dependency_upgrade_churn"]
    assert dependency["status"] == "observed"
    assert dependency["value"]["current_manifest_only"] is False
    assert dependency["value"]["manifest_history"]["changed_dependency_lines"] > 0
    assert records["api_doc_extraction"]["status"] == "observed"
    assert records["issue_pr_signals"]["status"] == "skipped"
    assert validate_audit(audit_dir).ok


def test_issue_pr_signals_observed_when_policy_and_target_allow(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"]).write_text(
        json.dumps({"schema_version": "1.0", "default": "deny", "allowed_domains": ["api.github.com"], "denied_domains": [], "send_source_code": False}),
        encoding="utf-8",
    )

    record = issue_pr_record(
        1,
        audit_dir,
        default_parameters(as_of="2026-05-23T00:00:00+00:00"),
        {"github": {"target": "owner/repo"}},
        fetcher=lambda target: {"target": target, "sampled_issue_count": 2, "sampled_pr_count": 1, "sampled_release_count": 1},
    )

    assert record["status"] == "observed"
    assert record["source"] == "github_api"
    assert record["value"]["target"] == "owner/repo"


def test_issue_pr_signals_rejects_traversal_target(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"]).write_text(
        json.dumps({"schema_version": "1.0", "default": "deny", "allowed_domains": ["api.github.com"], "denied_domains": [], "send_source_code": False}),
        encoding="utf-8",
    )

    record = issue_pr_record(
        1,
        audit_dir,
        default_parameters(as_of="2026-05-23T00:00:00+00:00"),
        {"github": {"target": "../../evil.com/path"}},
        fetcher=lambda target: {"target": target},
    )

    assert record["status"] == "skipped"
    assert record["limitations"] == ["GitHub target invalid"]


def test_project_telemetry_report_sections_must_match_json(tmp_path: Path) -> None:
    repo = tmp_path / "no-git"
    shutil.copytree(FIXTURES / "no_git_repo", repo)
    config = write_config(repo)
    result = run_cli("telemetry", "--config", str(config), cwd=repo)
    assert result.returncode == 0, result.stderr
    report_path = repo / "audit" / ARTIFACT_PATHS["PROJECT_TELEMETRY_MD"]
    report_path.write_text("# Project Telemetry\n\n## release_cadence\n\n- Status: skipped\n", encoding="utf-8")

    validation = validate_audit(repo / "audit")

    assert not validation.ok
    assert any("section categories do not match" in error for error in validation.errors)


def test_project_telemetry_json_requires_all_expected_categories(tmp_path: Path) -> None:
    repo = tmp_path / "no-git"
    shutil.copytree(FIXTURES / "no_git_repo", repo)
    config = write_config(repo)
    result = run_cli("telemetry", "--config", str(config), cwd=repo)
    assert result.returncode == 0, result.stderr
    telemetry_path = repo / "audit" / ARTIFACT_PATHS["PROJECT_TELEMETRY"]
    payload = json.loads(telemetry_path.read_text(encoding="utf-8"))
    payload["records"] = [record for record in payload["records"] if record["category"] != "release_cadence"]
    telemetry_path.write_text(json.dumps(payload), encoding="utf-8")
    report_path = repo / "audit" / ARTIFACT_PATHS["PROJECT_TELEMETRY_MD"]
    report_path.write_text(
        "\n".join(["# Project Telemetry", "", *[f"## {record['category']}\n" for record in payload["records"]]]),
        encoding="utf-8",
    )

    validation = validate_audit(repo / "audit")

    assert not validation.ok
    assert any("exactly one record per expected category" in error for error in validation.errors)


def test_project_telemetry_validator_requires_evidence_ids_array(tmp_path: Path) -> None:
    repo = tmp_path / "no-git"
    shutil.copytree(FIXTURES / "no_git_repo", repo)
    config = write_config(repo)
    result = run_cli("telemetry", "--config", str(config), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    telemetry_path = audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY"]
    payload = json.loads(telemetry_path.read_text(encoding="utf-8"))
    payload["records"][0]["evidence_ids"] = None
    telemetry_path.write_text(json.dumps(payload), encoding="utf-8")
    evidence_index = json.loads((audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).read_text(encoding="utf-8"))

    errors = validate_project_telemetry_artifacts(audit_dir, evidence_index)

    assert any("requires evidence_ids array" in error for error in errors)
