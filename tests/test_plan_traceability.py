from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / "tests" / "check_plan_traceability.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_plan_traceability", CHECKER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_plan_traceability"] = module
    spec.loader.exec_module(module)
    return module


def write_sequence(path: Path, refs: str = "`../017_traceability_matrix.md` Requirement") -> None:
    path.write_text(
        "# 001 - Sequence\n\n"
        "Status: test.\n\n"
        "Sources: test.\n\n"
        "Inputs: test.\n\n"
        "Outputs: test.\n\n"
        "Validation: test.\n\n"
        "## Atomic Steps\n\n"
        "- [ ] Step 001.1 - Do one thing.\n"
        "  - Target: test.\n"
        f"  - Refs: {refs}.\n"
        "  - Verify: test.\n\n"
        "## Acceptance\n\n"
        "- Test.\n",
        encoding="utf-8",
    )


def write_minimal_general_plan(repo_root: Path, plan_dir: Path) -> None:
    general_dir = repo_root / "piano_doc"
    general_dir.mkdir(parents=True)
    plan_dir.mkdir(parents=True)
    (general_dir / "017_traceability_matrix.md").write_text(
        "# Traceability Matrix\n\n"
        "| Requirement | Source | Plan Files | Implementation Revision | Validation | Gate |\n"
        "|---|---|---|---|---|---|\n"
        "| Requirement A | User | `001` | impl | validate | gate |\n\n"
        "## Goal Questions Coverage\n\n"
        "| Goal Question | Primary Artifacts | Schema/Format | Validation | Skipped/Open Question Behavior |\n"
        "|---|---|---|---|---|\n"
        "| Question A? | `REPORT.md` | Markdown | validate | unknown |\n",
        encoding="utf-8",
    )
    (general_dir / "018_output_matrix.md").write_text(
        "# Output Matrix\n\n"
        "| Artifact | Created By | Updated/Validated By | Role | Schema/Format | Validation |\n"
        "|---|---|---|---|---|---|\n"
        "| `REPORT.md` | phase 9 | review | report | Markdown | validate |\n",
        encoding="utf-8",
    )
    (general_dir / "010_metriche_validazione.md").write_text(
        "# Metriche\n\nFixture autoritative:\n\n- `fixture_a`: fixture.\n\n## Acceptance\n",
        encoding="utf-8",
    )
    write_sequence(plan_dir / "001_seq_minimal.md", refs="`../017_traceability_matrix.md` Requirement A")
    write_sequence(plan_dir / "030_seq_validate.md", refs="`../017_traceability_matrix.md` Requirement A")
    (plan_dir / "028_seq_fixtures_test_suite_ci.md").write_text(
        "# 028 - Fixtures\n\n"
        "Status: test.\n\nSources: test.\n\nInputs: test.\n\nOutputs: fixture_a.\n\nValidation: test.\n\n"
        "## Atomic Steps\n\n"
        "- [ ] Step 028.1 - Fixture.\n"
        "  - Target: fixture_a.\n"
        "  - Refs: `../010_metriche_validazione.md` fixture_a.\n"
        "  - Verify: fixture_a.\n\n"
        "## Acceptance\n\n- fixture_a.\n",
        encoding="utf-8",
    )
    (plan_dir / "900_traceability_to_general_plan.md").write_text(
        "# 900\n\n"
        "## Exact Requirement Coverage From `017`\n\n"
        "| # | Requirement label | Producer | Validator |\n"
        "|---|---|---|---|\n"
        "| R1 | Requirement A | `001` | `030` |\n\n"
        "## Exact Goal Question Coverage From `017`\n\n"
        "| # | Goal question | Coverage |\n"
        "|---|---|---|\n"
        "| G1 | Question A? | `001` |\n\n"
        "## Exact Artifact Coverage From `018`\n\n"
        "| # | Artifact label | Producer | Validator |\n"
        "|---|---|---|---|\n"
        "| A1 | `REPORT.md` | `001` | `030` |\n\n"
        "## Exact Fixture Coverage From `010`\n\n"
        "| Fixture | Coverage |\n"
        "|---|---|\n"
        "| fixture_a | `028` |\n",
        encoding="utf-8",
    )
    (plan_dir / "901_internal_review_packet.md").write_text(
        "# 901\n\nScope: Implementation Plan Only.\n\nExclude: runtime plugin code and creating `plugins/`.\n",
        encoding="utf-8",
    )


def test_plan_traceability_checker_passes_minimal_plan(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    plan_dir = repo_root / "piano_doc" / "implementazione"
    write_minimal_general_plan(repo_root, plan_dir)
    output = tmp_path / "PLAN_TRACEABILITY_REPORT.md"
    result = subprocess.run(
        [
            sys.executable,
            str(CHECKER_PATH),
            "--repo-root",
            str(repo_root),
            "--plan-dir",
            str(plan_dir),
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    report = output.read_text(encoding="utf-8")
    assert result.returncode == 0, report + result.stderr
    assert "Status: `pass`" in report
    assert "Review packet readiness: `ready`" in report
    assert "Requirement rows: `1`" in report
    assert "Artifact rows: `1`" in report
    assert "Authoritative fixtures: `1`" in report


def test_reference_checker_fails_invalid_parent_directory_ref(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "piano_doc" / "implementazione"
    plan_dir.mkdir(parents=True)
    write_sequence(plan_dir / "001_seq_bad.md", refs="`../missing.md` missing")

    violations = checker.lint_reference_paths(plan_dir, tmp_path)

    assert violations
    assert "unresolved local reference ../missing.md" in violations[0].message


def test_reference_checker_accepts_same_folder_sequence_ref(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "piano_doc" / "implementazione"
    plan_dir.mkdir(parents=True)
    write_sequence(plan_dir / "001_seq_peer.md", refs="`002_seq_peer.md` peer")
    write_sequence(plan_dir / "002_seq_peer.md", refs="`001_seq_peer.md` peer")

    violations = checker.lint_reference_paths(plan_dir, tmp_path)

    assert violations == []


def test_matrix_coverage_fails_missing_artifact_row(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "piano_doc" / "implementazione"
    write_minimal_general_plan(tmp_path, plan_dir)
    (tmp_path / "piano_doc" / "018_output_matrix.md").write_text(
        "# Output Matrix\n\n"
        "| Artifact | Created By | Updated/Validated By | Role | Schema/Format | Validation |\n"
        "|---|---|---|---|---|---|\n"
        "| `MISSING.json` | phase 1 | phase 9 | data | JSON | validate |\n",
        encoding="utf-8",
    )

    violations, _stats = checker.lint_matrix_coverage(tmp_path, plan_dir)

    assert any(v.category == "artifacts" and v.item == "`MISSING.json`" for v in violations)


def test_matrix_coverage_fails_missing_requirement_row(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "piano_doc" / "implementazione"
    write_minimal_general_plan(tmp_path, plan_dir)
    text = (plan_dir / "900_traceability_to_general_plan.md").read_text(encoding="utf-8")
    text = text.replace("| R1 | Requirement A | `001` | `030` |\n", "")
    (plan_dir / "900_traceability_to_general_plan.md").write_text(text, encoding="utf-8")

    violations, _stats = checker.lint_matrix_coverage(tmp_path, plan_dir)

    assert any(v.category == "requirements" and v.item == "Requirement A" for v in violations)


def test_matrix_coverage_fails_missing_validator_cell(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "piano_doc" / "implementazione"
    write_minimal_general_plan(tmp_path, plan_dir)
    text = (plan_dir / "900_traceability_to_general_plan.md").read_text(encoding="utf-8")
    text = text.replace("| A1 | `REPORT.md` | `001` | `030` |", "| A1 | `REPORT.md` | `001` |  |")
    (plan_dir / "900_traceability_to_general_plan.md").write_text(text, encoding="utf-8")

    violations, _stats = checker.lint_matrix_coverage(tmp_path, plan_dir)

    assert any(
        v.category == "artifacts" and v.item == "`REPORT.md`" and "missing validator sequence ids" in v.message
        for v in violations
    )


def test_fixture_coverage_fails_removed_authoritative_fixture(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "piano_doc" / "implementazione"
    write_minimal_general_plan(tmp_path, plan_dir)
    (plan_dir / "028_seq_fixtures_test_suite_ci.md").write_text(
        "# 028\n\nStatus: test.\n\nSources: test.\n\nInputs: test.\n\nOutputs: test.\n\nValidation: test.\n\n"
        "## Atomic Steps\n\n"
        "- [ ] Step 028.1 - Fixture.\n"
        "  - Target: other.\n"
        "  - Refs: `../010_metriche_validazione.md`.\n"
        "  - Verify: other.\n\n"
        "## Acceptance\n\n- Test.\n",
        encoding="utf-8",
    )

    violations, _stats = checker.lint_matrix_coverage(tmp_path, plan_dir)

    assert any(v.category == "fixtures" and v.item == "fixture_a" for v in violations)


def test_required_sections_linter_fails_missing_acceptance(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    write_sequence(plan_dir / "001_seq_missing.md")
    text = (plan_dir / "001_seq_missing.md").read_text(encoding="utf-8").replace("## Acceptance", "## Done")
    (plan_dir / "001_seq_missing.md").write_text(text, encoding="utf-8")

    violations = checker.lint_required_sections(plan_dir)

    assert any(v.message == "missing ## Acceptance" for v in violations)


def test_forbidden_marker_linter_fails_marker_fixture(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    write_sequence(plan_dir / "001_seq_marker.md")
    marker = "TO" + "DO"
    text = (plan_dir / "001_seq_marker.md").read_text(encoding="utf-8") + f"\n{marker}: bad\n"
    (plan_dir / "001_seq_marker.md").write_text(text, encoding="utf-8")

    violations = checker.lint_forbidden_markers(plan_dir)

    assert any(v.category == "forbidden_markers" for v in violations)


def test_review_packet_scope_blocks_non_plan_scope(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    (plan_dir / "901_internal_review_packet.md").write_text("# Review\n\nRuntime code review.\n", encoding="utf-8")

    violations = checker.lint_review_packet(plan_dir)

    assert len(violations) == 3


def test_review_packet_scope_rejects_contradictory_plugin_code_inclusion(tmp_path: Path) -> None:
    checker = load_checker()
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    (plan_dir / "901_internal_review_packet.md").write_text(
        "# Review\n\n"
        "Scope: Implementation Plan Only.\n"
        "- Include: runtime plugin code and creating `plugins/`.\n"
        "- Exclude: writing runtime plugin code, creating `plugins/`.\n",
        encoding="utf-8",
    )

    violations = checker.lint_review_packet(plan_dir)

    assert any("contradictory plugin-code inclusion" in v.message for v in violations)
