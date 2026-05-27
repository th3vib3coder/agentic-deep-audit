from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


STEP_RE = re.compile(r"^- \[.\] Step (?P<id>\d{3}\.\w+) - (?P<title>.+)$")
SEQUENCE_FILE_RE = re.compile(r"^(?P<number>\d{3})_.*\.md$")
MD_REF_RE = re.compile(r"`(?P<path>[^`]+?\.md(?:#[^`]*)?)`")

REQUIRED_STEP_FIELDS = ("Target:", "Refs:", "Verify:")
REQUIRED_SECTIONS = (
    "Status:",
    "Sources:",
    "Inputs:",
    "Outputs:",
    "Validation:",
    "## Atomic Steps",
    "## Acceptance",
)
FORBIDDEN_MARKERS = (
    "TB" + "D",
    "TO" + "DO",
    "implement " + "later",
    "similar " + "to",
    "as " + "appropriate",
    "place" + "holder",
    "st" + "ub",
)


@dataclass(frozen=True)
class Violation:
    category: str
    path: str
    item: str
    message: str


@dataclass(frozen=True)
class PlanStats:
    step_count: int
    requirement_rows: int
    artifact_rows: int
    fixture_rows: int
    goal_question_rows: int


def numbered_sequence_files(plan_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(plan_dir.glob("*.md")):
        match = SEQUENCE_FILE_RE.match(path.name)
        if match and 1 <= int(match.group("number")) <= 899:
            files.append(path)
    return files


def step_blocks(text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    current_id: str | None = None
    current: list[str] = []
    for line in text.splitlines():
        match = STEP_RE.match(line)
        if match:
            if current_id is not None:
                blocks.append((current_id, "\n".join(current)))
            current_id = match.group("id")
            current = [line]
            continue
        if current_id is not None:
            current.append(line)
    if current_id is not None:
        blocks.append((current_id, "\n".join(current)))
    return blocks


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _relative(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _clean_ref_token(token: str) -> str:
    without_anchor = token.split("#", 1)[0].strip()
    return without_anchor.split()[0]


def _looks_like_local_doc_ref(token: str) -> bool:
    token = token.replace("\\", "/")
    if not token.endswith(".md"):
        return False
    if "*" in token:
        return False
    if token.startswith(("http://", "https://")):
        return False
    if token.startswith((".", "/")) or "/" in token:
        return True
    return bool(SEQUENCE_FILE_RE.match(token))


def _sequence_ids_from_line(line: str) -> set[str]:
    return set(re.findall(r"`(?P<id>\d{3})`", line))


def _table_rows_after_heading(text: str, heading: str) -> list[list[str]]:
    rows: list[list[str]] = []
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == heading:
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if not in_section or not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or cells[0].startswith("---") or cells[0] in {"#", "Requirement label", "Goal question", "Artifact label", "Fixture"}:
            continue
        rows.append(cells)
    return rows


def _rows_by_label(text: str, heading: str, label_index: int) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for cells in _table_rows_after_heading(text, heading):
        if len(cells) > label_index:
            rows[cells[label_index]] = cells
    return rows


def _fixture_label(cell: str) -> str:
    match = re.match(r"`(?P<fixture>[^`]+)`", cell)
    return match.group("fixture") if match else cell


def _fixture_rows_by_label(text: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for cells in _table_rows_after_heading(text, "## Exact Fixture Coverage From `010`"):
        if cells:
            rows[_fixture_label(cells[0])] = cells
    return rows


def _validate_sequence_cell(
    violations: list[Violation],
    category: str,
    label: str,
    cells: list[str] | None,
    cell_index: int,
    role: str,
    existing_sequence_ids: set[str],
) -> None:
    if cells is None:
        violations.append(Violation(category, "900_traceability_to_general_plan.md", label, "missing from 900"))
        return
    if len(cells) <= cell_index:
        violations.append(Violation(category, "900_traceability_to_general_plan.md", label, f"missing {role} cell"))
        return
    ids = _sequence_ids_from_line(cells[cell_index])
    if not ids:
        violations.append(
            Violation(category, "900_traceability_to_general_plan.md", label, f"missing {role} sequence ids")
        )
        return
    missing = sorted(seq_id for seq_id in ids if seq_id not in existing_sequence_ids)
    if missing:
        violations.append(
            Violation(
                category,
                "900_traceability_to_general_plan.md",
                label,
                f"references missing sequence ids {', '.join(missing)}",
            )
        )


def parse_requirement_rows(traceability_matrix: Path) -> list[str]:
    rows: list[str] = []
    in_table = False
    for line in _read(traceability_matrix).splitlines():
        if line.startswith("| Requirement |"):
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or cells[0].startswith("---"):
            continue
        rows.append(cells[0])
    return rows


def parse_goal_question_rows(traceability_matrix: Path) -> list[str]:
    rows: list[str] = []
    in_table = False
    for line in _read(traceability_matrix).splitlines():
        if line.startswith("| Goal Question |"):
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or cells[0].startswith("---"):
            continue
        rows.append(cells[0])
    return rows


def parse_artifact_rows(output_matrix: Path) -> list[str]:
    rows: list[str] = []
    for line in _read(output_matrix).splitlines():
        if line.startswith("| `"):
            rows.append(line.split("|")[1].strip())
    return rows


def parse_fixture_rows(metrics_file: Path) -> list[str]:
    rows: list[str] = []
    in_fixture_list = False
    for line in _read(metrics_file).splitlines():
        stripped = line.strip()
        if stripped == "Fixture autoritative:":
            in_fixture_list = True
            continue
        if in_fixture_list and stripped.startswith("## "):
            break
        if not in_fixture_list:
            continue
        match = re.match(r"- `(?P<name>[^`]+)`", stripped)
        if match:
            rows.append(match.group("name"))
    return rows


def lint_step_fields(plan_dir: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in numbered_sequence_files(plan_dir):
        for step_id, block in step_blocks(_read(path)):
            for field in REQUIRED_STEP_FIELDS:
                if field not in block:
                    violations.append(
                        Violation("step_fields", _relative(path, plan_dir), step_id, f"missing {field}")
                    )
    return violations


def lint_reference_paths(plan_dir: Path, repo_root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in numbered_sequence_files(plan_dir):
        text = _read(path)
        for step_id, block in step_blocks(text):
            for line in block.splitlines():
                if "Refs:" not in line:
                    continue
                for match in MD_REF_RE.finditer(line):
                    token = _clean_ref_token(match.group("path"))
                    if not _looks_like_local_doc_ref(token):
                        continue
                    target = (path.parent / token).resolve()
                    if not target.exists():
                        violations.append(
                            Violation(
                                "local_refs",
                                _relative(path, repo_root),
                                step_id,
                                f"unresolved local reference {token}",
                            )
                        )
    return violations


def lint_required_sections(plan_dir: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in numbered_sequence_files(plan_dir):
        text = _read(path)
        for section in REQUIRED_SECTIONS:
            if section not in text:
                violations.append(
                    Violation("required_sections", _relative(path, plan_dir), path.stem, f"missing {section}")
                )
    return violations


def lint_forbidden_markers(plan_dir: Path) -> list[Violation]:
    violations: list[Violation] = []
    lowered_markers = [marker.lower() for marker in FORBIDDEN_MARKERS]
    for path in numbered_sequence_files(plan_dir):
        for line_number, line in enumerate(_read(path).splitlines(), start=1):
            lowered = line.lower()
            for marker in lowered_markers:
                if marker in lowered:
                    violations.append(
                        Violation(
                            "forbidden_markers",
                            _relative(path, plan_dir),
                            str(line_number),
                            f"contains forbidden marker {marker!r}",
                        )
                    )
    return violations


def lint_matrix_coverage(repo_root: Path, plan_dir: Path) -> tuple[list[Violation], PlanStats]:
    general_dir = repo_root / "piano_doc"
    requirements = parse_requirement_rows(general_dir / "017_traceability_matrix.md")
    goal_questions = parse_goal_question_rows(general_dir / "017_traceability_matrix.md")
    artifacts = parse_artifact_rows(general_dir / "018_output_matrix.md")
    fixtures = parse_fixture_rows(general_dir / "010_metriche_validazione.md")

    traceability_path = plan_dir / "900_traceability_to_general_plan.md"
    traceability_text = _read(traceability_path)
    fixture_sequence = _read(plan_dir / "028_seq_fixtures_test_suite_ci.md")
    existing_sequence_ids = {path.name.split("_", 1)[0] for path in numbered_sequence_files(plan_dir)}
    existing_sequence_ids.update({"000", "900", "901", "902"})
    requirement_rows = _rows_by_label(traceability_text, "## Exact Requirement Coverage From `017`", 1)
    goal_question_rows = _rows_by_label(traceability_text, "## Exact Goal Question Coverage From `017`", 1)
    artifact_rows = _rows_by_label(traceability_text, "## Exact Artifact Coverage From `018`", 1)
    fixture_rows_900 = _fixture_rows_by_label(traceability_text)

    violations: list[Violation] = []
    for requirement in requirements:
        cells = requirement_rows.get(requirement)
        if cells is None:
            violations.append(Violation("requirements", "900_traceability_to_general_plan.md", requirement, "missing from 900"))
            continue
        _validate_sequence_cell(violations, "requirements", requirement, cells, 2, "producer", existing_sequence_ids)
        _validate_sequence_cell(violations, "requirements", requirement, cells, 3, "validator", existing_sequence_ids)

    for question in goal_questions:
        cells = goal_question_rows.get(question)
        if cells is None:
            violations.append(Violation("goal_questions", "900_traceability_to_general_plan.md", question, "missing from 900"))
            continue
        _validate_sequence_cell(violations, "goal_questions", question, cells, 2, "coverage", existing_sequence_ids)

    for artifact in artifacts:
        cells = artifact_rows.get(artifact)
        if cells is None:
            violations.append(Violation("artifacts", "900_traceability_to_general_plan.md", artifact, "missing from 900"))
            continue
        _validate_sequence_cell(violations, "artifacts", artifact, cells, 2, "producer", existing_sequence_ids)
        _validate_sequence_cell(violations, "artifacts", artifact, cells, 3, "validator", existing_sequence_ids)

    for fixture in fixtures:
        cells = fixture_rows_900.get(fixture)
        if cells is None:
            violations.append(Violation("fixtures", "900_traceability_to_general_plan.md", fixture, "missing from 900"))
        else:
            _validate_sequence_cell(violations, "fixtures", fixture, cells, 1, "coverage", existing_sequence_ids)
        if fixture not in fixture_sequence:
            violations.append(Violation("fixtures", "028_seq_fixtures_test_suite_ci.md", fixture, "missing from fixture sequence"))

    stats = PlanStats(
        step_count=sum(len(step_blocks(_read(path))) for path in numbered_sequence_files(plan_dir)),
        requirement_rows=len(requirements),
        artifact_rows=len(artifacts),
        fixture_rows=len(fixtures),
        goal_question_rows=len(goal_questions),
    )
    return violations, stats


def lint_review_packet(plan_dir: Path) -> list[Violation]:
    path = plan_dir / "901_internal_review_packet.md"
    text = _read(path).lower()
    violations: list[Violation] = []
    if "implementation plan only" not in text:
        violations.append(Violation("review_packet", path.name, "scope", "missing Implementation Plan Only scope"))
    if not re.search(r"exclude:.*runtime plugin code", text):
        violations.append(Violation("review_packet", path.name, "scope", "missing runtime plugin code exclusion"))
    if not re.search(r"exclude:.*creating `plugins/`", text):
        violations.append(Violation("review_packet", path.name, "scope", "missing plugins directory exclusion"))
    contradiction_patterns = (
        r"include:\s*.*(?:runtime plugin code|plugin code|creating `plugins/`|plugins/)",
        r"\ballow(?:s|ed)?\s+.*(?:runtime plugin code|plugin code|creating `plugins/`|plugins/)",
        r"\bauthori[sz](?:e|ed|es)?\s+.*(?:runtime plugin code|plugin code|creating `plugins/`|plugins/)",
    )
    for pattern in contradiction_patterns:
        if re.search(pattern, text):
            violations.append(
                Violation("review_packet", path.name, "scope", "contradictory plugin-code inclusion")
            )
            break
    return violations


def validate_plan(repo_root: Path, plan_dir: Path) -> tuple[list[Violation], PlanStats]:
    violations: list[Violation] = []
    violations.extend(lint_step_fields(plan_dir))
    violations.extend(lint_reference_paths(plan_dir, repo_root))
    violations.extend(lint_required_sections(plan_dir))
    violations.extend(lint_forbidden_markers(plan_dir))
    coverage_violations, stats = lint_matrix_coverage(repo_root, plan_dir)
    violations.extend(coverage_violations)
    violations.extend(lint_review_packet(plan_dir))
    return violations, stats


def write_report(output: Path, repo_root: Path, plan_dir: Path, violations: list[Violation], stats: PlanStats) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    status = "pass" if not violations else "blocker"
    ready = "ready" if not violations else "blocked"
    lines = [
        "# Implementation Plan Traceability Report",
        "",
        f"- Repository root: `{repo_root}`",
        f"- Plan dir: `{plan_dir}`",
        f"- Status: `{status}`",
        f"- Review packet readiness: `{ready}`",
        f"- Step count: `{stats.step_count}`",
        f"- Requirement rows: `{stats.requirement_rows}`",
        f"- Goal question rows: `{stats.goal_question_rows}`",
        f"- Artifact rows: `{stats.artifact_rows}`",
        f"- Authoritative fixtures: `{stats.fixture_rows}`",
        f"- Violation count: `{len(violations)}`",
        "",
        "## Violations",
        "",
    ]
    if violations:
        lines.extend(
            f"- `{violation.category}` `{violation.path}` `{violation.item}`: {violation.message}"
            for violation in violations
        )
    else:
        lines.append("- None.")
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--plan-dir", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    plan_dir = Path(args.plan_dir).resolve()
    output = Path(args.output)
    violations, stats = validate_plan(repo_root, plan_dir)
    write_report(output, repo_root, plan_dir, violations, stats)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
