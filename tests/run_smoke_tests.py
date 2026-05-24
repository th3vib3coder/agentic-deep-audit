from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"
DEFAULT_FIXTURES = ["mixed_risky", "performance_quality_project", "license_manifest"]
REQUIRED_ARTIFACTS = ["RUN_CONFIG.json", "FILE_INDEX.json", "MODULE_GRAPH.json", "wiki/000_home.md", "VALIDATION_REPORT.md"]


@dataclass(frozen=True)
class SmokeResult:
    fixture: str
    status: str
    detail: str


def run_command(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return subprocess.run(args, cwd=cwd, env=env, check=False, text=True, capture_output=True)


def run_fixture(name: str, work_root: Path) -> SmokeResult:
    source = FIXTURE_ROOT / name
    target = work_root / name
    shutil.copytree(source, target)
    config = target / "audit.config.yaml"
    if not config.exists():
        return SmokeResult(name, "fail", "missing audit.config.yaml")
    run = run_command([sys.executable, "-m", "agentic_deep_audit.cli", "wiki", "--config", str(config)], cwd=target)
    if run.returncode != 0:
        return SmokeResult(name, "fail", run.stderr.strip() or run.stdout.strip())
    audit_dir = target / "audit"
    validate = run_command([sys.executable, "-m", "agentic_deep_audit.cli", "validate", "--audit-dir", str(audit_dir)], cwd=target)
    if validate.returncode != 0:
        return SmokeResult(name, "fail", validate.stderr.strip() or validate.stdout.strip())
    missing = [artifact for artifact in REQUIRED_ARTIFACTS if not (audit_dir / artifact).exists()]
    if missing:
        return SmokeResult(name, "fail", "missing artifacts: " + ", ".join(missing))
    return SmokeResult(name, "pass", "artifact set present")


def write_report(path: Path, results: list[SmokeResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Smoke Test Report", "", "| Fixture | Status | Detail |", "|---|---|---|"]
    lines.extend(f"| `{result.fixture}` | `{result.status}` | {result.detail.replace('|', '/')} |" for result in results)
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", action="append", dest="fixtures")
    parser.add_argument("--report", default=str(PLUGIN_ROOT / "audit" / "SMOKE_TEST_REPORT.md"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fixtures = args.fixtures or DEFAULT_FIXTURES
    with tempfile.TemporaryDirectory(prefix="agentic-deep-audit-smoke-") as tmp:
        results = [run_fixture(name, Path(tmp)) for name in fixtures]
    write_report(Path(args.report), results)
    return 0 if all(result.status == "pass" for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
