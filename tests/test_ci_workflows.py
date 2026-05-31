from __future__ import annotations

import yaml

from agentic_deep_audit.models import PLUGIN_ROOT


WORKFLOW = PLUGIN_ROOT / ".github" / "workflows" / "agentic-deep-audit.yml"
GHA_DOC = PLUGIN_ROOT / "docs" / "adapters" / "github-actions.md"

NINE_FIELDS = (
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


def _load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _matrix_jobs(wf: dict) -> list[dict]:
    return [
        job
        for job in wf.get("jobs", {}).values()
        if isinstance(job, dict) and isinstance(job.get("strategy"), dict) and "matrix" in job["strategy"]
    ]


def test_workflow_matrix_includes_ubuntu_and_windows_three_pythons() -> None:
    wf = _load_workflow()
    matrix_jobs = _matrix_jobs(wf)
    assert matrix_jobs, "no job declares strategy.matrix"
    matrix = matrix_jobs[0]["strategy"]["matrix"]

    assert matrix.get("os") == ["ubuntu-latest", "windows-latest"], f"matrix.os == {matrix.get('os')!r}"
    # YAML would coerce bare 3.10 -> float 3.1; the workflow must quote them as strings.
    assert matrix.get("python-version") == ["3.10", "3.11", "3.12"], f"matrix.python-version == {matrix.get('python-version')!r}"
    assert "macos-latest" not in matrix.get("os", []), "macos-latest must not be an active matrix runner (SD-4 deferred)"

    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "macos-latest: deferred" in raw, "workflow must carry the 'macos-latest: deferred' comment token (SD-4)"


def test_workflow_run_steps_are_cross_shell_safe() -> None:
    # Bash-only idioms (set -o pipefail, tee, grep, mkdir -p, backslash continuations) fail under
    # the windows-latest default pwsh. Either the job sets defaults.run.shell: bash, or every
    # multi-line run step declares shell: bash.
    wf = _load_workflow()
    for name, job in wf.get("jobs", {}).items():
        if not isinstance(job, dict):
            continue
        job_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell")
        if job_shell == "bash":
            continue
        for step in job.get("steps", []) or []:
            run = step.get("run") if isinstance(step, dict) else None
            if isinstance(run, str) and "\n" in run:
                assert step.get("shell") == "bash", (
                    f"job {name!r} step {step.get('name')!r} has a multi-line run without shell: bash "
                    "and the job has no defaults.run.shell: bash"
                )


def test_github_actions_doc_has_nine_fields() -> None:
    lowered = GHA_DOC.read_text(encoding="utf-8").lower()  # FileNotFoundError when absent (RED)
    missing = [field for field in NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"github-actions.md missing field sections: {missing}"


def test_workflow_has_no_piano_doc_reference() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    private = [tok for tok in ("piano_doc", "plugins/agentic-deep-audit", "nuove_skill", "013_ledger") if tok in raw]
    assert not private, f"workflow references private tokens: {private}"
