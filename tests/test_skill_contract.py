from __future__ import annotations

import re
from pathlib import Path

from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = PLUGIN_ROOT / "skills" / "deep-repo-audit"
REFERENCES = SKILL_ROOT / "references"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_skill_trigger_description_and_safety_defaults() -> None:
    skill = read(SKILL_ROOT / "SKILL.md")
    lower = skill.lower()

    for trigger in [
        "deep audit",
        "repo audit",
        "github audit",
        "local audit",
        "architecture map",
        "reuse evaluation",
        "wiki graph",
        "supply-chain audit",
    ]:
        assert trigger in lower
    assert "binary re is excluded by default" in lower
    assert "source-audit" in skill
    assert "binary_triage_consent" in skill
    assert "do not execute target repository code" in lower


def test_references_exist_and_are_linked() -> None:
    skill = read(SKILL_ROOT / "SKILL.md")
    expected = [
        "audit_contract.md",
        "profiles.md",
        "output_artifacts.md",
        "safety_policy.md",
        "review_protocol.md",
        "tool_adapters.md",
    ]

    for filename in expected:
        assert (REFERENCES / filename).exists()
        assert f"references/{filename}" in skill


def test_audit_contract_has_each_phase_once() -> None:
    contract = read(REFERENCES / "audit_contract.md")
    phases = re.findall(r"^## Phase ([0-9])\b", contract, flags=re.MULTILINE)

    assert phases == [str(number) for number in range(10)]


def test_output_reference_covers_runtime_artifacts() -> None:
    output_reference = read(REFERENCES / "output_artifacts.md")
    required = [
        ARTIFACT_PATHS["RUN_CONFIG"],
        ARTIFACT_PATHS["EVIDENCE_INDEX"],
        ARTIFACT_PATHS["GRAPH"],
        ARTIFACT_PATHS["CORPUS_INDEX"],
        ARTIFACT_PATHS["REPORT"],
        ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"],
    ]

    missing = sorted(artifact for artifact in required if f"`{artifact}`" not in output_reference)
    assert not missing


def test_safety_review_and_adapter_references_have_required_terms() -> None:
    safety = read(REFERENCES / "safety_policy.md")
    safety_lower = safety.lower()
    review = read(REFERENCES / "review_protocol.md").lower()
    adapters = read(REFERENCES / "tool_adapters.md")

    assert "BLOCKED_COMMANDS_ATTEMPTS.json" in safety
    assert "TOOL_STATUS.json" in safety
    assert "fail-closed" in safety
    assert "no-exec default" in safety_lower
    assert "network" in safety_lower
    assert "denied domains override allowed domains" in safety_lower
    assert "untrusted markdown sanitizer" in safety_lower
    assert "mcp write policy" in safety_lower
    assert "host mcp config reading" in safety_lower
    assert "reviewer different from the author" in review
    for operation in ["detect", "run", "parse", "status"]:
        assert f"- `{operation}`:" in adapters
    assert "TOOL_STATUS.json" in adapters
    assert "Adapter Promotion Gate" in adapters
