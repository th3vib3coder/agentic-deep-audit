from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_deep_audit.adapters.base import AdapterError, AdapterStatus, ToolAdapter, persist_raw_output, raw_output_path, run_adapter_command
from agentic_deep_audit.adapters.loader import AdapterBlockedPrePromotion, load_adapter, load_adapter_decision, validate_adapter_promotion
from agentic_deep_audit.bootstrap import bootstrap_audit, detect_command
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


REPO_ROOT = PLUGIN_ROOT


class FakeAdapter(ToolAdapter):
    def __init__(self, adapter_id: str = "fake", provenance_class: str = "core") -> None:
        super().__init__(adapter_id=adapter_id, capability="test", provenance_class=provenance_class)
        self.calls: list[str] = []
        self._status = AdapterStatus(tool=self.adapter_id, status="skipped", policy="skipped", available=False, capability=self.capability, availability="missing", provenance_class=self.provenance_class, skipped_reason="not run")

    def detect(self) -> AdapterStatus:
        self.calls.append("detect")
        self._status = AdapterStatus(tool=self.adapter_id, status="detected", policy="allowed", available=True, capability=self.capability, availability="available", provenance_class=self.provenance_class)
        return self._status

    def run(self, run_config: dict, audit_dir: Path) -> AdapterStatus:
        self.calls.append("run")
        self._status = AdapterStatus(tool=self.adapter_id, status="completed", policy="allowed", available=True, capability=self.capability, availability="available", provenance_class=self.provenance_class)
        return self._status

    def parse(self, raw_output_path: Path | None) -> dict:
        self.calls.append("parse")
        return {"raw_output_path": str(raw_output_path) if raw_output_path else None}

    def status(self) -> AdapterStatus:
        self.calls.append("status")
        return self._status


def minimal_run_config(tmp_path: Path) -> dict:
    return {
        "run_id": "run-adapter",
        "repo": {"kind": "local", "path": str(tmp_path), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": "audit",
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**"]},
        "target_context": {"preset": "MIT downstream"},
        "binary_triage_consent": False,
    }


def write_promote_decision(root: Path, adapter_id: str = "graphify", decision: str = "promote") -> Path:
    target = root / "docs" / "adapters" / adapter_id
    target.mkdir(parents=True)
    payload = {
        "adapter_id": adapter_id,
        "installability": {"os": ["Windows"], "notes": "installed in fixture"},
        "license": {"spdx": "MIT", "compatible_with_target_context": True},
        "version_pinning": {"strategy": "minimum", "min_version": "1.0.0"},
        "command_readonly": f"{adapter_id} --version",
        "policy_applied": ["no-exec", "read-only", "path-containment"],
        "schema_output_observed": {"sample_path": "samples/output.json", "hash": "abc123"},
        "fallback": "canonical fallback",
        "decision": decision,
        "reviewer": "Ada",
        "decision_date": "2026-05-23",
    }
    path = target / "adapter_decision.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def test_fake_adapter_records_all_lifecycle_methods(tmp_path: Path) -> None:
    adapter = FakeAdapter()

    adapter.detect()
    adapter.run({}, tmp_path)
    adapter.parse(None)
    adapter.status()

    assert adapter.calls == ["detect", "run", "parse", "status"]


def test_tool_status_core_records_include_capability_fields(tmp_path: Path) -> None:
    audit_dir = bootstrap_audit(minimal_run_config(tmp_path), cwd=tmp_path)
    payload = json.loads((audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8"))

    by_tool = {tool["tool"]: tool for tool in payload["tools"]}
    for name in ["python", "git", "rg", "sqlite_fts5", "network_policy"]:
        assert name in by_tool
        for key in ["os", "capability", "availability", "provenance_class"]:
            assert by_tool[name][key]
    missing = detect_command("definitely_missing_agentic_audit_tool", ["--version"])
    assert missing["status"] == "skipped"
    assert missing["skipped_reason"]
    assert missing["capability"] == "definitely_missing_agentic_audit_tool_version_probe"


def test_adapter_promotion_blocks_deferred_and_missing_decisions(tmp_path: Path) -> None:
    with pytest.raises(AdapterBlockedPrePromotion, match="adapter_blocked_pre_promotion"):
        load_adapter(FakeAdapter(adapter_id="madge", provenance_class="industry-known"), tmp_path)

    write_promote_decision(tmp_path, adapter_id="graphify", decision="defer")
    with pytest.raises(AdapterBlockedPrePromotion, match="decision is defer"):
        validate_adapter_promotion(tmp_path, "graphify", "industry-known")


def test_adapter_promotion_accepts_schema_valid_promote_decision(tmp_path: Path) -> None:
    path = write_promote_decision(tmp_path, adapter_id="graphify", decision="promote")

    decision = load_adapter_decision(tmp_path, "graphify")
    adapter = load_adapter(FakeAdapter(adapter_id="graphify", provenance_class="industry-known"), tmp_path)

    assert decision.path == path
    assert decision.decision == "promote"
    assert adapter.adapter_id == "graphify"


def test_real_graphify_decision_starts_deferred() -> None:
    with pytest.raises(AdapterBlockedPrePromotion, match="decision is defer"):
        validate_adapter_promotion(PLUGIN_ROOT, "graphify", "industry-known")


def test_schema_invalid_adapter_decision_blocks(tmp_path: Path) -> None:
    target = tmp_path / "docs" / "adapters" / "pydeps"
    target.mkdir(parents=True)
    (target / "adapter_decision.json").write_text(json.dumps({"adapter_id": "pydeps", "decision": "promote"}) + "\n", encoding="utf-8")

    with pytest.raises(AdapterBlockedPrePromotion, match="schema-invalid"):
        validate_adapter_promotion(tmp_path, "pydeps", "industry-known")


def test_adapter_promotion_rejects_mismatched_adapter_id(tmp_path: Path) -> None:
    path = write_promote_decision(tmp_path, adapter_id="madge", decision="promote")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["adapter_id"] = "graphify"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(AdapterBlockedPrePromotion, match="does not match madge"):
        validate_adapter_promotion(tmp_path, "madge", "industry-known")


def test_secret_like_raw_output_is_not_persisted(tmp_path: Path) -> None:
    persisted, summary = persist_raw_output(tmp_path, "semgrep", "raw.json", "token ghp_ABCDEFGHIJKLMNOPQRST")

    assert persisted is None
    assert summary == "raw/semgrep/REDACTED_SUMMARY.json"
    text = (tmp_path / summary).read_text(encoding="utf-8")
    assert "ghp_ABCDEFGHIJKLMNOPQRST" not in text
    assert "raw_persisted" in text


def test_raw_output_path_cannot_escape_audit_dir(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match="outside containment"):
        raw_output_path(tmp_path, "tool", "../../../outside.txt")


def test_adapter_run_network_block_records_tool_status(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    adapter = FakeAdapter(adapter_id="networked", provenance_class="industry-known")

    status = run_adapter_command(adapter, ["python", "-m", "agentic_deep_audit.cli", "--help"], cwd=tmp_path, audit_dir=audit_dir, network_target="api.github.com", network_policy=None)

    assert status.status == "blocked"
    assert status.policy == "blocked"
    payload = json.loads((audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8"))
    record = payload["tools"][-1]
    assert record["tool"] == "networked"
    assert record["degradation_reason"] == "network policy blocked adapter request"


def test_adapter_run_persists_raw_output_inside_audit_dir(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    adapter = FakeAdapter(adapter_id="python_probe", provenance_class="core")

    status = run_adapter_command(adapter, ["python", "-m", "agentic_deep_audit.cli", "--help"], cwd=REPO_ROOT, audit_dir=audit_dir)

    assert status.output_path == "raw/python_probe/stdout.txt"
    assert (audit_dir / status.output_path).exists()
    assert status.exit_code is not None


def test_adapter_run_rejects_cwd_outside_repo_root(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    adapter = FakeAdapter(adapter_id="cwd_probe", provenance_class="core")

    with pytest.raises(AdapterError, match="outside containment"):
        run_adapter_command(
            adapter,
            ["python", "-m", "agentic_deep_audit.cli", "--help"],
            cwd=outside,
            audit_dir=audit_dir,
            repo_root=repo_root,
        )
