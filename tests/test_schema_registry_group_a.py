from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from agentic_deep_audit import validate_extensions
from agentic_deep_audit.validate_json_schema import SCHEMA_BY_ARTIFACT_KEY, SCHEMA_EXEMPT_ARTIFACT_KEYS
from agentic_deep_audit.models import ARTIFACT_PATHS, load_schema_registry


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = PLUGIN_ROOT / "skills" / "deep-repo-audit" / "schemas"
SRC_SCHEMA_DIR = PLUGIN_ROOT / "src" / "agentic_deep_audit" / "schemas"


def schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate_sample(schema_value: dict, sample: dict) -> None:
    Draft202012Validator.check_schema(schema_value)
    Draft202012Validator(schema_value).validate(sample)


def assert_invalid(schema_value: dict, sample: dict) -> None:
    Draft202012Validator.check_schema(schema_value)
    with pytest.raises(ValidationError):
        Draft202012Validator(schema_value).validate(sample)


def test_all_group_a_schemas_parse() -> None:
    expected = {
        "audit_config.schema.json",
        "run_config.schema.json",
        "network_policy.schema.json",
        "blocked_commands.schema.json",
        "file_index.schema.json",
        "provenance.schema.json",
        "manifests.schema.json",
        "evidence_index.schema.json",
        "tool_status.schema.json",
        "module_graph.schema.json",
        "symbol_index.schema.json",
        "call_graph.schema.json",
        "graph.schema.json",
        "api_surface.schema.json",
        "cli_surface.schema.json",
        "mcp_surface.schema.json",
        "config_surface.schema.json",
        "special_implementations.schema.json",
        "risk_findings.schema.json",
        "suspicious_behaviors.schema.json",
        "agentic_security_finding.schema.json",
        "license_cards.schema.json",
        "reuse_cards.schema.json",
        "scientific_provenance.schema.json",
        "project_telemetry.schema.json",
        "audit_runtime_metrics.schema.json",
        "binary_artifacts.schema.json",
        "corpus_index.schema.json",
        "mcp_config.schema.json",
        "adapter_decision.schema.json",
        "core_envelope.schema.json",
    }
    observed = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}

    assert observed == expected
    for schema_name in observed:
        Draft202012Validator.check_schema(schema(schema_name))


def test_src_and_skill_schema_copies_are_identical() -> None:
    src_schemas = {path.name for path in SRC_SCHEMA_DIR.glob("*.schema.json")}
    skill_schemas = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}

    assert src_schemas == skill_schemas
    for schema_name in sorted(src_schemas):
        assert (SRC_SCHEMA_DIR / schema_name).read_bytes() == (SCHEMA_DIR / schema_name).read_bytes(), schema_name


def test_all_group_a_schemas_reject_unknown_root_properties() -> None:
    for path in SCHEMA_DIR.glob("*.schema.json"):
        value = schema(path.name)
        assert value.get("additionalProperties") is False, path.name


def test_json_artifact_schema_coverage_has_explicit_exemptions() -> None:
    json_artifact_keys = {key for key, value in ARTIFACT_PATHS.items() if value.endswith(".json")}
    covered = set(SCHEMA_BY_ARTIFACT_KEY) | set(SCHEMA_EXEMPT_ARTIFACT_KEYS)

    assert json_artifact_keys <= covered
    assert set(SCHEMA_BY_ARTIFACT_KEY).isdisjoint(SCHEMA_EXEMPT_ARTIFACT_KEYS)


def test_high_trust_phase1_artifacts_are_schema_mapped_not_exempt() -> None:
    assert SCHEMA_BY_ARTIFACT_KEY["FILE_INDEX"] == "file_index"
    assert SCHEMA_BY_ARTIFACT_KEY["PROVENANCE"] == "provenance"
    assert SCHEMA_BY_ARTIFACT_KEY["MANIFESTS"] == "manifests"
    assert {"FILE_INDEX", "PROVENANCE", "MANIFESTS"}.isdisjoint(SCHEMA_EXEMPT_ARTIFACT_KEYS)

    assert_invalid(schema("file_index.schema.json"), {"schema_version": "1.0", "repo": {}, "records": [{"path": "a.py"}]})
    assert_invalid(schema("provenance.schema.json"), {"schema_version": "1.0", "git": "not-an-object"})
    assert_invalid(schema("manifests.schema.json"), {"schema_version": "1.0", "records": [{"path": "package.json", "skipped": False, "skip_reason": None}]})


def test_semantic_validator_json_artifacts_are_schema_backed() -> None:
    """Keep the schema/hand-validator contract explicit when new domains are added."""

    extension_groups = [
        validate_extensions.SCIENTIFIC_KEYS,
        validate_extensions.TELEMETRY_KEYS,
        validate_extensions.RISK_KEYS,
        validate_extensions.LICENSE_BINARY_KEYS,
        validate_extensions.PERFORMANCE_QUALITY_KEYS,
        validate_extensions.REUSE_KEYS,
        validate_extensions.WIKI_KEYS,
        validate_extensions.GRAPH_KEYS,
        validate_extensions.CORPUS_KEYS,
        validate_extensions.MCP_EXPORT_KEYS,
        validate_extensions.REPORT_KEYS,
    ]
    semantic_json_keys = {
        key
        for group in extension_groups
        for key in group
        if ARTIFACT_PATHS[key].endswith(".json")
    }
    expected_extension_schema_keys = {
        "SCIENTIFIC_PROVENANCE",
        "PROJECT_TELEMETRY",
        "SUSPICIOUS_BEHAVIORS",
        "RISK_FINDINGS",
        "AGENTIC_SECURITY_FINDINGS",
        "LICENSE_CARDS",
        "BINARY_ARTIFACTS",
        "AUDIT_RUNTIME_METRICS",
        "REUSE_CARDS",
        "GRAPH",
        "CORPUS_INDEX",
        "MCP_CONFIG",
    }
    legacy_semantic_exemptions = {
        "SBOM",
        "GRAPH_NODES",
        "GRAPH_EDGES",
        "GRAPHIFY_GRAPH",
    }
    core_semantic_schema_keys = {
        "FILE_INDEX",
        "PROVENANCE",
        "MANIFESTS",
        "EVIDENCE_INDEX",
        "MODULE_GRAPH",
        "SYMBOL_INDEX",
        "CALL_GRAPH",
        "API_SURFACE",
        "CLI_SURFACE",
        "MCP_SURFACE",
        "CONFIG_SURFACE",
        "SPECIAL_IMPLEMENTATIONS",
    }

    assert semantic_json_keys == expected_extension_schema_keys | legacy_semantic_exemptions
    assert expected_extension_schema_keys <= set(SCHEMA_BY_ARTIFACT_KEY)
    assert legacy_semantic_exemptions <= SCHEMA_EXEMPT_ARTIFACT_KEYS
    assert core_semantic_schema_keys <= set(SCHEMA_BY_ARTIFACT_KEY)
    assert (expected_extension_schema_keys | core_semantic_schema_keys).isdisjoint(SCHEMA_EXEMPT_ARTIFACT_KEYS)


def test_audit_config_valid_and_invalid_samples() -> None:
    valid = {
        "schema_version": "1.0",
        "repo": {"kind": "local", "path": ".", "github": None},
        "profile": "standard",
        "mode": "source-audit",
        "output_dir": "audit",
        "target_context": "MIT downstream",
        "binary_triage_consent": False,
    }
    validate_sample(schema("audit_config.schema.json"), valid)
    invalid = dict(valid)
    invalid.pop("repo")
    assert_invalid(schema("audit_config.schema.json"), invalid)


def test_policy_schemas_require_fail_closed_fields() -> None:
    network = {"schema_version": "1.0", "default": "deny", "allowed_domains": [], "denied_domains": ["*"], "redaction_rules": ["token"], "send_source_code": False, "send_dependency_names": True}
    validate_sample(schema("network_policy.schema.json"), network)
    missing_denied = dict(network)
    missing_denied.pop("denied_domains")
    assert_invalid(schema("network_policy.schema.json"), missing_denied)

    blocked = {"schema_version": "1.0", "allowed": [{"command": "git", "subcommands": ["status"], "network": False}], "blocked_always": ["npm"], "sandbox_only": ["pytest"]}
    validate_sample(schema("blocked_commands.schema.json"), blocked)
    invalid_blocked = {"schema_version": "1.0", "allowed": [{"command": 123, "subcommands": "status", "network": "false"}], "blocked_always": ["npm"], "sandbox_only": ["pytest"]}
    assert_invalid(schema("blocked_commands.schema.json"), invalid_blocked)


def test_representative_schema_enums_reject_unknown_values() -> None:
    assert_invalid(
        schema("audit_config.schema.json"),
        {
            "schema_version": "1.0",
            "repo": {"kind": "local", "path": ".", "github": None},
            "profile": "aggressive",
            "mode": "source-audit",
            "output_dir": "audit",
            "target_context": "MIT downstream",
            "binary_triage_consent": False,
        },
    )
    assert_invalid(
        schema("network_policy.schema.json"),
        {
            "schema_version": "1.0",
            "default": "allow",
            "allowed_domains": [],
            "denied_domains": ["*"],
            "redaction_rules": [],
            "send_source_code": False,
            "send_dependency_names": True,
        },
    )
    assert_invalid(
        schema("file_index.schema.json"),
        {
            "schema_version": "1.0",
            "run_id": "run-1",
            "repo": {"path": "."},
            "generated_at": "2026-05-29T00:00:00Z",
            "source_artifacts": ["RUN_CONFIG.json"],
            "records": [{"path": "a.py", "path_normalized": "a.py", "size_bytes": 1, "sha256": "abc", "extension": ".py", "language": "python", "kind": "source", "binary": False}],
            "skipped": False,
            "skip_reason": None,
            "skipped_paths": [],
            "root_documents": [],
        },
    )


def test_evidence_file_line_requires_byte_range() -> None:
    valid = {"schema_version": "1.1", "repo": {"path": ".", "commit": "abc"}, "evidence": [{"id": "ev-000001", "kind": "file_line", "path": "a.py", "start_line": 1, "end_line": 1, "start_byte": 0, "end_byte": 5, "sha256": "abc"}]}
    validate_sample(schema("evidence_index.schema.json"), valid)
    overflow_valid = {"schema_version": "1.1", "repo": {"path": ".", "commit": "abc"}, "evidence": [{**valid["evidence"][0], "id": "ev-1000000"}]}
    validate_sample(schema("evidence_index.schema.json"), overflow_valid)
    invalid = {"schema_version": "1.1", "repo": {"path": ".", "commit": "abc"}, "evidence": [{"id": "ev-000001", "kind": "file_line", "path": "a.py", "start_line": 1, "end_line": 1, "sha256": "abc"}]}
    assert_invalid(schema("evidence_index.schema.json"), invalid)
    invalid_binary = {"schema_version": "1.1", "repo": {"path": ".", "commit": "abc"}, "evidence": [{"id": "ev-000002", "kind": "file_whole", "path": "logo.bin", "binary_safe": True, "sha256": "abc"}]}
    assert_invalid(schema("evidence_index.schema.json"), invalid_binary)
    duplicate = {"schema_version": "1.1", "repo": {"path": ".", "commit": "abc"}, "evidence": [valid["evidence"][0], valid["evidence"][0]]}
    assert_invalid(schema("evidence_index.schema.json"), duplicate)


def test_tool_status_requires_skipped_and_degraded_detail() -> None:
    valid = {"schema_version": "1.0", "tools": [{"tool": "graphify", "status": "skipped", "policy": "skipped", "skipped_reason": "not installed", "os": "Windows", "capability": "graph", "availability": "missing", "provenance_class": "industry-known"}]}
    validate_sample(schema("tool_status.schema.json"), valid)
    invalid = {"schema_version": "1.0", "tools": [{"tool": "graphify", "status": "skipped", "policy": "skipped"}]}
    assert_invalid(schema("tool_status.schema.json"), invalid)
    degraded = {"schema_version": "1.0", "tools": [{"tool": "tree-sitter", "status": "degraded", "policy": "allowed", "os": "Windows", "capability": "parser", "availability": "partial", "provenance_class": "industry-known", "degradation": "missing grammar", "degradation_reason": "missing grammar"}]}
    validate_sample(schema("tool_status.schema.json"), degraded)
    invalid_degraded = {"schema_version": "1.0", "tools": [{"tool": "tree-sitter", "status": "degraded", "policy": "allowed"}]}
    assert_invalid(schema("tool_status.schema.json"), invalid_degraded)
    deferred = {"schema_version": "1.0", "tools": [{"tool": "graphify", "status": "deferred", "policy": "skipped", "skipped_reason": "adapter deferred", "os": "Windows", "capability": "graph", "availability": "deferred", "provenance_class": "industry-known", "degradation": "adapter deferred", "degradation_reason": "adapter deferred"}]}
    validate_sample(schema("tool_status.schema.json"), deferred)
    invalid_deferred = {"schema_version": "1.0", "tools": [{key: value for key, value in deferred["tools"][0].items() if key != "skipped_reason"}]}
    assert_invalid(schema("tool_status.schema.json"), invalid_deferred)


def test_graph_schemas_reject_invalid_types() -> None:
    graph = {"schema_version": "1.0", "repo": {}, "nodes": [{"id": "module:src", "type": "module", "label": "src", "evidence_ids": ["ev-000001"]}], "edges": [{"source": "module:a", "target": "module:b", "type": "depends_on", "weight": 1.0, "conditional": False, "dynamic": False, "evidence_ids": ["ev-000001"]}]}
    validate_sample(schema("graph.schema.json"), graph)
    invalid = {"schema_version": "1.0", "repo": {}, "nodes": [{"id": "x", "type": "invalid", "label": "x", "evidence_ids": []}], "edges": []}
    assert_invalid(schema("graph.schema.json"), invalid)
    missing_evidence = {"schema_version": "1.0", "repo": {}, "nodes": [{"id": "x", "type": "module", "label": "x"}], "edges": []}
    assert_invalid(schema("graph.schema.json"), missing_evidence)

    module_graph = {"schema_version": "1.0", "nodes": [{"id": "m:a", "type": "module", "path": "a.py"}], "edges": [{"source": "m:a", "target": "m:b", "type": "imports", "weight": 1, "conditional": False, "dynamic": False, "evidence_ids": ["ev-000001"]}], "coverage": {}}
    validate_sample(schema("module_graph.schema.json"), module_graph)
    module_graph_missing_evidence = {"schema_version": "1.0", "nodes": [{"id": "m:a", "type": "module", "path": "a.py"}], "edges": [{"source": "m:a", "target": "m:b", "type": "imports", "weight": 1, "conditional": False, "dynamic": False}], "coverage": {}}
    assert_invalid(schema("module_graph.schema.json"), module_graph_missing_evidence)
    symbol_index = {"schema_version": "1.0", "symbols": [{"symbol_id": "symbol:a.py:function:main:1", "name": "main", "kind": "function", "path": "a.py", "span": {"start_line": 1, "end_line": 1, "start_byte": 0, "end_byte": 10}, "public": True, "evidence_ids": ["ev-000001"]}]}
    validate_sample(schema("symbol_index.schema.json"), symbol_index)
    call_graph = {"schema_version": "1.0", "nodes": [{"id": "symbol:a.py:function:main:1", "kind": "symbol", "label": "main", "path": "a.py"}], "edges": [{"caller": "symbol:a.py:function:main:1", "callee": "external:print", "type": "calls", "conditional": False, "dynamic": False, "evidence_ids": ["ev-000001"]}], "coverage": {}}
    validate_sample(schema("call_graph.schema.json"), call_graph)


def test_surface_schemas_require_common_evidence_and_safety_fields() -> None:
    api = {"schema_version": "1.0", "records": [{"surface_id": "api-000001", "kind": "rest_route", "source_path": "src/api.py", "status": "observed", "confidence": "high", "evidence_ids": ["ev-000001"], "sanitizer_decision": "not_markdown", "method": "GET", "path": "/health", "framework": "fastapi"}]}
    validate_sample(schema("api_surface.schema.json"), api)
    invalid_api = {"schema_version": "1.0", "records": [{key: value for key, value in api["records"][0].items() if key != "evidence_ids"}]}
    assert_invalid(schema("api_surface.schema.json"), invalid_api)

    cli = {"schema_version": "1.0", "records": [{"surface_id": "cli-000001", "kind": "manifest_script", "source_path": "package.json", "status": "observed", "confidence": "high", "evidence_ids": ["ev-000002"], "sanitizer_decision": "not_markdown", "executable": False, "observed_not_executed": True, "command": "npm test"}]}
    validate_sample(schema("cli_surface.schema.json"), cli)
    invalid_cli = {"schema_version": "1.0", "records": [{**cli["records"][0], "executable": True}]}
    assert_invalid(schema("cli_surface.schema.json"), invalid_cli)

    mcp = {"schema_version": "1.0", "records": [{"surface_id": "mcp-000001", "kind": "target_mcp_config", "source_path": ".mcp.json", "status": "observed", "confidence": "high", "evidence_ids": ["ev-000003"], "sanitizer_decision": "not_markdown", "host_imported": False, "audit_only": True}]}
    validate_sample(schema("mcp_surface.schema.json"), mcp)
    invalid_mcp = {"schema_version": "1.0", "records": [{**mcp["records"][0], "host_imported": True}]}
    assert_invalid(schema("mcp_surface.schema.json"), invalid_mcp)

    config = {"schema_version": "1.0", "records": [{"surface_id": "config-000001", "kind": "env_var", "source_path": "README.md", "status": "heuristic", "confidence": "medium", "evidence_ids": ["ev-000004"], "sanitizer_decision": "quoted_with_flags", "name": "DATABASE_URL", "value_read": False}]}
    validate_sample(schema("config_surface.schema.json"), config)
    invalid_config = {"schema_version": "1.0", "records": [{**config["records"][0], "value_read": True}]}
    assert_invalid(schema("config_surface.schema.json"), invalid_config)


def test_special_implementations_schema_requires_reuse_evidence_fields() -> None:
    valid = {
        "schema_version": "1.0",
        "candidates": [
            {
                "candidate_id": "reuse-000001",
                "name": "Greeter",
                "kind": "reusable_component",
                "files": ["src/utils.py"],
                "coupling": "low",
                "dependencies": [],
                "license_status_source": "root_license:ev-000001",
                "performance_note": "No benchmark evidence.",
                "limitations": ["static synthesis only"],
                "evidence_ids": ["ev-000002"],
            }
        ],
    }
    validate_sample(schema("special_implementations.schema.json"), valid)
    invalid = {"schema_version": "1.0", "candidates": [{key: value for key, value in valid["candidates"][0].items() if key != "license_status_source"}]}
    assert_invalid(schema("special_implementations.schema.json"), invalid)
    invalid_source = {"schema_version": "1.0", "candidates": [{**valid["candidates"][0], "license_status_source": "unreviewed"}]}
    assert_invalid(schema("special_implementations.schema.json"), invalid_source)


def test_risk_schema_rejects_unconfirmed_heuristic_source_kind() -> None:
    valid = {
        "schema_version": "1.0",
        "promotion_policy": "heuristics_not_promoted_without_external_tool_confirmation",
        "source_tools": [],
        "findings": [{"finding_id": "risk-1", "category": "dependency_cve", "severity": "high", "confidence": "high", "evidence_ids": ["ev-000001"], "source_kind": "external_tool", "recommendation": "upgrade", "requires_human_decision": False}],
    }
    validate_sample(schema("risk_findings.schema.json"), valid)
    invalid = {**valid, "findings": [{**valid["findings"][0], "source_kind": "heuristic"}]}
    assert_invalid(schema("risk_findings.schema.json"), invalid)
    assert_invalid(schema("risk_findings.schema.json"), {**valid, "promotion_policy": "promote_heuristics"})
    assert_invalid(schema("risk_findings.schema.json"), {key: value for key, value in valid.items() if key != "promotion_policy"})
    assert_invalid(schema("risk_findings.schema.json"), {key: value for key, value in valid.items() if key != "source_tools"})


def test_suspicious_schema_rejects_extra_keys_and_requires_recommendation() -> None:
    valid_behavior = {"behavior_id": "susp-1", "kind": "eval", "evidence_ids": ["ev-000001"], "severity": "high", "confidence": "medium", "source": "heuristic", "recommendation": "avoid eval"}
    suspicious_schema = schema("suspicious_behaviors.schema.json")
    validate_sample(suspicious_schema, {"schema_version": "1.0", "behaviors": [valid_behavior]})
    assert_invalid(suspicious_schema, {"schema_version": "1.0", "behaviors": [{key: value for key, value in valid_behavior.items() if key != "recommendation"}]})
    assert_invalid(suspicious_schema, {"schema_version": "1.0", "behaviors": [{**valid_behavior, "unexpected": "field"}]})


def test_reuse_schema_requires_plan_decision_enum_and_human_gate() -> None:
    valid_card = {
        "reuse_id": "reuse-1",
        "candidate_id": "candidate-1",
        "name": "Indexer",
        "problem_solved": "search",
        "files": ["a.py"],
        "license_status": "unknown",
        "target_context": {"allowed_languages": ["*"]},
        "recommendation": "study",
        "decision": "pending",
        "requires_human_decision": True,
        "legal_caveat": "review",
        "security_caveat": "review",
        "performance_caveat": "static signal",
        "score_inputs": {},
        "evidence_ids": ["ev-000001"],
    }
    valid = {"schema_version": "1.0", "target_context": {"allowed_languages": ["*"]}, "scoring_input_sources": {"target_context": "RUN_CONFIG.json"}, "cards": [valid_card]}
    validate_sample(schema("reuse_cards.schema.json"), valid)
    assert_invalid(schema("reuse_cards.schema.json"), {"schema_version": "1.0", "target_context": {"allowed_languages": ["*"]}, "scoring_input_sources": {"target_context": "RUN_CONFIG.json"}, "cards": [{**valid_card, "recommendation": "needs_review"}]})
    assert_invalid(schema("reuse_cards.schema.json"), {"schema_version": "1.0", "target_context": {"allowed_languages": ["*"]}, "scoring_input_sources": {"target_context": "RUN_CONFIG.json"}, "cards": [{**valid_card, "decision": "study"}]})
    invalid_missing_gate = {**valid_card}
    invalid_missing_gate.pop("requires_human_decision")
    assert_invalid(schema("reuse_cards.schema.json"), {"schema_version": "1.0", "target_context": {"allowed_languages": ["*"]}, "scoring_input_sources": {"target_context": "RUN_CONFIG.json"}, "cards": [invalid_missing_gate]})


@pytest.mark.parametrize(
    ("schema_name", "sample"),
    [
        (
            "file_index.schema.json",
            {
                "schema_version": "1.0",
                "run_id": "run-1",
                "repo": {"path": "."},
                "generated_at": "2026-05-29T00:00:00Z",
                "source_artifacts": ["RUN_CONFIG.json"],
                "records": [{"path": "a.py", "path_normalized": "a.py", "size_bytes": 1, "sha256": "abc", "extension": ".py", "language": "py", "kind": "code", "binary": False}],
                "skipped": False,
                "skip_reason": None,
                "skipped_paths": [{"path": ".git/config", "reason": "excluded by .git/**"}],
                "root_documents": [{"name": "README", "status": "missing", "path": None}],
            },
        ),
        (
            "provenance.schema.json",
            {
                "schema_version": "1.0",
                "run_id": "run-1",
                "repo": {"path": "."},
                "generated_at": "2026-05-29T00:00:00Z",
                "source_artifacts": ["RUN_CONFIG.json", "FILE_INDEX.json"],
                "records": [{"kind": "git"}, {"kind": "github"}],
                "skipped": False,
                "skip_reason": None,
                "git": {"status": "skipped", "target_path": ".", "repo_root": ".", "commit": None, "branch": None, "dirty": None, "tracked_file_count": 0, "remotes": [], "tags": [], "submodules": [], "commands": [], "limitations": ["no git"]},
                "github": {"target": None, "auth_mode": "manual-local", "metadata_status": "skipped_or_deferred"},
            },
        ),
        (
            "manifests.schema.json",
            {
                "schema_version": "1.0",
                "run_id": "run-1",
                "repo": {"path": "."},
                "source_artifacts": ["FILE_INDEX.json", "EVIDENCE_INDEX.json"],
                "skipped": False,
                "skip_reason": None,
                "records": [{"path": "package.json", "skipped": False, "skip_reason": None, "evidence_ids": ["ev-000001"], "ecosystem": "javascript", "package_name": "fixture", "build_system": "npm", "dependencies": [{"name": "express", "specifier": "^4", "scope": "dependencies"}], "scripts": [{"command": "npm test", "category": "test", "source": "package.json:scripts.test", "origin": "target_repo_manifest", "policy_decision": "block", "policy_rule": "target_repo_manifest_no_exec", "label": "observed, not executed"}], "lockfiles": []}],
            },
        ),
        ("suspicious_behaviors.schema.json", {"schema_version": "1.0", "behaviors": [{"behavior_id": "susp-1", "kind": "eval", "evidence_ids": ["ev-000001"], "severity": "high", "confidence": "medium", "source": "heuristic", "recommendation": "avoid eval"}]}),
        ("agentic_security_finding.schema.json", {"schema_version": "1.0", "findings": [{"finding_id": "agentic-1", "code": "W015", "target": "AGENTS.md", "severity": "medium", "confidence": "high", "evidence_ids": ["ev-000001"], "recommendation": "sanitize"}]}),
        ("license_cards.schema.json", {"schema_version": "1.0", "cards": [{"card_id": "lic-1", "kind": "file", "declared_license": "MIT", "confidence": "medium", "detection_method": "spdx_header", "requires_human_decision": False, "evidence_ids": ["ev-000001"]}]}),
        ("reuse_cards.schema.json", {"schema_version": "1.0", "target_context": {"allowed_languages": ["python"]}, "scoring_input_sources": {"special_implementations": "SPECIAL_IMPLEMENTATIONS.json"}, "cards": [{"reuse_id": "reuse-1", "candidate_id": "candidate-1", "name": "Indexer", "problem_solved": "search", "files": ["a.py"], "license_status": "needs_review", "target_context": {"allowed_languages": ["python"]}, "recommendation": "study", "decision": "pending", "requires_human_decision": True, "legal_caveat": "review", "security_caveat": "review", "performance_caveat": "static", "score_inputs": {}, "evidence_ids": ["ev-000001"]}]}),
        ("scientific_provenance.schema.json", {"schema_version": "1.0", "records": [{"record_id": "sci-1", "category": "tool_version", "observed_value": {"tool": "nextflow"}, "evidence_ids": ["ev-000001"], "confidence": "high", "detection_method": "manifest_or_lockfile", "requires_human_decision": False}]}),
        ("project_telemetry.schema.json", {"schema_version": "1.0", "records": [{"telemetry_id": "tel-000001", "category": "release_cadence", "status": "skipped", "parameters": {"time_window_days": 365, "from_ref": None, "to_ref": None, "bot_filter": "n/a", "identity_normalization": "n/a"}, "value": None, "evidence_ids": [], "source": "git_tags", "confidence": "low", "limitations": ["no git"]}]}),
        (
            "audit_runtime_metrics.schema.json",
            {
                "schema_version": "1.0",
                "run_id": "run-1",
                "phase_durations_ms": {"inventory": {"duration_ms": 1}, "manifest": 2, "skipped_phase": {"skipped_reason": "not run"}},
                "files_processed": 0,
                "bytes_processed": 0,
                "output_bytes": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "tool_failures": 0,
                "memory_peak": {"status": "skipped", "skipped_reason": "portable path"},
                "token_proxy": {"bytes_read": 0, "estimated_tokens": 0, "bytes_sent_to_agent": 0},
            },
        ),
        ("binary_artifacts.schema.json", {"schema_version": "1.0", "artifacts": [{"artifact_id": "bin-1", "path": "a.dll", "kind": "native_binary", "size_bytes": 1, "triage_triggered": True, "requires_operator_consent": True, "evidence_ids": ["ev-000001"]}], "summary": {"blob_count": 1, "total_binary_bytes": 1, "native_binary_count": 1, "mime_mismatch_count": 0}}),
        ("corpus_index.schema.json", {"schema_version": "1.0", "run_id": "run-1", "database_path": "CORPUS.sqlite", "skipped": False, "skip_reason": None, "table_counts": {"files": 1, "symbols": 1, "evidence": 1, "claims": 0, "graph_nodes": 1, "graph_edges": 1, "wiki_pages": 0}, "source_artifact_hashes": {"FILE_INDEX.json": "abc"}, "no_secret_check": {"status": "pass", "raw_secret_like_rows": 0, "redacted_tokens": 0}, "rrf": {"k": 60, "weights": {"fts": 1.0, "symbol": 1.0, "graph": 1.0, "manifest": 1.0}, "override": False, "override_keys": []}}),
        ("core_envelope.schema.json", {"schema_version": "1.0", "run_id": "run-1", "repo": {}, "generated_at": "2026-05-23T00:00:00Z", "source_artifacts": [], "records": [], "skipped": False, "skip_reason": None}),
    ],
)
def test_domain_schema_samples_validate(schema_name: str, sample: dict) -> None:
    validate_sample(schema(schema_name), sample)


def test_runtime_metrics_schema_matches_validator_contract() -> None:
    runtime_schema = schema("audit_runtime_metrics.schema.json")
    valid = {
        "schema_version": "1.0",
        "run_id": "run-1",
        "phase_durations_ms": {"inventory": {"duration_ms": 1}, "manifest": 2, "skipped_phase": {"skipped_reason": "not run"}},
        "files_processed": 1,
        "bytes_processed": 10,
        "output_bytes": 5,
        "cache_hits": 0,
        "cache_misses": 0,
        "tool_failures": 0,
        "memory_peak": {"status": "skipped", "skipped_reason": "portable path"},
        "token_proxy": {"bytes_read": 10, "estimated_tokens": 2, "bytes_sent_to_agent": 0},
    }
    validate_sample(runtime_schema, valid)
    assert_invalid(runtime_schema, {key: value for key, value in valid.items() if key != "token_proxy"})
    assert_invalid(runtime_schema, {**valid, "phase_durations_ms": {"inventory": {"value": 1}}})
    assert_invalid(runtime_schema, {**valid, "memory_peak": {"status": "observed"}})
    assert_invalid(runtime_schema, {**valid, "token_proxy": {"bytes_read": 10, "estimated_tokens": 2}})


def test_adapter_decision_required_keys_and_enum() -> None:
    valid = {
        "adapter_id": "graphify",
        "installability": {"os": ["Windows"], "notes": "manual install"},
        "license": {"spdx": "MIT", "compatible_with_target_context": True},
        "version_pinning": {"strategy": "minimum", "min_version": "1.0.0"},
        "command_readonly": "graphify --version",
        "policy_applied": ["no-exec", "read-only"],
        "schema_output_observed": {"sample_path": "samples/graph.json", "hash": "abc"},
        "fallback": "canonical graph",
        "decision": "defer",
        "reviewer": "Nash",
        "decision_date": "2026-05-23",
    }
    validate_sample(schema("adapter_decision.schema.json"), valid)
    missing = dict(valid)
    missing.pop("decision")
    assert_invalid(schema("adapter_decision.schema.json"), missing)
    invalid = dict(valid)
    invalid["decision"] = "heuristic"
    assert_invalid(schema("adapter_decision.schema.json"), invalid)
    missing_nested = dict(valid)
    missing_nested["installability"] = {"os": ["Windows"]}
    assert_invalid(schema("adapter_decision.schema.json"), missing_nested)


def test_tool_status_tool_records_reject_unknown_fields() -> None:
    valid_tool = {"tool": "graphify", "status": "completed", "policy": "allowed", "available": True, "notes": ["ok"]}
    validate_sample(schema("tool_status.schema.json"), {"schema_version": "1.0", "tools": [valid_tool]})
    assert_invalid(schema("tool_status.schema.json"), {"schema_version": "1.0", "tools": [{**valid_tool, "unexpected": "drift"}]})


def test_corpus_index_nested_contracts_reject_unknown_fields() -> None:
    valid = {
        "schema_version": "1.0",
        "run_id": "run-1",
        "database_path": "CORPUS.sqlite",
        "skipped": False,
        "skip_reason": None,
        "table_counts": {"files": 1, "symbols": 1, "evidence": 1, "claims": 0, "graph_nodes": 1, "graph_edges": 1, "wiki_pages": 0},
        "source_artifact_hashes": {"FILE_INDEX.json": "abc"},
        "no_secret_check": {"status": "pass", "raw_secret_like_rows": 0, "redacted_tokens": 0},
        "rrf": {"k": 60, "weights": {"fts": 1.0, "symbol": 1.0, "graph": 1.0, "manifest": 1.0}, "override": False, "override_keys": []},
    }
    validate_sample(schema("corpus_index.schema.json"), valid)
    assert_invalid(schema("corpus_index.schema.json"), {**valid, "table_counts": {**valid["table_counts"], "extra": 1}})
    assert_invalid(schema("corpus_index.schema.json"), {**valid, "no_secret_check": {**valid["no_secret_check"], "secret": "raw"}})
    assert_invalid(schema("corpus_index.schema.json"), {**valid, "rrf": {**valid["rrf"], "extra": True}})
    assert_invalid(schema("corpus_index.schema.json"), {**valid, "rrf": {**valid["rrf"], "weights": {**valid["rrf"]["weights"], "extra": 0.5}}})


def test_project_telemetry_skipped_requires_limitations() -> None:
    valid = {"schema_version": "1.0", "records": [{"telemetry_id": "tel-000001", "category": "release_cadence", "status": "skipped", "parameters": {"time_window_days": 365, "from_ref": None, "to_ref": None, "bot_filter": "n/a", "identity_normalization": "n/a"}, "value": None, "evidence_ids": [], "source": "git_tags", "confidence": "low", "limitations": ["no git"]}]}
    validate_sample(schema("project_telemetry.schema.json"), valid)
    invalid = {"schema_version": "1.0", "records": [{**valid["records"][0], "limitations": []}]}
    assert_invalid(schema("project_telemetry.schema.json"), invalid)


def test_project_telemetry_records_reject_drift_and_duplicate_lists() -> None:
    valid_record = {
        "telemetry_id": "tel-000001",
        "category": "release_cadence",
        "status": "observed",
        "parameters": {"time_window_days": 365, "from_ref": "v1", "to_ref": "v2", "bot_filter": "n/a", "identity_normalization": "n/a"},
        "value": {"tags": 2},
        "evidence_ids": ["ev-000001", "ev-000002"],
        "source": "git_tags",
        "confidence": "medium",
        "limitations": ["tag-only"],
    }
    telemetry_schema = schema("project_telemetry.schema.json")
    validate_sample(telemetry_schema, {"schema_version": "1.0", "records": [valid_record]})
    assert_invalid(telemetry_schema, {"schema_version": "1.0", "records": [{**valid_record, "telemetry_id": "tel-1"}]})
    assert_invalid(telemetry_schema, {"schema_version": "1.0", "records": [{**valid_record, "telemetry_id": "tel-1000000"}]})
    assert_invalid(telemetry_schema, {"schema_version": "1.0", "records": [{**valid_record, "evidence_ids": ["ev-000001", "ev-000001"]}]})
    assert_invalid(telemetry_schema, {"schema_version": "1.0", "records": [{**valid_record, "limitations": ["tag-only", "tag-only"]}]})
    assert_invalid(telemetry_schema, {"schema_version": "1.0", "records": [{**valid_record, "extra": "drift"}]})


def test_scientific_provenance_records_require_evidence() -> None:
    valid = {"schema_version": "1.0", "records": [{"record_id": "sci-1", "category": "tool_version", "observed_value": {"tool": "nextflow"}, "evidence_ids": ["ev-000001"], "confidence": "high", "detection_method": "manifest_or_lockfile", "requires_human_decision": False}]}
    validate_sample(schema("scientific_provenance.schema.json"), valid)
    invalid = {"schema_version": "1.0", "records": [{**valid["records"][0], "evidence_ids": []}]}
    assert_invalid(schema("scientific_provenance.schema.json"), invalid)


def test_schema_evidence_ids_reject_short_or_malformed_values() -> None:
    risk_schema = schema("risk_findings.schema.json")
    valid_finding = {"finding_id": "risk-1", "category": "dependency_cve", "severity": "high", "confidence": "high", "evidence_ids": ["ev-000001"], "source_kind": "external_tool", "recommendation": "upgrade", "requires_human_decision": False}
    valid = {
        "schema_version": "1.0",
        "promotion_policy": "heuristics_not_promoted_without_external_tool_confirmation",
        "source_tools": [],
        "findings": [valid_finding],
    }

    for bad_id in ["ev-1", "not-evidence"]:
        assert_invalid(risk_schema, {**valid, "findings": [{**valid_finding, "evidence_ids": [bad_id]}]})


def test_run_config_schema_registered_and_accepts_legacy_and_launch_surface_shape() -> None:
    # The RUN_CONFIG.json artifact is validated against run_config.schema.json (superseding
    # audit_config). The registry must load it (models.SCHEMA_FILES) and the artifact mapping
    # must repoint to it. Numeric-tuple launch_surface presence logic is the validator's job
    # (S-B03); here we only assert the schema SHAPE accepts legacy and 1.1 documents.
    registry = load_schema_registry()
    run_config_schema = registry["run_config"].schema  # KeyError (RED) until SCHEMA_FILES carries run_config
    Draft202012Validator.check_schema(run_config_schema)
    assert SCHEMA_BY_ARTIFACT_KEY["RUN_CONFIG"] == "run_config"

    base = {
        "repo": {"kind": "local", "path": ".", "github": None},
        "profile": "standard",
        "mode": "source-audit",
        "output_dir": "audit",
        "target_context": "MIT downstream",
        "binary_triage_consent": False,
    }
    # Legacy output: no schema_version at all (validator infers legacy; the schema accepts the shape).
    validate_sample(run_config_schema, dict(base))
    # Legacy output: explicit schema_version "1.0".
    validate_sample(run_config_schema, {**base, "schema_version": "1.0"})
    # Current output: schema_version "1.1" with a fully-formed launch_surface object.
    validate_sample(
        run_config_schema,
        {
            **base,
            "schema_version": "1.1",
            "launch_surface": {
                "adapter": "cli",
                "adapter_version": "0.1.0",
                "entry_command": "deep-audit run",
                "host_os": "linux",
                "cwd_policy": "package-root",
            },
        },
    )
