from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import agentic_deep_audit.audit_graph_renderers as graph_renderers
from agentic_deep_audit.audit_graph_renderers import write_graphify_outputs
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


def copy_fixture(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def run_fixture(tmp_path: Path, name: str, command: str = "run", *extra_args: str) -> Path:
    repo = copy_fixture(tmp_path, name)
    config = repo / "audit.config.yaml"
    if not config.exists():
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
                    'output_dir: "audit"',
                    "scope_filters:",
                    '  include: ["**/*"]',
                    '  exclude: [".git/**", "node_modules/**"]',
                    'target_context: "MIT downstream"',
                    "binary_triage_consent: false",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    result = run_cli(command, "--config", str(config), *extra_args, cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo / "audit"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_builtin_html_renderer_escapes_node_labels(tmp_path: Path) -> None:
    graph = {
        "nodes": [{"id": "n1<script>", "type": "module", "label": "<script>alert(1)</script>"}],
        "edges": [{"source": "n1<script>", "target": "n1<script>", "type": "<img src=x onerror=alert(1)>"}],
    }

    path = graph_renderers.write_builtin_html(tmp_path, graph)
    text = path.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "Content-Security-Policy" in text


def test_mermaid_renderer_escapes_quotes_brackets_bidi_and_fence_breaks() -> None:
    graph = {"nodes": [{"id": "n1", "label": 'evil"]\n```html\n<script>x</script>\u202e'}], "edges": []}

    lines = graph_renderers.mermaid_lines(graph)
    text = "\n".join(lines)

    assert 'evil"]' not in text
    assert "&#93;" in text
    assert "\u202e" not in text
    assert "```html" not in text
    assert "<script>" not in text
    assert "&lt;script&gt;x&lt;/script&gt;" in text


def test_run_exports_full_canonical_graph_after_wiki_and_reuse(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])
    nodes = graph["nodes"]
    edges = graph["edges"]
    node_types = {node["type"] for node in nodes}
    source_artifacts = set(graph["derivations"]["source_artifacts"])

    assert {"repo", "module", "symbol", "feature", "pattern", "reuse", "artifact"} <= node_types
    assert ARTIFACT_PATHS["FEATURE_CATALOG"] in source_artifacts
    assert ARTIFACT_PATHS["PATTERNS"] in source_artifacts
    assert ARTIFACT_PATHS["REUSE_CARDS"] in source_artifacts
    assert ARTIFACT_PATHS["MANIFESTS"] in source_artifacts
    assert any(path.startswith("wiki/") for path in source_artifacts)
    assert any(edge["type"] == "documents" for edge in edges)
    assert any(edge["type"] == "implements" for edge in edges)
    assert any(edge["type"] == "reuses" for edge in edges)
    assert (audit_dir / ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"]).exists()
    assert (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).exists()
    assert not (audit_dir / "graph" / "GRAPH_HTML_SKIPPED.md").exists()
    assert not (audit_dir / "graphify" / "GRAPHIFY_SKIPPED.md").exists()

    node_export = load_json(audit_dir / ARTIFACT_PATHS["GRAPH_NODES"])
    edge_export = load_json(audit_dir / ARTIFACT_PATHS["GRAPH_EDGES"])
    assert {json.dumps(node, sort_keys=True) for node in node_export["nodes"]} == {json.dumps(node, sort_keys=True) for node in nodes}
    assert {json.dumps(edge, sort_keys=True) for edge in edge_export["edges"]} == {json.dumps(edge, sort_keys=True) for edge in edges}
    assert validate_audit(audit_dir).ok


def test_canonical_graph_preserves_external_packages_as_artifacts(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", command="graph")
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])
    package = next(node for node in graph["nodes"] if node["id"] == "package:json")

    assert package["type"] == "artifact"
    assert package["artifact_kind"] == "package"
    assert any(edge["target"] == "package:json" and edge["type"] == "depends_on" for edge in graph["edges"])
    assert validate_audit(audit_dir).ok


def test_builtin_renderer_emits_html_and_status_consistency_is_validated(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", "graph", "--renderer", "builtin")
    html = audit_dir / ARTIFACT_PATHS["GRAPH_HTML"]

    assert html.exists()
    assert "Canonical Graph" in html.read_text(encoding="utf-8")
    assert not (audit_dir / ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"]).exists()
    assert validate_audit(audit_dir).ok

    status_path = audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]
    status = load_json(status_path)
    for tool in status["tools"]:
        if tool.get("tool") == "graph_html_renderer":
            tool["status"] = "skipped"
            tool["skipped_reason"] = "stale skip"
    write_json(status_path, status)
    broken = validate_audit(audit_dir)
    assert not broken.ok
    assert any("graph_html_renderer status must be completed" in error for error in broken.errors)


def test_run_exports_risk_nodes_in_late_canonical_graph(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "mixed_risky")
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])

    assert any(node["type"] == "risk" for node in graph["nodes"])
    assert any(edge["type"] == "risks" for edge in graph["edges"])
    assert validate_audit(audit_dir).ok


def test_graph_validator_rejects_missing_late_source_coverage(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    nodes_path = audit_dir / ARTIFACT_PATHS["GRAPH_NODES"]
    edges_path = audit_dir / ARTIFACT_PATHS["GRAPH_EDGES"]
    graph = load_json(graph_path)

    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node.get("type") not in {"feature", "pattern", "reuse"}
        and node.get("artifact_kind") not in {"wiki_page", "dependency"}
    ]
    graph["derivations"]["source_artifacts"] = [
        source
        for source in graph["derivations"]["source_artifacts"]
        if source not in {ARTIFACT_PATHS["FEATURE_CATALOG"], ARTIFACT_PATHS["PATTERNS"], ARTIFACT_PATHS["REUSE_CARDS"], ARTIFACT_PATHS["MANIFESTS"]}
        and not source.startswith("wiki/")
    ]
    remaining = {node["id"] for node in graph["nodes"]}
    graph["edges"] = [edge for edge in graph["edges"] if edge["source"] in remaining and edge["target"] in remaining]
    write_json(graph_path, graph)
    write_json(nodes_path, {"schema_version": "1.0", "nodes": graph["nodes"]})
    write_json(edges_path, {"schema_version": "1.0", "edges": graph["edges"]})

    result = validate_audit(audit_dir)
    assert not result.ok
    assert any("missing node type for source FEATURE_CATALOG.md" in error for error in result.errors)
    assert any("missing wiki source artifacts" in error for error in result.errors)


def test_graph_validator_rejects_single_missing_expected_node(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    nodes_path = audit_dir / ARTIFACT_PATHS["GRAPH_NODES"]
    edges_path = audit_dir / ARTIFACT_PATHS["GRAPH_EDGES"]
    graph = load_json(graph_path)
    feature = next(node for node in graph["nodes"] if node["type"] == "feature")

    graph["nodes"] = [node for node in graph["nodes"] if node["id"] != feature["id"]]
    graph["edges"] = [edge for edge in graph["edges"] if edge["source"] != feature["id"] and edge["target"] != feature["id"]]
    write_json(graph_path, graph)
    write_json(nodes_path, {"schema_version": "1.0", "nodes": graph["nodes"]})
    write_json(edges_path, {"schema_version": "1.0", "edges": graph["edges"]})

    result = validate_audit(audit_dir)
    assert not result.ok
    assert any("missing expected graph nodes" in error and feature["id"] in error for error in result.errors)


def test_graph_validator_rejects_missing_expected_edges(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    edges_path = audit_dir / ARTIFACT_PATHS["GRAPH_EDGES"]
    graph = load_json(graph_path)

    graph["edges"] = []
    write_json(graph_path, graph)
    write_json(edges_path, {"schema_version": "1.0", "edges": []})

    result = validate_audit(audit_dir)
    assert not result.ok
    assert any("missing expected graph edges" in error for error in result.errors)


def test_graph_validator_rejects_derived_drift_missing_evidence_and_wrong_skips(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    nodes_path = audit_dir / ARTIFACT_PATHS["GRAPH_NODES"]
    original_graph = load_json(graph_path)
    original_nodes = load_json(nodes_path)

    drifted_nodes = {"schema_version": "1.0", "nodes": original_nodes["nodes"][1:]}
    write_json(nodes_path, drifted_nodes)
    drift_result = validate_audit(audit_dir)
    assert not drift_result.ok
    assert any("does not recompose canonical graph node set" in error for error in drift_result.errors)
    write_json(nodes_path, original_nodes)

    broken_graph = json.loads(json.dumps(original_graph))
    broken_graph["nodes"][0].pop("evidence_ids")
    write_json(graph_path, broken_graph)
    evidence_result = validate_audit(audit_dir)
    assert not evidence_result.ok
    assert any("evidence_ids must be an array" in error for error in evidence_result.errors)
    write_json(graph_path, original_graph)

    wrong_html_skip = audit_dir / "graph" / "GRAPH_HTML_SKIPPED.md"
    wrong_html_skip.write_text("# Wrong\n\nReason: wrong path.\n", encoding="utf-8")
    wrong_html_result = validate_audit(audit_dir)
    assert not wrong_html_result.ok
    assert any("GRAPH_HTML_SKIPPED.md must be emitted at audit root" in error for error in wrong_html_result.errors)
    wrong_html_skip.unlink()

    wrong_graphify_skip = audit_dir / "graphify" / "GRAPHIFY_SKIPPED.md"
    wrong_graphify_skip.parent.mkdir(parents=True, exist_ok=True)
    wrong_graphify_skip.write_text("# Wrong\n\nReason: wrong path.\n", encoding="utf-8")
    wrong_graphify_result = validate_audit(audit_dir)
    assert not wrong_graphify_result.ok
    assert any("GRAPHIFY_SKIPPED.md must be emitted at audit root" in error for error in wrong_graphify_result.errors)


def test_graph_validator_rejects_missing_derived_nodes_export(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    (audit_dir / ARTIFACT_PATHS["GRAPH_NODES"]).unlink()

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("graph/nodes.json" in error for error in result.errors)


def test_graph_validator_rejects_non_object_json_roots(tmp_path: Path) -> None:
    audit_dir = run_fixture(tmp_path, "performance_quality_project")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph_path.write_text("[]\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("root must be object" in error for error in result.errors)


def test_promoted_graphify_writes_isolated_outputs_diff_and_preserves_canonical(tmp_path: Path, monkeypatch) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", command="graph")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = load_json(graph_path)
    original = graph_path.read_text(encoding="utf-8")
    plugin_root = tmp_path / "plugin-root"
    decision_path = plugin_root / "docs" / "adapters" / "graphify" / "adapter_decision.json"
    decision_path.parent.mkdir(parents=True)
    write_json(
        decision_path,
        {
            "adapter_id": "graphify",
            "installability": {"os": ["Windows"], "notes": "fake graphify for test"},
            "license": {"spdx": "MIT", "compatible_with_target_context": True},
            "version_pinning": {"strategy": "system", "min_version": None},
            "command_readonly": "graphify --version",
            "policy_applied": ["no-exec", "read-only", "path-containment"],
            "schema_output_observed": {"sample_path": "samples/graph.json", "hash": "fake"},
            "fallback": "canonical graph",
            "decision": "promote",
            "reviewer": "test",
            "decision_date": "2026-05-23",
        },
    )

    monkeypatch.setenv("GITHUB_TOKEN", "raw-token")

    def fake_run(command, cwd, env, text, encoding, errors, capture_output, check, timeout):
        assert encoding == "utf-8"
        assert errors == "replace"
        assert "GITHUB_TOKEN" not in env
        output = Path(command[4])
        output.parent.mkdir(parents=True, exist_ok=True)
        altered = json.loads(original)
        altered["nodes"].append({"id": "graphify:extra", "type": "artifact", "label": "Graphify extra", "evidence_ids": []})
        write_json(output, altered)
        return subprocess.CompletedProcess(command, 0, stdout="\x1b[31mgraphify ok\x1b[0m\n```html\n<script>x()</script>\n```", stderr="bad\n```\u202e")

    monkeypatch.setattr(graph_renderers, "PLUGIN_ROOT", plugin_root)
    monkeypatch.setattr(graph_renderers.shutil, "which", lambda name: "graphify" if name == "graphify" else None)
    monkeypatch.setattr(graph_renderers.subprocess, "run", fake_run)

    write_graphify_outputs(audit_dir, graph)

    assert graph_path.read_text(encoding="utf-8") == original
    assert (audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]).exists()
    assert (audit_dir / ARTIFACT_PATHS["GRAPHIFY_REPORT"]).exists()
    diff = (audit_dir / ARTIFACT_PATHS["GRAPHIFY_DIFF"]).read_text(encoding="utf-8")
    assert "canonical_sha256" in diff
    assert "graphify_sha256" in diff
    report = (audit_dir / ARTIFACT_PATHS["GRAPHIFY_REPORT"]).read_text(encoding="utf-8")
    assert "\x1b" not in report
    assert "\u202e" not in report
    assert "`\u200b``html" in report
    assert "bad\n`\u200b``" in report
    assert "```html\n<script>x()</script>" not in report
    assert not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).exists()
    assert validate_audit(audit_dir).ok

    (audit_dir / ARTIFACT_PATHS["GRAPHIFY_DIFF"]).unlink()
    missing_diff = validate_audit(audit_dir)
    assert not missing_diff.ok
    assert any("GRAPHIFY_DIFF.md required" in error for error in missing_diff.errors)


def test_promoted_graphify_mutating_canonical_is_restored_and_skipped(tmp_path: Path, monkeypatch) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", command="graph")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = load_json(graph_path)
    original = graph_path.read_text(encoding="utf-8")
    plugin_root = tmp_path / "plugin-root-mutate"
    decision_path = plugin_root / "docs" / "adapters" / "graphify" / "adapter_decision.json"
    decision_path.parent.mkdir(parents=True)
    write_json(
        decision_path,
        {
            "adapter_id": "graphify",
            "installability": {"os": ["Windows"], "notes": "fake graphify for mutation guard"},
            "license": {"spdx": "MIT", "compatible_with_target_context": True},
            "version_pinning": {"strategy": "system", "min_version": None},
            "command_readonly": "graphify --version",
            "policy_applied": ["no-exec", "read-only", "path-containment"],
            "schema_output_observed": {"sample_path": "samples/graph.json", "hash": "fake"},
            "fallback": "canonical graph",
            "decision": "promote",
            "reviewer": "test",
            "decision_date": "2026-05-23",
        },
    )

    def mutating_run(command, cwd, env, text, encoding, errors, capture_output, check, timeout):
        Path(command[2]).write_text('{"mutated": true}\n', encoding="utf-8")
        output = Path(command[4])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('{"schema_version": "1.0", "nodes": [], "edges": []}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="mutated", stderr="")

    monkeypatch.setattr(graph_renderers, "PLUGIN_ROOT", plugin_root)
    monkeypatch.setattr(graph_renderers.shutil, "which", lambda name: "graphify" if name == "graphify" else None)
    monkeypatch.setattr(graph_renderers.subprocess, "run", mutating_run)

    write_graphify_outputs(audit_dir, graph)

    assert graph_path.read_text(encoding="utf-8") == original
    assert not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]).exists()
    assert "attempted to mutate canonical graph" in (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).read_text(encoding="utf-8")
    assert validate_audit(audit_dir).ok


def test_failed_graphify_stderr_cannot_break_skipped_markdown(tmp_path: Path, monkeypatch) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", command="graph")
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])
    plugin_root = tmp_path / "plugin-root-failed-stderr"
    decision_path = plugin_root / "docs" / "adapters" / "graphify" / "adapter_decision.json"
    decision_path.parent.mkdir(parents=True)
    write_json(
        decision_path,
        {
            "adapter_id": "graphify",
            "installability": {"os": ["Windows"], "notes": "fake graphify failure"},
            "license": {"spdx": "MIT", "compatible_with_target_context": True},
            "version_pinning": {"strategy": "system", "min_version": None},
            "command_readonly": "graphify --version",
            "policy_applied": ["no-exec", "read-only", "path-containment"],
            "schema_output_observed": {"sample_path": "samples/graph.json", "hash": "fake"},
            "fallback": "canonical graph",
            "decision": "promote",
            "reviewer": "test",
            "decision_date": "2026-05-23",
        },
    )

    def failing_run(command, cwd, env, text, encoding, errors, capture_output, check, timeout):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="bad\n```html\n<script>x()</script>\n```")

    monkeypatch.setattr(graph_renderers, "PLUGIN_ROOT", plugin_root)
    monkeypatch.setattr(graph_renderers.shutil, "which", lambda name: "graphify" if name == "graphify" else None)
    monkeypatch.setattr(graph_renderers.subprocess, "run", failing_run)

    write_graphify_outputs(audit_dir, graph)

    skipped = (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).read_text(encoding="utf-8")
    assert "bad `\u200b``html <script>x()</script> `\u200b``" in skipped
    assert "```html\n<script>x()</script>" not in skipped
    assert validate_audit(audit_dir).ok


def test_promoted_graphify_deleting_canonical_is_restored_and_skipped(tmp_path: Path, monkeypatch) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", command="graph")
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = load_json(graph_path)
    original = graph_path.read_text(encoding="utf-8")
    plugin_root = tmp_path / "plugin-root-delete"
    decision_path = plugin_root / "docs" / "adapters" / "graphify" / "adapter_decision.json"
    decision_path.parent.mkdir(parents=True)
    write_json(
        decision_path,
        {
            "adapter_id": "graphify",
            "installability": {"os": ["Windows"], "notes": "fake graphify deletion guard"},
            "license": {"spdx": "MIT", "compatible_with_target_context": True},
            "version_pinning": {"strategy": "system", "min_version": None},
            "command_readonly": "graphify --version",
            "policy_applied": ["no-exec", "read-only", "path-containment"],
            "schema_output_observed": {"sample_path": "samples/graph.json", "hash": "fake"},
            "fallback": "canonical graph",
            "decision": "promote",
            "reviewer": "test",
            "decision_date": "2026-05-23",
        },
    )

    def deleting_run(command, cwd, env, text, encoding, errors, capture_output, check, timeout):
        Path(command[2]).unlink()
        output = Path(command[4])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('{"schema_version": "1.0", "nodes": [], "edges": []}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="deleted", stderr="")

    monkeypatch.setattr(graph_renderers, "PLUGIN_ROOT", plugin_root)
    monkeypatch.setattr(graph_renderers.shutil, "which", lambda name: "graphify" if name == "graphify" else None)
    monkeypatch.setattr(graph_renderers.subprocess, "run", deleting_run)

    write_graphify_outputs(audit_dir, graph)

    assert graph_path.read_text(encoding="utf-8") == original
    assert not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]).exists()
    assert "attempted to mutate canonical graph" in (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).read_text(encoding="utf-8")
    assert validate_audit(audit_dir).ok


def test_graphify_disabled_mode_never_invokes_promoted_adapter(tmp_path: Path, monkeypatch) -> None:
    audit_dir = run_fixture(tmp_path, "python_basic", command="graph")
    graph = load_json(audit_dir / ARTIFACT_PATHS["GRAPH"])
    plugin_root = tmp_path / "plugin-root-disabled"
    decision_path = plugin_root / "docs" / "adapters" / "graphify" / "adapter_decision.json"
    decision_path.parent.mkdir(parents=True)
    write_json(
        decision_path,
        {
            "adapter_id": "graphify",
            "installability": {"os": ["Windows"], "notes": "fake graphify disabled"},
            "license": {"spdx": "MIT", "compatible_with_target_context": True},
            "version_pinning": {"strategy": "system", "min_version": None},
            "command_readonly": "graphify --version",
            "policy_applied": ["no-exec", "read-only", "path-containment"],
            "schema_output_observed": {"sample_path": "samples/graph.json", "hash": "fake"},
            "fallback": "canonical graph",
            "decision": "promote",
            "reviewer": "test",
            "decision_date": "2026-05-23",
        },
    )
    monkeypatch.setattr(graph_renderers, "PLUGIN_ROOT", plugin_root)
    monkeypatch.setattr(graph_renderers.shutil, "which", lambda name: "graphify")
    monkeypatch.setattr(graph_renderers.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("graphify must not run")))

    write_graphify_outputs(audit_dir, graph, {"graph": {"graphify": "disabled"}})

    assert "disabled by run configuration" in (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).read_text(encoding="utf-8")
    assert not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]).exists()
    assert validate_audit(audit_dir).ok
