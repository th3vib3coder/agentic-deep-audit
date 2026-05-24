"""Phase 7 performance, quality, test and runtime signal generation."""

from __future__ import annotations

import ast
import json
import platform
import re
import time
from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS
from .sanitize import sanitize_markdown


BENCHMARK_NAMES = {"bench", "benchmark", "benchmarks", "perf", "performance"}
LINT_CONFIG_NAMES = {".flake8", ".ruff.toml", "ruff.toml", ".eslintrc", ".eslintrc.json", "mypy.ini", "pylintrc", ".pylintrc"}
PHASE_NAMES = ["bootstrap", "inventory", "provenance", "manifest", "graph", "surface", "synthesis", "scientific", "telemetry", "risk_security", "license_binary", "performance_quality"]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def repo_path_from(file_index: dict[str, Any], run_config: dict[str, Any]) -> Path:
    repo = file_index.get("repo") if isinstance(file_index.get("repo"), dict) else {}
    config_repo = run_config.get("repo") if isinstance(run_config.get("repo"), dict) else {}
    return Path(str(repo.get("path") or config_repo.get("path") or ".")).resolve()


def record_path(record: dict[str, Any]) -> str:
    return str(record.get("path_normalized") or record.get("path") or "")


def markdown_cell(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().replace("|", "\\|")


def top_hot_modules(file_index: dict[str, Any], module_graph: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    sizes = {record_path(record): int(record.get("size_bytes") or 0) for record in file_index.get("records", []) if isinstance(record, dict)}
    nodes = {str(node.get("id")): str(node.get("path") or "") for node in module_graph.get("nodes", []) if isinstance(node, dict)}
    rows: list[dict[str, Any]] = []
    for node_id, info in (module_graph.get("centrality") or {}).items():
        if not isinstance(info, dict):
            continue
        path = nodes.get(str(node_id), str(node_id).removeprefix("module:"))
        rows.append({"module": path, "centrality_score": float(info.get("score") or 0.0), "rank": int(info.get("rank") or 0), "size_bytes": sizes.get(path, 0)})
    return sorted(rows, key=lambda item: (int(item["rank"]) or 10**9, -int(item["size_bytes"]), str(item["module"])))[:limit]


def python_function_spans(path: Path) -> list[dict[str, Any]]:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(data)
    except (OSError, SyntaxError):
        return []
    rows: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = int(getattr(node, "lineno", 0))
            end = int(getattr(node, "end_lineno", start))
            rows.append({"name": node.name, "start_line": start, "end_line": end, "line_count": max(0, end - start + 1)})
    return rows


def static_signals(repo_path: Path, file_index: dict[str, Any], evidence_lookup: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    large_files: list[dict[str, Any]] = []
    large_functions: list[dict[str, Any]] = []
    call_sites: list[dict[str, Any]] = []
    for record in file_index.get("records", []):
        if not isinstance(record, dict) or record.get("binary"):
            continue
        path_value = record_path(record)
        kind = str(record.get("kind") or "")
        if kind == "code" and int(record.get("size_bytes") or 0) >= 2048:
            large_files.append({"path": path_value, "size_bytes": int(record.get("size_bytes") or 0), "evidence_ids": [evidence_lookup.get(path_value)] if evidence_lookup.get(path_value) else []})
        source = repo_path / path_value
        if source.suffix.lower() == ".py":
            for function in python_function_spans(source):
                if int(function["line_count"]) >= 20:
                    large_functions.append({**function, "path": path_value, "evidence_ids": [evidence_lookup.get(path_value)] if evidence_lookup.get(path_value) else []})
        if kind != "code" or not source.exists():
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        patterns = {
            "io": r"\b(open|read_text|write_text|read_bytes|write_bytes)\s*\(",
            "network": r"\b(requests\.|httpx\.|fetch\s*\(|urllib\.request|axios\.)",
            "database": r"\b(sqlite3|SELECT\s+|INSERT\s+|UPDATE\s+|DELETE\s+|execute\s*\()",
        }
        for signal, pattern in patterns.items():
            if re.search(pattern, text, flags=re.IGNORECASE):
                call_sites.append({"path": path_value, "signal": signal, "evidence_ids": [evidence_lookup.get(path_value)] if evidence_lookup.get(path_value) else []})
    return {"large_files": large_files, "large_functions": large_functions, "call_sites": call_sites}


def benchmark_files(file_index: dict[str, Any], evidence_lookup: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in file_index.get("records", []):
        if not isinstance(record, dict) or record.get("binary"):
            continue
        path_value = record_path(record)
        lowered = path_value.lower()
        if any(token in lowered for token in BENCHMARK_NAMES):
            rows.append({"path": path_value, "kind": record.get("kind"), "evidence_ids": [evidence_lookup.get(path_value)] if evidence_lookup.get(path_value) else []})
    return rows


def performance_claims(repo_path: Path, file_index: dict[str, Any], evidence_lookup: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = re.compile(r"\b(fast|faster|performance|latency|throughput|requests?/s|req/s|ops/s|benchmark)\b", re.IGNORECASE)
    for record in file_index.get("records", []):
        if not isinstance(record, dict) or record.get("kind") != "docs":
            continue
        path_value = record_path(record)
        source = repo_path / path_value
        if not source.exists():
            continue
        for line_number, line in enumerate(source.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if pattern.search(line):
                sanitized = sanitize_markdown(path_value, line, evidence_id=evidence_lookup.get(path_value))
                rows.append({"path": path_value, "line": line_number, "claim": markdown_cell(sanitized.sanitized_text)[:220], "sanitizer_decision": sanitized.decision, "status": "claim-only", "evidence_ids": [evidence_lookup.get(path_value)] if evidence_lookup.get(path_value) else []})
    return rows


def test_coverage_signal(file_index: dict[str, Any], build_test_map: str, ci_map: dict[str, Any], repo_path: Path, evidence_lookup: dict[str, str]) -> dict[str, Any]:
    test_files = [record_path(record) for record in file_index.get("records", []) if isinstance(record, dict) and record.get("kind") == "test"]
    coverage_files = [record_path(record) for record in file_index.get("records", []) if isinstance(record, dict) and "coverage" in record_path(record).lower()]
    ci_commands = [command for row in ci_map.get("records", []) if isinstance(row, dict) for command in row.get("commands", []) if isinstance(command, dict)]
    numeric: list[dict[str, Any]] = []
    for path_value in coverage_files:
        source = repo_path / path_value
        if source.name.lower() == "coverage.xml" and source.exists():
            match = re.search(r'line-rate="([0-9.]+)"', source.read_text(encoding="utf-8", errors="replace"))
            if match:
                numeric.append({"path": path_value, "coverage_percent": round(float(match.group(1)) * 100, 2), "evidence_ids": [evidence_lookup.get(path_value)] if evidence_lookup.get(path_value) else []})
    return {"test_files": test_files, "coverage_files": coverage_files, "ci_test_command_count": build_test_map.lower().count(" test") + build_test_map.lower().count("pytest"), "ci_commands": len(ci_commands), "numeric_coverage": numeric}


def audit_runtime_metrics(run_config: dict[str, Any], audit_dir: Path, file_index: dict[str, Any], started_at: float) -> dict[str, Any]:
    durations = dict(run_config.get("_phase_durations_ms") or {})
    durations["performance_quality"] = max(0, int((time.perf_counter() - started_at) * 1000))
    phase_entries: dict[str, dict[str, Any]] = {}
    for phase in PHASE_NAMES:
        if phase in durations:
            phase_entries[phase] = {"duration_ms": int(durations[phase])}
        else:
            phase_entries[phase] = {"skipped_reason": "phase duration not instrumented for this command"}
    records = [record for record in file_index.get("records", []) if isinstance(record, dict)]
    output_bytes = sum(path.stat().st_size for path in audit_dir.rglob("*") if path.is_file())
    tool_status = load_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"])
    tool_failures = sum(1 for tool in tool_status.get("tools", []) if isinstance(tool, dict) and tool.get("status") in {"failed", "blocked", "degraded"})
    memory_peak = {"status": "skipped", "skipped_reason": f"peak memory measurement unsupported by deterministic portable path on {platform.system() or 'unknown'}"}
    return {
        "schema_version": "1.0",
        "run_id": str(run_config.get("run_id") or "run-unknown"),
        "phase_durations_ms": phase_entries,
        "files_processed": len(records),
        "bytes_processed": sum(int(record.get("size_bytes") or 0) for record in records),
        "output_bytes": output_bytes,
        "cache_hits": 0,
        "cache_misses": 0,
        "tool_failures": tool_failures,
        "memory_peak": memory_peak,
        "token_proxy": {"bytes_read": sum(int(record.get("size_bytes") or 0) for record in records), "estimated_tokens": sum(int(record.get("size_bytes") or 0) for record in records) // 4, "bytes_sent_to_agent": 0},
        "notes": ["AUDIT_RUNTIME_METRICS.json measures the audit plugin, not the audited project.", "cache stats are zero until a cache backend is introduced"],
    }


def performance_markdown(hot: list[dict[str, Any]], signals: dict[str, list[dict[str, Any]]], benchmarks: list[dict[str, Any]], claims: list[dict[str, Any]]) -> str:
    lines = ["# Performance Review", "", "Scope: audited project performance. Static proxy signals are not runtime benchmarks.", "", "## Hot Modules Static Proxy", "", "| Rank | Module | Centrality | Size Bytes |", "|---:|---|---:|---:|"]
    if hot:
        lines.extend(f"| {row['rank']} | `{row['module']}` | {row['centrality_score']:.3f} | {row['size_bytes']} |" for row in hot)
    else:
        lines.append("|  |  |  |  |")
    lines.extend(["", "## Existing Benchmarks", "", "| Path | Evidence |", "|---|---|"])
    if benchmarks:
        lines.extend(f"| `{row['path']}` | {', '.join(row['evidence_ids']) or 'none'} |" for row in benchmarks)
    else:
        lines.append("|  | none observed |")
    lines.extend(["", "## Static Performance Proxies", "", "- Cyclomatic complexity: skipped because no promoted complexity adapter is available; not guessed.", f"- Large files: {len(signals['large_files'])}.", f"- Large functions: {len(signals['large_functions'])}.", f"- I/O, network or database call-site files: {len(signals['call_sites'])}.", "", "## Performance Claims From Docs", "", "| Path | Line | Status | Evidence | Claim |", "|---|---:|---|---|---|"])
    if claims:
        lines.extend(f"| `{row['path']}` | {row['line']} | {row['status']}:{row.get('sanitizer_decision', 'pass')} | {', '.join(row['evidence_ids']) or 'none'} | {row['claim']} |" for row in claims)
    else:
        lines.append("|  |  | none observed |  |  |")
    lines.extend(["", "Caveat: static proxies identify review targets only; they are never described as observed runtime benchmark results.", ""])
    return "\n".join(lines)


def quality_markdown(file_index: dict[str, Any], ci_map: dict[str, Any], telemetry: dict[str, Any], risk: dict[str, Any], coverage: dict[str, Any]) -> str:
    records = [record for record in file_index.get("records", []) if isinstance(record, dict)]
    docs = sum(1 for record in records if record.get("kind") == "docs")
    lint_configs = [record_path(record) for record in records if Path(record_path(record)).name.lower() in LINT_CONFIG_NAMES]
    risk_count = len(risk.get("findings", [])) if isinstance(risk.get("findings"), list) else 0
    observed_telemetry = sum(1 for record in telemetry.get("records", []) if isinstance(record, dict) and record.get("status") == "observed")
    score_parts = [bool(coverage["test_files"]), bool(coverage["ci_commands"]), bool(lint_configs), docs > 0, risk_count == 0]
    score = sum(1 for item in score_parts if item)
    return "\n".join([
        "# Quality Review",
        "",
        "Caveat: this is an evidence-weighted quality signal, not a production readiness score.",
        "",
        f"- Evidence-weighted quality signal: {score}/5.",
        f"- Test files observed: {len(coverage['test_files'])}.",
        f"- CI commands observed: {coverage['ci_commands']}.",
        f"- Lint/static config files observed: {len(lint_configs)}.",
        f"- Documentation files observed: {docs}.",
        f"- Risk findings observed: {risk_count}.",
        f"- Telemetry categories observed: {observed_telemetry}.",
        "",
    ])


def coverage_markdown(coverage: dict[str, Any]) -> str:
    lines = ["# Test Coverage Signal", "", "Observed test evidence only. No runtime coverage percentage is claimed unless a coverage artifact is present.", "", f"- Test files observed: {len(coverage['test_files'])}.", f"- Coverage artifact files observed: {len(coverage['coverage_files'])}.", f"- CI/test command signal count: {coverage['ci_test_command_count']}.", "", "## Numeric Coverage", ""]
    if coverage["numeric_coverage"]:
        lines.extend(f"- {row['coverage_percent']}% from `{row['path']}` ({', '.join(row['evidence_ids']) or 'no evidence id'})." for row in coverage["numeric_coverage"])
    else:
        lines.append("- Skipped: no coverage artifact with machine-readable numeric value was observed.")
    lines.append("")
    return "\n".join(lines)


def run_performance_quality(run_config: dict[str, Any], audit_dir: Path) -> None:
    started = time.perf_counter()
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    ci_map = load_json(audit_dir / ARTIFACT_PATHS["CI_MAP"])
    telemetry = load_json(audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY"])
    risk = load_json(audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"])
    build_test_map = (audit_dir / ARTIFACT_PATHS["BUILD_TEST_MAP"]).read_text(encoding="utf-8") if (audit_dir / ARTIFACT_PATHS["BUILD_TEST_MAP"]).exists() else ""
    repo_path = repo_path_from(file_index, run_config)
    evidence_lookup = evidence_by_path(audit_dir)
    hot = top_hot_modules(file_index, module_graph)
    signals = static_signals(repo_path, file_index, evidence_lookup)
    benchmarks = benchmark_files(file_index, evidence_lookup)
    claims = performance_claims(repo_path, file_index, evidence_lookup)
    coverage = test_coverage_signal(file_index, build_test_map, ci_map, repo_path, evidence_lookup)
    (audit_dir / ARTIFACT_PATHS["PERFORMANCE_REVIEW"]).write_text(performance_markdown(hot, signals, benchmarks, claims), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["QUALITY_REVIEW"]).write_text(quality_markdown(file_index, ci_map, telemetry, risk, coverage), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"]).write_text(coverage_markdown(coverage), encoding="utf-8")
    write_json(audit_dir / ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"], audit_runtime_metrics(run_config, audit_dir, file_index, started))
