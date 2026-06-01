"""Command line interface for Agentic Deep Audit."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable

from .audit_inventory import run_inventory
from .audit_canonical_graph import run_canonical_graph_outputs
from .audit_corpus import run_corpus
from .audit_license_binary import run_license_binary
from .audit_graph import run_graph
from .audit_manifest import run_manifest
from .audit_mcp_export import run_mcp_export
from .audit_provenance import run_provenance
from .audit_quality import run_performance_quality
from .audit_report import completion_ready, generate_report_artifacts, remove_stale_review_packet
from .audit_reuse import run_reuse
from .audit_risk import run_risk_security
from .audit_scientific import run_scientific_provenance
from .audit_surface import run_surface
from .audit_synthesis import run_synthesis
from .audit_telemetry import run_project_telemetry
from .audit_validate import validate_audit
from .audit_wiki import run_wiki
from .bootstrap import bootstrap_audit
from .config import ArgvOverrides, ConfigError, load_config_file, load_run_config, normalize_run_config
from .models import ARTIFACT_PATHS
from .validation_report import write_validation_report


CONFIG_COMMANDS = {"run", "inventory", "graph", "surface", "synthesis", "scientific", "telemetry", "risk", "wiki"}
URL_COMMAND = "url"
ALL_COMMANDS = ["run", "inventory", "graph", "surface", "synthesis", "scientific", "telemetry", "risk", "wiki", "validate", URL_COMMAND]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agentic_deep_audit.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in CONFIG_COMMANDS:
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--config")
        subparser.add_argument("--run-config")
        subparser.add_argument("--profile")
        subparser.add_argument("--output-dir")
        subparser.add_argument("--allowed-root", action="append", default=[])
        subparser.add_argument("--allow-system-roots", action="store_true")
        subparser.add_argument("--dry-run", action="store_true")
        if command == "graph":
            subparser.add_argument("--renderer")
            subparser.add_argument("--graphify", action="store_true")
            subparser.add_argument("--graph-centrality")
        if command == "risk":
            subparser.add_argument("--network-policy")
        if command == "wiki":
            subparser.add_argument("--graph-source")
    validate = subparsers.add_parser("validate")
    validate.add_argument("--audit-dir", required=True)
    validate.add_argument("--profile")
    validate.add_argument("--dry-run", action="store_true")
    url = subparsers.add_parser(
        URL_COMMAND,
        help="Clone a GitHub repository and run the deep audit pipeline.",
        description=(
            "Validate a GitHub HTTPS URL, clone it to a sandbox path, generate "
            "a minimal audit config, and invoke the existing run pipeline."
        ),
    )
    url.add_argument("url", help="https://github.com/<owner>/<repo>")
    url.add_argument("--output-dir", help="Defaults to ./audit_runs/<safe_repo_name>/")
    url.add_argument(
        "--profile",
        default="standard",
        choices=["minimal", "standard", "extended", "research"],
    )
    url.add_argument("--allowed-root", action="append", default=[])
    url.add_argument("--dry-run", action="store_true")
    url.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Clone timeout in seconds. Default: 300.",
    )
    return parser


def planned_artifacts(command: str) -> list[str]:
    base = [ARTIFACT_PATHS["RUN_CONFIG"], ARTIFACT_PATHS["TOOL_STATUS"], ARTIFACT_PATHS["PROGRESS"]]
    by_command = {
        "run": [
            ARTIFACT_PATHS["FILE_INDEX"],
            ARTIFACT_PATHS["INVENTORY"],
            ARTIFACT_PATHS["EVIDENCE_INDEX"],
            ARTIFACT_PATHS["PROVENANCE"],
            ARTIFACT_PATHS["MANIFESTS"],
            ARTIFACT_PATHS["BUILD_TEST_MAP"],
            ARTIFACT_PATHS["CI_MAP"],
            ARTIFACT_PATHS["MODULE_GRAPH"],
            ARTIFACT_PATHS["SYMBOL_INDEX"],
            ARTIFACT_PATHS["GRAPH"],
            ARTIFACT_PATHS["GRAPH_NODES"],
            ARTIFACT_PATHS["GRAPH_EDGES"],
            ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"],
            ARTIFACT_PATHS["GRAPHIFY_SKIPPED"],
            ARTIFACT_PATHS["API_SURFACE"],
            ARTIFACT_PATHS["CLI_SURFACE"],
            ARTIFACT_PATHS["MCP_SURFACE"],
            ARTIFACT_PATHS["CONFIG_SURFACE"],
            ARTIFACT_PATHS["ARCHITECTURE"],
            ARTIFACT_PATHS["FEATURE_CATALOG"],
            ARTIFACT_PATHS["PATTERNS"],
            ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"],
            ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"],
            ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"],
            ARTIFACT_PATHS["PROJECT_TELEMETRY"],
            ARTIFACT_PATHS["PROJECT_TELEMETRY_MD"],
            ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"],
            ARTIFACT_PATHS["RISK_FINDINGS"],
            ARTIFACT_PATHS["AGENTIC_SECURITY_FINDINGS"],
            ARTIFACT_PATHS["AGENTIC_SECURITY"],
            ARTIFACT_PATHS["SUPPLY_CHAIN_SIGNALS"],
            ARTIFACT_PATHS["RISK_REPORT"],
            ARTIFACT_PATHS["LICENSE_CARDS"],
            ARTIFACT_PATHS["LICENSE_MATRIX"],
            ARTIFACT_PATHS["SBOM_SKIPPED"],
            ARTIFACT_PATHS["BINARY_ARTIFACTS"],
            ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
            ARTIFACT_PATHS["QUALITY_REVIEW"],
            ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"],
            ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"],
            ARTIFACT_PATHS["REUSE_CARDS"],
            ARTIFACT_PATHS["REUSE_MAP"],
            ARTIFACT_PATHS["WIKI_HOME"],
            ARTIFACT_PATHS["WIKI_REPO_SUMMARY"],
            ARTIFACT_PATHS["WIKI_ARCHITECTURE"],
            ARTIFACT_PATHS["WIKI_REUSE_INDEX"],
            ARTIFACT_PATHS["WIKI_RISK_INDEX"],
            ARTIFACT_PATHS["CORPUS_INDEX"],
            ARTIFACT_PATHS["CORPUS_SQLITE"],
            ARTIFACT_PATHS["MCP_CONFIG"],
            ARTIFACT_PATHS["MCP_DEFERRED"],
            ARTIFACT_PATHS["MCP_COLLISION_REPORT"],
        ],
        "inventory": [
            ARTIFACT_PATHS["FILE_INDEX"],
            ARTIFACT_PATHS["INVENTORY"],
            ARTIFACT_PATHS["EVIDENCE_INDEX"],
            ARTIFACT_PATHS["PROVENANCE"],
            ARTIFACT_PATHS["MANIFESTS"],
            ARTIFACT_PATHS["BUILD_TEST_MAP"],
            ARTIFACT_PATHS["CI_MAP"],
        ],
        "graph": [
            ARTIFACT_PATHS["MODULE_GRAPH"],
            ARTIFACT_PATHS["SYMBOL_INDEX"],
            ARTIFACT_PATHS["GRAPH"],
            ARTIFACT_PATHS["GRAPH_NODES"],
            ARTIFACT_PATHS["GRAPH_EDGES"],
            ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"],
            ARTIFACT_PATHS["GRAPHIFY_SKIPPED"],
        ],
        "surface": [ARTIFACT_PATHS["API_SURFACE"], ARTIFACT_PATHS["CLI_SURFACE"], ARTIFACT_PATHS["MCP_SURFACE"], ARTIFACT_PATHS["CONFIG_SURFACE"]],
        "synthesis": [ARTIFACT_PATHS["ARCHITECTURE"], ARTIFACT_PATHS["FEATURE_CATALOG"], ARTIFACT_PATHS["PATTERNS"], ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"]],
        "scientific": [ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"], ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"]],
        "telemetry": [ARTIFACT_PATHS["PROJECT_TELEMETRY"], ARTIFACT_PATHS["PROJECT_TELEMETRY_MD"]],
        "risk": [ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"], ARTIFACT_PATHS["RISK_FINDINGS"], ARTIFACT_PATHS["AGENTIC_SECURITY_FINDINGS"], ARTIFACT_PATHS["AGENTIC_SECURITY"], ARTIFACT_PATHS["SUPPLY_CHAIN_SIGNALS"], ARTIFACT_PATHS["RISK_REPORT"], ARTIFACT_PATHS["LICENSE_CARDS"], ARTIFACT_PATHS["LICENSE_MATRIX"], ARTIFACT_PATHS["SBOM_SKIPPED"], ARTIFACT_PATHS["BINARY_ARTIFACTS"]],
        "wiki": [ARTIFACT_PATHS["WIKI_HOME"], ARTIFACT_PATHS["WIKI_REPO_SUMMARY"], ARTIFACT_PATHS["WIKI_ARCHITECTURE"], ARTIFACT_PATHS["WIKI_REUSE_INDEX"], ARTIFACT_PATHS["WIKI_RISK_INDEX"], ARTIFACT_PATHS["WIKI_MODULES"], ARTIFACT_PATHS["WIKI_FEATURES"], ARTIFACT_PATHS["WIKI_PATTERNS"], ARTIFACT_PATHS["WIKI_RISKS"], ARTIFACT_PATHS["WIKI_REUSE"], ARTIFACT_PATHS["WIKI_DECISIONS"], ARTIFACT_PATHS["GRAPH"], ARTIFACT_PATHS["GRAPH_NODES"], ARTIFACT_PATHS["GRAPH_EDGES"], ARTIFACT_PATHS["CORPUS_INDEX"], ARTIFACT_PATHS["CORPUS_SQLITE"]],
        "validate": [
            ARTIFACT_PATHS["VALIDATION_REPORT"],
            ARTIFACT_PATHS["VALIDATION_REPORT_JSON"],
            ARTIFACT_PATHS["REPORT"],
            ARTIFACT_PATHS["OPEN_QUESTIONS"],
            ARTIFACT_PATHS["REVIEW_LEDGER"],
            ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"],
        ],
    }
    return base + by_command[command]


def timed_phase(durations: dict[str, int], name: str, action: Callable[[], None]) -> None:
    started = time.perf_counter()
    action()
    durations[name] = max(0, int((time.perf_counter() - started) * 1000))


def build_overrides(args: argparse.Namespace, argv: list[str]) -> ArgvOverrides:
    return ArgvOverrides(
        command=args.command,
        argv=argv,
        profile=getattr(args, "profile", None),
        output_dir=getattr(args, "output_dir", None),
        allowed_roots=tuple(getattr(args, "allowed_root", []) or []),
        allow_system_roots=bool(getattr(args, "allow_system_roots", False)),
        dry_run=bool(getattr(args, "dry_run", False)),
        renderer=getattr(args, "renderer", None),
        graphify=bool(getattr(args, "graphify", False)),
        graph_centrality=getattr(args, "graph_centrality", None),
        network_policy=getattr(args, "network_policy", None),
        graph_source=getattr(args, "graph_source", None),
    )


def load_normalized_config(args: argparse.Namespace, argv: list[str]) -> dict[str, object]:
    has_config = bool(getattr(args, "config", None))
    has_run_config = bool(getattr(args, "run_config", None))
    if has_config and has_run_config:
        raise ConfigError("use exactly one primary source: --config or --run-config, not both")
    if not has_config and not has_run_config:
        raise ConfigError("missing primary source: pass --config or --run-config")
    overrides = build_overrides(args, argv)
    if has_run_config:
        return load_run_config(Path(args.run_config), overrides)
    config_path = Path(args.config)
    config = load_config_file(config_path)
    return normalize_run_config(config, overrides, config_path)


def handle_config_command(args: argparse.Namespace, argv: list[str]) -> int:
    run_config = load_normalized_config(args, argv)
    if args.dry_run:
        print(json.dumps({"command": args.command, "dry_run": True, "planned_artifacts": planned_artifacts(args.command)}, indent=2))
        return 0
    phase_durations: dict[str, int] = {}
    bootstrap_started = time.perf_counter()
    audit_dir = bootstrap_audit(run_config, Path.cwd())
    phase_durations["bootstrap"] = max(0, int((time.perf_counter() - bootstrap_started) * 1000))
    if args.command == "run":
        timed_phase(phase_durations, "inventory", lambda: run_inventory(run_config, audit_dir))
        timed_phase(phase_durations, "provenance", lambda: run_provenance(run_config, audit_dir))
        timed_phase(phase_durations, "manifest", lambda: run_manifest(run_config, audit_dir))
        timed_phase(phase_durations, "graph", lambda: run_graph(run_config, audit_dir))
        timed_phase(phase_durations, "surface", lambda: run_surface(run_config, audit_dir))
        timed_phase(phase_durations, "synthesis", lambda: run_synthesis(run_config, audit_dir))
        timed_phase(phase_durations, "scientific", lambda: run_scientific_provenance(run_config, audit_dir))
        timed_phase(phase_durations, "telemetry", lambda: run_project_telemetry(run_config, audit_dir))
        timed_phase(phase_durations, "risk_security", lambda: run_risk_security(run_config, audit_dir))
        timed_phase(phase_durations, "license_binary", lambda: run_license_binary(run_config, audit_dir))
        run_config["_phase_durations_ms"] = phase_durations
        run_performance_quality(run_config, audit_dir)
        run_reuse(run_config, audit_dir)
        run_wiki(run_config, audit_dir)
        run_canonical_graph_outputs(run_config, audit_dir)
        run_corpus(run_config, audit_dir)
        run_mcp_export(run_config, audit_dir)
    if args.command == "inventory":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
    if args.command == "graph":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
        run_graph(run_config, audit_dir)
    if args.command == "surface":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
        run_graph(run_config, audit_dir)
        run_surface(run_config, audit_dir)
    if args.command == "synthesis":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
        run_graph(run_config, audit_dir)
        run_surface(run_config, audit_dir)
        run_synthesis(run_config, audit_dir)
    if args.command == "scientific":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
        run_graph(run_config, audit_dir)
        run_surface(run_config, audit_dir)
        run_synthesis(run_config, audit_dir)
        run_scientific_provenance(run_config, audit_dir)
    if args.command == "telemetry":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
        run_project_telemetry(run_config, audit_dir)
    if args.command == "risk":
        run_inventory(run_config, audit_dir)
        run_provenance(run_config, audit_dir)
        run_manifest(run_config, audit_dir)
        run_risk_security(run_config, audit_dir)
        run_license_binary(run_config, audit_dir)
    if args.command == "wiki":
        timed_phase(phase_durations, "inventory", lambda: run_inventory(run_config, audit_dir))
        timed_phase(phase_durations, "provenance", lambda: run_provenance(run_config, audit_dir))
        timed_phase(phase_durations, "manifest", lambda: run_manifest(run_config, audit_dir))
        timed_phase(phase_durations, "graph", lambda: run_graph(run_config, audit_dir))
        timed_phase(phase_durations, "surface", lambda: run_surface(run_config, audit_dir))
        timed_phase(phase_durations, "synthesis", lambda: run_synthesis(run_config, audit_dir))
        timed_phase(phase_durations, "scientific", lambda: run_scientific_provenance(run_config, audit_dir))
        timed_phase(phase_durations, "telemetry", lambda: run_project_telemetry(run_config, audit_dir))
        timed_phase(phase_durations, "risk_security", lambda: run_risk_security(run_config, audit_dir))
        timed_phase(phase_durations, "license_binary", lambda: run_license_binary(run_config, audit_dir))
        run_config["_phase_durations_ms"] = phase_durations
        run_performance_quality(run_config, audit_dir)
        run_reuse(run_config, audit_dir)
        run_wiki(run_config, audit_dir)
        run_canonical_graph_outputs(run_config, audit_dir)
        run_corpus(run_config, audit_dir)
    print(f"bootstrapped {audit_dir}")
    return 0


def finalize_audit(audit_dir: Path, command: str):
    initial = validate_audit(audit_dir)
    write_validation_report(audit_dir, initial, command)
    if not initial.ok:
        remove_stale_review_packet(audit_dir)
        return initial
    if not completion_ready(audit_dir):
        remove_stale_review_packet(audit_dir)
        return initial
    try:
        generate_report_artifacts(audit_dir, command=command)
    except Exception as exc:  # noqa: BLE001 - convert report gate failures into validation-style blockers.
        remove_stale_review_packet(audit_dir)
        return type(initial)(ok=False, errors=[str(exc)])
    return validate_audit(audit_dir)


def handle_validate(args: argparse.Namespace) -> int:
    audit_dir = Path(args.audit_dir)
    if args.dry_run:
        print(json.dumps({"command": "validate", "dry_run": True, "audit_dir": str(audit_dir), "planned_artifacts": planned_artifacts("validate")}, indent=2))
        return 0
    if not audit_dir.exists() or not audit_dir.is_dir():
        raise ConfigError(f"missing audit dir: {audit_dir}")
    command = f"python -m agentic_deep_audit.cli validate --audit-dir {audit_dir}"
    result = finalize_audit(audit_dir, command)
    if not result.ok:
        raise ConfigError("audit validation failed: " + "; ".join(result.errors))
    print(f"validated audit for {audit_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(actual_argv)
    try:
        if args.command in CONFIG_COMMANDS:
            return handle_config_command(args, [args.command, *actual_argv[1:]])
        if args.command == "validate":
            return handle_validate(args)
        if args.command == URL_COMMAND:
            from .audit_from_url import run_url_workflow
            return run_url_workflow(
                url=args.url,
                output_dir=args.output_dir,
                profile=args.profile,
                allowed_roots=args.allowed_root,
                dry_run=args.dry_run,
                timeout_seconds=args.timeout,
            )
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
