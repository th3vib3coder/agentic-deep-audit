"""Configuration normalization for Agentic Deep Audit."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifact_io import write_json_artifact
from .limits import FileSizeLimitError, read_text_auto_capped
from .models import ARTIFACT_PATHS, RUN_CONFIG, load_schema_registry
from .time_utils import current_run_id


DEFAULT_GRAPH_CENTRALITY = {
    "algorithm": "weighted_in_degree",
    "normal_import_weight": 1.0,
    "conditional_import_weight": 0.5,
    "tie_break": ["size_bytes_desc", "path_normalized_asc"],
}

DEFAULT_SCOPE_FILTERS = {"include": ["**/*"], "exclude": [".git/**", "node_modules/**", "dist/**"]}
DEFAULT_RRF = {"k": 60, "weights": {"fts": 1.0, "symbol": 1.0, "graph": 1.0, "manifest": 1.0}}

TARGET_CONTEXT_PRESETS: dict[str, dict[str, Any]] = {
    "MIT downstream": {
        "reuse_policy": "MIT downstream",
        "allowed_languages": ["python"],
        "license_tolerance": "permissive-only",
        "production_required": True,
        "custom_fields": {},
    },
    "AGPL-tolerant": {
        "reuse_policy": "AGPL-tolerant",
        "allowed_languages": [],
        "license_tolerance": "strong-copyleft-ok",
        "production_required": False,
        "custom_fields": {},
    },
    "Python-only": {
        "reuse_policy": "Python-only",
        "allowed_languages": ["python"],
        "license_tolerance": "permissive-with-weak-copyleft",
        "production_required": False,
        "custom_fields": {},
    },
    "production-grade": {
        "reuse_policy": "production-grade",
        "allowed_languages": [],
        "license_tolerance": "permissive-only",
        "production_required": True,
        "custom_fields": {},
    },
}


class ConfigError(ValueError):
    """Raised when configuration cannot be normalized."""


@dataclass(frozen=True)
class ArgvOverrides:
    command: str
    argv: list[str]
    profile: str | None = None
    output_dir: str | None = None
    allowed_roots: tuple[str, ...] = ()
    allow_system_roots: bool = False
    dry_run: bool = False
    renderer: str | None = None
    graphify: bool = False
    graph_centrality: str | None = None
    network_policy: str | None = None
    graph_source: str | None = None


def load_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    try:
        text = read_text_auto_capped(path, encoding="utf-8-sig", label="audit config")
    except FileSizeLimitError as exc:
        raise ConfigError(f"config read failed: {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config file is not valid UTF-8: {path}: {exc}") from exc
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            data = load_yaml_config_text(text)
    except (json.JSONDecodeError, ConfigError) as exc:
        raise ConfigError(f"config parse failed: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("config root must be an object")
    return data


def _is_windows_path_literal(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:\\", value) or value.startswith("\\\\"))


def _escape_windows_paths_in_line(line: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char != '"':
            output.append(char)
            index += 1
            continue
        end = index + 1
        escaped = False
        value_chars: list[str] = []
        while end < len(line):
            current = line[end]
            if current == '"' and not escaped:
                break
            value_chars.append(current)
            escaped = current == "\\" and not escaped
            if current != "\\":
                escaped = False
            end += 1
        if end >= len(line):
            output.append(line[index:])
            break
        value = "".join(value_chars)
        if _is_windows_path_literal(value):
            value = escape_unescaped_backslashes(value)
        output.extend(['"', value, '"'])
        index = end + 1
    return "".join(output)


def _escape_windows_backslashes_in_double_quoted_scalars(text: str) -> str:
    lines: list[str] = []
    block_indent: int | None = None
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if line.strip() and indent <= block_indent:
                block_indent = None
            else:
                lines.append(line)
                continue
        if re.search(r":\s*[|>][+-]?\s*(?:#.*)?$", line):
            block_indent = indent
            lines.append(line)
            continue
        lines.append(_escape_windows_paths_in_line(line))
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def escape_unescaped_backslashes(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue
        if index + 1 < len(value) and value[index + 1] == "\\":
            output.append("\\\\")
            index += 2
            continue
        output.append("\\\\")
        index += 1
    return "".join(output)


def load_yaml_config_text(text: str) -> dict[str, Any]:
    prepared = _escape_windows_backslashes_in_double_quoted_scalars(text)
    try:
        import yaml

        data = yaml.safe_load(prepared) or {}
    except Exception as exc:  # noqa: BLE001 - keep optional YAML dependency lazy while preserving parse context.
        raise ConfigError(str(exc)) from exc
    if not isinstance(data, dict):
        raise ConfigError("config root must be an object")
    return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonicalize_target_context(value: Any) -> dict[str, Any]:
    def normalized_allowed_languages(raw: Any) -> list[str]:
        if not isinstance(raw, list):
            raise ConfigError("target_context.allowed_languages must be a list")
        normalized = [str(item).strip().lower() for item in raw if str(item).strip()]
        return normalized or ["*"]

    if value is None:
        result = copy.deepcopy(TARGET_CONTEXT_PRESETS["MIT downstream"])
        result["allowed_languages"] = normalized_allowed_languages(result["allowed_languages"])
        return result
    if isinstance(value, str):
        if value not in TARGET_CONTEXT_PRESETS:
            raise ConfigError(f"unknown target_context preset: {value}")
        result = copy.deepcopy(TARGET_CONTEXT_PRESETS[value])
        result["allowed_languages"] = normalized_allowed_languages(result["allowed_languages"])
        return result
    if not isinstance(value, dict):
        raise ConfigError("target_context must be a preset string or object")
    preset = value.get("preset")
    if isinstance(preset, str):
        if preset not in TARGET_CONTEXT_PRESETS:
            raise ConfigError(f"unknown target_context preset: {preset}")
        base = copy.deepcopy(TARGET_CONTEXT_PRESETS[preset])
        for key, item in value.items():
            if key != "preset":
                base[key] = item
        value = base
    result = {
        "reuse_policy": value.get("reuse_policy", "custom"),
        "allowed_languages": value.get("allowed_languages", []),
        "license_tolerance": value.get("license_tolerance", "none"),
        "production_required": bool(value.get("production_required", False)),
        "custom_fields": value.get("custom_fields", {}),
    }
    result["allowed_languages"] = normalized_allowed_languages(result["allowed_languages"])
    if not isinstance(result["custom_fields"], dict):
        raise ConfigError("target_context.custom_fields must be an object")
    return result


def canonicalize_graph(config: dict[str, Any]) -> dict[str, Any]:
    graph = copy.deepcopy(config.get("graph") or {})
    centrality = copy.deepcopy(DEFAULT_GRAPH_CENTRALITY)
    centrality.update(graph.get("centrality") or {})
    graph["centrality"] = centrality
    graph.setdefault("graphify", "auto")
    graph.setdefault("html_renderer", "pyvis")
    return graph


def canonicalize_retrieval(value: Any) -> dict[str, Any]:
    retrieval = copy.deepcopy(value or {})
    if not isinstance(retrieval, dict):
        raise ConfigError("retrieval must be an object")
    rrf_input = retrieval.get("rrf") if isinstance(retrieval.get("rrf"), dict) else {}
    effective = copy.deepcopy(DEFAULT_RRF)
    override_keys: list[str] = []
    if "k" in rrf_input:
        if not isinstance(rrf_input["k"], int) or rrf_input["k"] <= 0:
            raise ConfigError("retrieval.rrf.k must be a positive integer")
        effective["k"] = rrf_input["k"]
        override_keys.append("k")
    weights = rrf_input.get("weights") if isinstance(rrf_input.get("weights"), dict) else {}
    for key, value in weights.items():
        if key not in effective["weights"]:
            raise ConfigError(f"unknown retrieval.rrf weight source: {key}")
        if not isinstance(value, (int, float)) or value < 0:
            raise ConfigError(f"retrieval.rrf.weights.{key} must be a non-negative number")
        effective["weights"][key] = float(value)
        override_keys.append(f"weights.{key}")
    retrieval["rrf"] = {**effective, "override": bool(override_keys), "override_keys": sorted(override_keys)}
    return retrieval


def validate_audit_config_document(config: dict[str, Any], schema_name: str = "audit_config") -> None:
    schema = load_schema_registry()[schema_name].schema
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(config), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ConfigError(f"config schema invalid at {location}: {first.message}")


def _detect_host_os() -> str:
    platform_name = sys.platform
    if platform_name.startswith("win"):
        return "windows"
    if platform_name.startswith("linux"):
        return "linux"
    if platform_name == "darwin":
        return "macos"
    return "unknown"


def _adapter_version() -> str:
    try:
        from importlib.metadata import version

        return version("agentic-deep-audit")
    except Exception:
        return "0.1.0"


def build_launch_surface(adapter: str = "cli", entry_command: str | None = None, cwd_policy: str = "package-root") -> dict[str, str]:
    """Build the launch_surface block recorded in the run config (schema 1.1; see docs/contracts/output_contract.md)."""
    return {
        "adapter": adapter,
        "adapter_version": _adapter_version(),
        "entry_command": entry_command or "",
        "host_os": _detect_host_os(),
        "cwd_policy": cwd_policy,
    }


def _stringify_path(path: Path) -> str:
    return path.as_posix()


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _home_path() -> Path | None:
    try:
        return Path.home().resolve()
    except RuntimeError:
        return None


def _sensitive_roots() -> list[tuple[Path, str]]:
    roots: list[tuple[Path, str]] = []
    for raw, label in [("/etc", "/etc"), ("/proc", "/proc"), ("/sys", "/sys")]:
        path = Path(raw)
        if path.exists():
            roots.append((path.resolve(), label))
    for raw, label in [("C:/Windows", "C:\\Windows"), ("C:/Program Files", "C:\\Program Files"), ("C:/Program Files (x86)", "C:\\Program Files (x86)")]:
        path = Path(raw)
        if path.exists():
            roots.append((path.resolve(), label))
    home = _home_path()
    if home is not None:
        for child in [".ssh", ".aws", ".config"]:
            roots.append(((home / child).resolve(), f"~/{child}"))
    return roots


def _reject_sensitive_path(path: Path, field_name: str, allow_system_roots: bool) -> None:
    if allow_system_roots:
        return
    resolved = path.resolve()
    home = _home_path()
    if home is not None and resolved == home:
        raise ConfigError(f"{field_name} points at user home; pass --allow-system-roots to opt in: {_stringify_path(resolved)}")
    for root, label in _sensitive_roots():
        if _path_is_relative_to(resolved, root):
            raise ConfigError(f"{field_name} points at sensitive system path {label}; pass --allow-system-roots to opt in: {_stringify_path(resolved)}")


def _default_allowed_roots(config_path: Path | None) -> list[Path]:
    cwd = Path.cwd().resolve()
    home = _home_path()
    roots = [] if home is not None and cwd == home else [cwd]
    if config_path is not None:
        roots.append(config_path.parent.resolve())
    return list(dict.fromkeys(roots))


def _resolve_allowed_roots(raw_roots: tuple[str, ...] | list[str] | None, config_path: Path | None) -> list[Path]:
    roots = _default_allowed_roots(config_path)
    base = config_path.parent if config_path is not None else Path.cwd()
    for raw in raw_roots or ():
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigError("allowed root must be a non-empty string")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = base / candidate
        resolved = candidate.resolve()
        if not resolved.exists() or not resolved.is_dir():
            raise ConfigError(f"allowed root does not exist or is not a directory: {resolved}")
        roots.append(resolved)
    return list(dict.fromkeys(roots))


def _assert_under_allowed_roots(path: Path, allowed_roots: list[Path], field_name: str, allow_system_roots: bool = False) -> None:
    resolved = path.resolve()
    _reject_sensitive_path(resolved, field_name, allow_system_roots)
    for root in allowed_roots:
        try:
            resolved.relative_to(root.resolve())
            return
        except ValueError:
            continue
    roots = ", ".join(_stringify_path(root.resolve()) for root in allowed_roots)
    raise ConfigError(f"{field_name} outside allowed root: {_stringify_path(resolved)} (allowed: {roots})")


def resolve_repo_path(repo_path: Any, config_path: Path | None, allowed_roots: list[Path] | None = None, allow_system_roots: bool = False) -> Path:
    if not isinstance(repo_path, str) or not repo_path.strip():
        raise ConfigError("repo.path must be a non-empty string for local repositories")
    path = Path(repo_path).expanduser()
    if not path.is_absolute():
        base = config_path.parent if config_path is not None else Path.cwd()
        path = base / path
    resolved = path.resolve()
    if not resolved.exists():
        raise ConfigError(f"repo.path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ConfigError(f"repo.path must be a directory: {resolved}")
    _assert_under_allowed_roots(resolved, allowed_roots or _default_allowed_roots(config_path), "repo.path", allow_system_roots)
    return resolved


def normalize_output_dir(value: Any, config_path: Path | None = None, allowed_roots: list[Path] | None = None, allow_system_roots: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("output_dir must be a non-empty string")
    path = Path(value).expanduser()
    if not path.is_absolute():
        base = config_path.parent if config_path is not None else Path.cwd()
        path = base / path
    resolved = path.resolve()
    _assert_under_allowed_roots(resolved, allowed_roots or _default_allowed_roots(config_path), "output_dir", allow_system_roots)
    return _stringify_path(resolved)


def normalize_repo_config(repo: Any, config_path: Path | None, allowed_roots: list[Path] | None = None, allow_system_roots: bool = False) -> tuple[dict[str, Any], bool]:
    if not isinstance(repo, dict):
        raise ConfigError("config requires repo object")
    normalized = copy.deepcopy(repo)
    repo_kind = normalized.get("kind")
    if repo_kind == "local":
        resolved_repo = resolve_repo_path(normalized.get("path"), config_path, allowed_roots, allow_system_roots)
        normalized["path"] = _stringify_path(resolved_repo)
        return normalized, True
    if repo_kind == "github":
        if not normalized.get("github"):
            raise ConfigError("repo.github is required when repo.kind is github")
        return normalized, False
    raise ConfigError("repo.kind must be local or github")


def normalize_run_config(config: dict[str, Any], overrides: ArgvOverrides, config_path: Path | None) -> dict[str, Any]:
    validate_audit_config_document(config)
    if "repo" not in config or not isinstance(config["repo"], dict):
        raise ConfigError("config requires repo object")
    allowed_roots = _resolve_allowed_roots(overrides.allowed_roots, config_path)
    repo_config, repo_path_environment_specific = normalize_repo_config(config["repo"], config_path, allowed_roots, overrides.allow_system_roots)
    normalized = {
        "schema_version": "1.1",
        "launch_surface": build_launch_surface(entry_command=overrides.command),
        "run_id": current_run_id(),
        "repo": repo_config,
        "profile": config.get("profile", "standard"),
        "mode": config.get("mode", "source-audit"),
        "output_dir": config.get("output_dir", "audit"),
        "scope_filters": copy.deepcopy(config.get("scope_filters", DEFAULT_SCOPE_FILTERS)),
        "network_policy_file": config.get("network_policy_file", ARTIFACT_PATHS["NETWORK_POLICY"]),
        "mcp_config": config.get("mcp_config"),
        "blocked_tools": copy.deepcopy(config.get("blocked_tools", [])),
        "blocked_commands_file": config.get("blocked_commands_file", ARTIFACT_PATHS["BLOCKED_COMMANDS_ALLOWLIST"]),
        "target_context": canonicalize_target_context(config.get("target_context")),
        "binary_triage_consent": bool(config.get("binary_triage_consent", False)),
        "graph": canonicalize_graph(config),
        "retrieval": canonicalize_retrieval(config.get("retrieval")),
        "security": copy.deepcopy(config.get("security", {"default_no_exec": True, "sanitize_untrusted_markdown": True})),
        "argv": overrides.argv,
        "command": overrides.command,
        "dry_run": overrides.dry_run,
        "override_source": {},
        "provenance": {
            "config_path": str(config_path.resolve()) if config_path else None,
            "config_sha256": sha256_file(config_path) if config_path and config_path.exists() else None,
            "environment_specific_paths": [],
        },
    }
    if overrides.profile is not None:
        normalized["profile"] = overrides.profile
        normalized["override_source"]["profile"] = "argv"
    if overrides.output_dir is not None:
        normalized["output_dir"] = overrides.output_dir
        normalized["override_source"]["output_dir"] = "argv"
    if overrides.renderer is not None:
        normalized["graph"]["html_renderer"] = overrides.renderer
        normalized["override_source"]["graph.html_renderer"] = "argv"
    if overrides.graphify:
        normalized["graph"]["graphify"] = "required"
        normalized["override_source"]["graph.graphify"] = "argv"
    if overrides.graph_centrality is not None:
        normalized["graph"].setdefault("centrality", {})["algorithm"] = overrides.graph_centrality
        normalized["override_source"]["graph.centrality.algorithm"] = "argv"
    if overrides.network_policy is not None:
        normalized["network_policy_file"] = overrides.network_policy
        normalized["override_source"]["network_policy_file"] = "argv"
    if overrides.graph_source is not None:
        normalized["graph_source"] = overrides.graph_source
        normalized["override_source"]["graph_source"] = "argv"
    if normalized["retrieval"]["rrf"]["override"]:
        normalized["override_source"]["retrieval.rrf"] = "config"
    if repo_path_environment_specific:
        normalized["provenance"]["environment_specific_paths"].append("repo.path")
    normalized["output_dir"] = normalize_output_dir(normalized["output_dir"], config_path, allowed_roots, overrides.allow_system_roots)
    return normalized


def load_run_config(path: Path, overrides: ArgvOverrides) -> dict[str, Any]:
    try:
        data = json.loads(read_text_auto_capped(path, encoding="utf-8-sig", label="run config"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"run config parse failed: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("run config root must be an object")
    data = copy.deepcopy(data)
    validate_audit_config_document(data, schema_name="run_config")
    if "repo" not in data or not isinstance(data["repo"], dict):
        raise ConfigError("run config requires repo object")
    allowed_roots = _resolve_allowed_roots(overrides.allowed_roots, path)
    data["repo"], _ = normalize_repo_config(data["repo"], path, allowed_roots, overrides.allow_system_roots)
    if "output_dir" not in data:
        raise ConfigError("run config requires output_dir")
    data["target_context"] = canonicalize_target_context(data.get("target_context"))
    data["retrieval"] = canonicalize_retrieval(data.get("retrieval"))
    data["argv"] = overrides.argv
    data["command"] = overrides.command
    data["dry_run"] = overrides.dry_run
    if overrides.profile is not None:
        data["profile"] = overrides.profile
        data.setdefault("override_source", {})["profile"] = "argv"
    if overrides.output_dir is not None:
        data["output_dir"] = overrides.output_dir
        data.setdefault("override_source", {})["output_dir"] = "argv"
    if overrides.renderer is not None:
        data.setdefault("graph", {})["html_renderer"] = overrides.renderer
        data.setdefault("override_source", {})["graph.html_renderer"] = "argv"
    if overrides.graphify:
        data.setdefault("graph", {})["graphify"] = "required"
        data.setdefault("override_source", {})["graph.graphify"] = "argv"
    if overrides.graph_centrality is not None:
        data.setdefault("graph", {}).setdefault("centrality", {})["algorithm"] = overrides.graph_centrality
        data.setdefault("override_source", {})["graph.centrality.algorithm"] = "argv"
    if overrides.network_policy is not None:
        data["network_policy_file"] = overrides.network_policy
        data.setdefault("override_source", {})["network_policy_file"] = "argv"
    if overrides.graph_source is not None:
        data["graph_source"] = overrides.graph_source
        data.setdefault("override_source", {})["graph_source"] = "argv"
    if data["retrieval"]["rrf"]["override"]:
        override_source = data.setdefault("override_source", {})
        override_source["retrieval.rrf"] = override_source.get("retrieval.rrf", "config")
    data["output_dir"] = normalize_output_dir(data["output_dir"], path, allowed_roots, overrides.allow_system_roots)
    return data


def write_run_config(run_config: dict[str, Any]) -> Path:
    output_dir = Path(str(run_config["output_dir"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / RUN_CONFIG
    write_json_artifact(path, run_config)
    return path
