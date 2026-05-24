"""Configuration normalization for Agentic Deep Audit."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS, RUN_CONFIG


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
    dry_run: bool = False
    renderer: str | None = None
    graphify: bool = False
    graph_centrality: str | None = None
    network_policy: str | None = None
    graph_source: str | None = None


def _strip_inline_comment(value: str) -> str:
    in_quote: str | None = None
    for index, char in enumerate(value):
        if char in {"'", '"'}:
            in_quote = None if in_quote == char else char
        if char == "#" and in_quote is None:
            return value[:index].rstrip()
    return value


def parse_scalar(value: str) -> Any:
    value = _strip_inline_comment(value.strip())
    if value == "":
        return ""
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(",")]
    if value.startswith("{") and value.endswith("}"):
        inner = value[1:-1].strip()
        if not inner:
            return {}
        result: dict[str, Any] = {}
        for part in inner.split(","):
            key, item_value = part.split(":", 1)
            result[str(parse_scalar(key.strip()))] = parse_scalar(item_value.strip())
        return result
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the constrained YAML shape used by audit configuration fixtures."""

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if ":" not in line:
            raise ConfigError(f"unsupported YAML line: {raw_line}")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ConfigError(f"invalid indentation near: {raw_line}")
        parent = stack[-1][1]
        if raw_value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = parse_scalar(raw_value)
    return root


def load_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        data = parse_simple_yaml(text)
    if not isinstance(data, dict):
        raise ConfigError("config root must be an object")
    return data


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def normalize_run_config(config: dict[str, Any], overrides: ArgvOverrides, config_path: Path | None) -> dict[str, Any]:
    if "repo" not in config or not isinstance(config["repo"], dict):
        raise ConfigError("config requires repo object")
    normalized = {
        "schema_version": str(config.get("schema_version", "1.0")),
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "repo": copy.deepcopy(config["repo"]),
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
    repo_path = normalized["repo"].get("path")
    if repo_path:
        normalized["repo"]["path"] = str(Path(repo_path).resolve())
        normalized["provenance"]["environment_specific_paths"].append("repo.path")
    normalized["output_dir"] = str(Path(str(normalized["output_dir"])))
    return normalized


def load_run_config(path: Path, overrides: ArgvOverrides) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError("run config root must be an object")
    data = copy.deepcopy(data)
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
    return data


def write_run_config(run_config: dict[str, Any]) -> Path:
    output_dir = Path(str(run_config["output_dir"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / RUN_CONFIG
    path.write_text(json.dumps(run_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
