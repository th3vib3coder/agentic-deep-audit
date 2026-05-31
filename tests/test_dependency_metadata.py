from __future__ import annotations

import ast
import re
import sys
from importlib.metadata import packages_distributions

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility.
    import tomli as tomllib

from agentic_deep_audit.models import PLUGIN_ROOT


SRC = PLUGIN_ROOT / "src" / "agentic_deep_audit"

# Import-name -> distribution-name aliases for cases where they differ (normalized, lowercase).
# packages_distributions() is the primary source; this is a robustness fallback.
KNOWN_IMPORT_TO_DIST = {"yaml": "pyyaml"}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared_dependencies() -> set[str]:
    data = tomllib.loads((PLUGIN_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = set()
    for spec in data["project"]["dependencies"]:
        name = re.split(r"[<>=!~;\[\s]", spec, maxsplit=1)[0]
        if name:
            declared.add(_normalize(name))
    return declared


def _dep_justifications() -> set[str]:
    data = tomllib.loads((PLUGIN_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    table = data.get("tool", {}).get("agentic-deep-audit", {}).get("dep-justification", {})
    return {_normalize(key) for key in table}


def _third_party_imports() -> set[str]:
    stdlib = set(sys.stdlib_module_names)
    imports: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".")[0])
    return {imp for imp in imports if imp != "agentic_deep_audit" and imp not in stdlib}


def _candidate_dists(imp: str, mapping: dict[str, list[str]]) -> set[str]:
    candidates = {_normalize(imp)}
    for dist in mapping.get(imp, []):
        candidates.add(_normalize(dist))
    if imp in KNOWN_IMPORT_TO_DIST:
        candidates.add(_normalize(KNOWN_IMPORT_TO_DIST[imp]))
    return candidates


def test_all_runtime_imports_declared() -> None:
    declared = _declared_dependencies()
    mapping = packages_distributions()
    undeclared = [imp for imp in sorted(_third_party_imports()) if not (_candidate_dists(imp, mapping) & declared)]
    assert not undeclared, f"runtime third-party imports not declared in [project.dependencies]: {undeclared}"


def test_declared_deps_are_imported_or_justified() -> None:
    declared = _declared_dependencies()
    justified = _dep_justifications()
    mapping = packages_distributions()
    satisfied: set[str] = set()
    for imp in _third_party_imports():
        satisfied |= _candidate_dists(imp, mapping)
    unused = sorted(dep for dep in declared if dep not in satisfied and dep not in justified)
    assert not unused, (
        "declared dependencies neither imported under src/ nor justified in "
        f"[tool.agentic-deep-audit.dep-justification]: {unused}"
    )
