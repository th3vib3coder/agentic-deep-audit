"""Phase 2 manifest, build/test command and CI mapping."""

from __future__ import annotations

import json
import re
import shlex
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS
from .policy import decide_command


MANIFEST_FILENAMES = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}
CI_PREFIXES = (".github/workflows/", ".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml", "azure-pipelines.yaml")


@dataclass(frozen=True)
class ObservedCommand:
    command: str
    category: str
    source: str
    origin: str
    policy_decision: str
    policy_rule: str
    label: str = "observed, not executed"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def command_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    return tokens or [command]


def classify_command(command: str) -> str:
    lowered = command.lower()
    if any(token in lowered for token in [" test", "pytest", "jest", "cargo test", "go test", "mvn test", "gradle test"]):
        return "test"
    if any(token in lowered for token in [" lint", "ruff", "eslint", "flake8", "golangci-lint"]):
        return "lint"
    if any(token in lowered for token in [" docs", "mkdocs", "sphinx", "typedoc"]):
        return "docs"
    if any(token in lowered for token in [" release", "publish", "deploy"]):
        return "release"
    if any(token in lowered for token in [" install", "pip install", "npm install", "pnpm install", "yarn install", "cargo fetch"]):
        return "install"
    return "build"


def observed_command(command: str, source: str, category: str | None = None) -> dict[str, Any]:
    decision = decide_command(command_tokens(command), origin="target_repo_manifest")
    return asdict(
        ObservedCommand(
            command=command,
            category=category or classify_command(command),
            source=source,
            origin=decision.origin,
            policy_decision=decision.decision,
            policy_rule=decision.policy_rule,
        )
    )


def dependency(name: str, specifier: str | None = None, scope: str | None = None) -> dict[str, Any]:
    return {"name": name, "specifier": specifier, "scope": scope}


def parse_pyproject(path: Path) -> dict[str, Any]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
    build_system = payload.get("build-system") if isinstance(payload.get("build-system"), dict) else {}
    dependencies: list[dict[str, Any]] = []
    for item in project.get("dependencies") or []:
        dependencies.append(dependency(str(item), scope="project.dependencies"))
    for group, values in (project.get("optional-dependencies") or {}).items():
        for item in values or []:
            dependencies.append(dependency(str(item), scope=f"optional.{group}"))
    for item in build_system.get("requires") or []:
        dependencies.append(dependency(str(item), scope="build-system.requires"))
    commands = [observed_command(command, path.name, category="build") for command in (project.get("scripts") or {}).values()]
    return {"ecosystem": "python", "package_name": project.get("name"), "build_system": build_system.get("build-backend"), "dependencies": dependencies, "scripts": commands, "lockfiles": []}


def parse_requirements(path: Path) -> dict[str, Any]:
    dependencies: list[dict[str, Any]] = []
    lockfiles: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith(("-r ", "--requirement ")):
            lockfiles.append(stripped.split(maxsplit=1)[1])
            continue
        if stripped.startswith("-"):
            dependencies.append(dependency(stripped, scope="pip-option"))
            continue
        dependencies.append(dependency(stripped, scope="requirements"))
    return {"ecosystem": "python", "package_name": None, "build_system": "pip", "dependencies": dependencies, "scripts": [], "lockfiles": lockfiles}


def parse_package_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    dependencies: list[dict[str, Any]] = []
    for scope in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        for name, specifier in (payload.get(scope) or {}).items():
            dependencies.append(dependency(str(name), str(specifier), scope=scope))
    scripts = [observed_command(str(command), f"{path.name}:scripts.{name}", category=classify_command(str(command))) for name, command in (payload.get("scripts") or {}).items()]
    return {"ecosystem": "javascript", "package_name": payload.get("name"), "build_system": "npm", "dependencies": dependencies, "scripts": scripts, "lockfiles": []}


def parse_cargo(path: Path) -> dict[str, Any]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
    dependencies: list[dict[str, Any]] = []
    for scope in ["dependencies", "dev-dependencies", "build-dependencies"]:
        for name, specifier in (payload.get(scope) or {}).items():
            dependencies.append(dependency(str(name), json.dumps(specifier, sort_keys=True) if isinstance(specifier, dict) else str(specifier), scope=scope))
    return {"ecosystem": "rust", "package_name": package.get("name"), "build_system": "cargo", "dependencies": dependencies, "scripts": [], "lockfiles": ["Cargo.lock"]}


def parse_go_mod(path: Path) -> dict[str, Any]:
    dependencies: list[dict[str, Any]] = []
    module_name: str | None = None
    in_require = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("module "):
            module_name = stripped.split(maxsplit=1)[1]
        elif stripped == "require (":
            in_require = True
        elif in_require and stripped == ")":
            in_require = False
        elif stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 3:
                dependencies.append(dependency(parts[1], parts[2], scope="require"))
        elif in_require and stripped and not stripped.startswith("//"):
            parts = stripped.split()
            if len(parts) >= 2:
                dependencies.append(dependency(parts[0], parts[1], scope="require"))
    return {"ecosystem": "go", "package_name": module_name, "build_system": "go", "dependencies": dependencies, "scripts": [], "lockfiles": ["go.sum"]}


def parse_pom(path: Path) -> dict[str, Any]:
    root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}

    def find_text(element: ET.Element, name: str) -> str | None:
        found = element.find(f"m:{name}", ns) if ns else element.find(name)
        return found.text.strip() if found is not None and found.text else None

    dependencies: list[dict[str, Any]] = []
    dep_nodes = root.findall(".//m:dependency", ns) if ns else root.findall(".//dependency")
    for dep in dep_nodes:
        group = find_text(dep, "groupId") or ""
        artifact = find_text(dep, "artifactId") or ""
        name = f"{group}:{artifact}".strip(":")
        if name:
            dependencies.append(dependency(name, find_text(dep, "version"), scope=find_text(dep, "scope") or "dependency"))
    package_name = ":".join(item for item in [find_text(root, "groupId"), find_text(root, "artifactId")] if item) or None
    return {"ecosystem": "java", "package_name": package_name, "build_system": "maven", "dependencies": dependencies, "scripts": [], "lockfiles": []}


def parse_gradle(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    dependencies = [dependency(match.group(1), scope="gradle.dependencies") for match in re.finditer(r"['\"]([^'\"]+:[^'\"]+:[^'\"]+)['\"]", text)]
    commands = [observed_command(match.group(1), path.name) for match in re.finditer(r"commandLine\s+['\"]([^'\"]+)['\"]", text)]
    package_match = re.search(r"rootProject\.name\s*=\s*['\"]([^'\"]+)['\"]", text)
    return {"ecosystem": "java", "package_name": package_match.group(1) if package_match else None, "build_system": "gradle", "dependencies": dependencies, "scripts": commands, "lockfiles": ["gradle.lockfile"]}


def parse_dockerfile(path: Path) -> dict[str, Any]:
    commands = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("RUN "):
            commands.append(observed_command(stripped[4:].strip(), path.name, category="build"))
    return {"ecosystem": "container", "package_name": None, "build_system": "docker", "dependencies": [], "scripts": commands, "lockfiles": []}


def parse_compose(path: Path) -> dict[str, Any]:
    commands = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("command:"):
            commands.append(observed_command(stripped.split(":", 1)[1].strip().strip("'\""), path.name))
    return {"ecosystem": "container", "package_name": None, "build_system": "compose", "dependencies": [], "scripts": commands, "lockfiles": []}


def parse_manifest(path: Path) -> dict[str, Any]:
    name = path.name.lower()
    if name == "pyproject.toml":
        return parse_pyproject(path)
    if name == "requirements.txt":
        return parse_requirements(path)
    if name == "package.json":
        return parse_package_json(path)
    if name == "cargo.toml":
        return parse_cargo(path)
    if name == "go.mod":
        return parse_go_mod(path)
    if name == "pom.xml":
        return parse_pom(path)
    if name in {"build.gradle", "build.gradle.kts"}:
        return parse_gradle(path)
    if name == "dockerfile":
        return parse_dockerfile(path)
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return parse_compose(path)
    return {"ecosystem": "unknown", "package_name": None, "build_system": None, "dependencies": [], "scripts": [], "lockfiles": [], "skip_reason": "unsupported manifest"}


def is_manifest_path(path: str) -> bool:
    return Path(path).name.lower() in MANIFEST_FILENAMES


def is_ci_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.startswith(CI_PREFIXES) or lowered.endswith((".github/workflows/ci.yml", ".github/workflows/ci.yaml"))


def manifest_records(file_index: dict[str, Any], evidence_lookup: dict[str, str], repo_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for file_record in file_index.get("records", []):
        path_value = str(file_record.get("path") or "")
        if not is_manifest_path(path_value):
            continue
        evidence_id = evidence_lookup.get(path_value)
        if not evidence_id:
            records.append({"path": path_value, "skipped": True, "skip_reason": "missing manifest evidence id", "evidence_ids": []})
            continue
        try:
            parsed = parse_manifest(repo_path / path_value)
        except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError) as exc:
            records.append(
                {
                    "path": path_value,
                    "skipped": True,
                    "skip_reason": f"parse error: {type(exc).__name__}: {exc}",
                    "evidence_ids": [evidence_id],
                    "ecosystem": "unknown",
                    "package_name": None,
                    "build_system": None,
                    "dependencies": [],
                    "scripts": [],
                    "lockfiles": [],
                }
            )
            continue
        records.append({"path": path_value, "skipped": False, "skip_reason": None, "evidence_ids": [evidence_id], **parsed})
    return records


def extract_ci_run_commands(text: str, path_value: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    commands: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(?P<indent>\s*)-\s*run:\s*(?P<value>.*)$|^(?P<indent2>\s*)run:\s*(?P<value2>.*)$", line)
        if not match:
            index += 1
            continue
        indent = len(match.group("indent") if match.group("indent") is not None else match.group("indent2") or "")
        value = (match.group("value") if match.group("value") is not None else match.group("value2") or "").strip()
        if value in {"|", ">"}:
            index += 1
            block: list[str] = []
            while index < len(lines):
                next_line = lines[index]
                if next_line.strip() and len(next_line) - len(next_line.lstrip(" ")) <= indent:
                    break
                if next_line.strip():
                    block.append(next_line.strip())
                index += 1
            commands.extend(observed_command(command, f"{path_value}:run") for command in block if command and not command.startswith("#"))
            continue
        if value:
            commands.append(observed_command(value, f"{path_value}:run"))
        index += 1
    return commands


def parse_ci_workflow(path: Path, path_value: str, evidence_id: str | None) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    triggers = sorted(set(re.findall(r"^\s*(push|pull_request|workflow_dispatch|schedule|merge_request_event)\s*:", text, flags=re.MULTILINE)))
    commands = extract_ci_run_commands(text, path_value)
    jobs = sorted(set(match.group(1) for match in re.finditer(r"^\s{2}([A-Za-z0-9_.-]+):\s*$", text, flags=re.MULTILINE)))
    return {
        "path": path_value,
        "triggers": triggers,
        "jobs": jobs,
        "commands": commands,
        "skipped": False,
        "skip_reason": None,
        "evidence_ids": [evidence_id] if evidence_id else [],
    }


def ci_records(file_index: dict[str, Any], evidence_lookup: dict[str, str], repo_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for file_record in file_index.get("records", []):
        path_value = str(file_record.get("path") or "")
        if is_ci_path(path_value):
            records.append(parse_ci_workflow(repo_path / path_value, path_value, evidence_lookup.get(path_value)))
    return records


def build_test_map_markdown(manifests: list[dict[str, Any]], ci: list[dict[str, Any]]) -> str:
    lines = [
        "# Build Test Map",
        "",
        "Every command below is observed, not executed.",
        "",
        "| Source | Category | Command | Policy | Label |",
        "|---|---|---|---|---|",
    ]
    rows: list[dict[str, Any]] = []
    for record in manifests:
        rows.extend(record.get("scripts") or [])
    for record in ci:
        rows.extend(record.get("commands") or [])
    if not rows:
        lines.append("|  |  |  |  | observed, not executed |")
    for command in rows:
        lines.append(f"| {command['source']} | {command['category']} | `{command['command']}` | {command['policy_rule']} | {command['label']} |")
    lines.append("")
    return "\n".join(lines)


def run_manifest(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    repo_path = Path(str((file_index.get("repo") or {}).get("path") or (run_config.get("repo") or {}).get("path") or ".")).resolve()
    evidence_lookup = evidence_by_path(audit_dir)
    manifests = manifest_records(file_index, evidence_lookup, repo_path)
    ci = ci_records(file_index, evidence_lookup, repo_path)
    common = {
        "schema_version": "1.0",
        "run_id": run_config.get("run_id"),
        "repo": file_index.get("repo") or run_config.get("repo") or {},
        "source_artifacts": [ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["EVIDENCE_INDEX"]],
        "skipped": False,
        "skip_reason": None,
    }
    write_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"], {**common, "records": manifests})
    write_json(audit_dir / ARTIFACT_PATHS["CI_MAP"], {**common, "records": ci})
    (audit_dir / ARTIFACT_PATHS["BUILD_TEST_MAP"]).write_text(build_test_map_markdown(manifests, ci), encoding="utf-8")
