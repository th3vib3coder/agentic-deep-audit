"""Project telemetry extraction from git history, manifests and docs."""

from __future__ import annotations

import json
import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from itertools import combinations
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .audit_provenance import run_git_command
from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS
from .policy import decide_network


CATEGORIES = [
    "changelog_parsing",
    "release_cadence",
    "contributors_graph",
    "bus_factor_proxy",
    "ownership_concentration",
    "dependency_upgrade_churn",
    "api_doc_extraction",
    "commit_message_quality_signal",
    "issue_pr_signals",
]
GIT_DEPENDENT = {"release_cadence", "contributors_graph", "bus_factor_proxy", "ownership_concentration", "commit_message_quality_signal"}
BOT_FILTER_RULE = "name/email contains [bot], bot@, noreply bot suffix, or GitHub actor type bot"
MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
}
CODE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".r",
    ".R",
}
VENDORED_PARTS = {"node_modules", "vendor", "third_party", "dist", "build", ".venv", "venv"}
GITHUB_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
IDENTITY_SALT = "agentic-deep-audit-telemetry-v1"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return read_json_capped(path, label="telemetry input")


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def parse_iso_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def default_parameters(from_ref: str | None = None, to_ref: str | None = None, as_of: str | None = None) -> dict[str, Any]:
    window_end = parse_iso_datetime(as_of)
    window_start = window_end - timedelta(days=365)
    return {
        "time_window_days": 365,
        "from_ref": from_ref,
        "to_ref": to_ref,
        "time_window_start": window_start.isoformat(timespec="seconds"),
        "time_window_end": window_end.isoformat(timespec="seconds"),
        "bot_filter": BOT_FILTER_RULE,
        "identity_normalization": ".mailmap if present else lower-case email else normalized author name",
    }


def is_bot_author(name: str, email: str, actor_type: str | None = None) -> bool:
    combined = f"{name} {email}".lower()
    if actor_type and actor_type.lower() == "bot":
        return True
    if "[bot]" in combined or "bot@" in combined:
        return True
    return "noreply" in combined and "bot" in combined


def load_mailmap(repo_path: Path) -> dict[str, str]:
    path = repo_path / ".mailmap"
    if not path.exists():
        return {}
    mapping: dict[str, str] = {}
    try:
        lines = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="mailmap").splitlines()
    except (OSError, FileSizeLimitError):
        return mapping
    for line in lines:
        emails = re.findall(r"<([^>]+)>", line)
        if len(emails) >= 2:
            canonical = emails[0].lower()
            for alias in emails[1:]:
                mapping[alias.lower()] = canonical
    return mapping


def normalize_identity(name: str, email: str, mailmap: dict[str, str]) -> str:
    if email:
        lowered = email.lower()
        return mailmap.get(lowered, lowered)
    return re.sub(r"\s+", " ", name.strip().lower())


def pseudonymize_identity(identity: str, salt: str = IDENTITY_SALT) -> str:
    digest = hashlib.sha256((salt + identity.casefold()).encode("utf-8")).hexdigest()[:12]
    return f"id_{digest}"


def telemetry_record(index: int, category: str, status: str, parameters: dict[str, Any], value: dict[str, Any] | None, evidence_ids: list[str], source: str, confidence: str, limitations: list[str]) -> dict[str, Any]:
    return {
        "telemetry_id": f"tel-{index:06d}",
        "category": category,
        "status": status,
        "parameters": parameters,
        "value": value,
        "evidence_ids": evidence_ids,
        "source": source,
        "confidence": confidence,
        "limitations": limitations,
    }


def parse_changelog(repo_path: Path, file_index: dict[str, Any], evidence_lookup: dict[str, str], parameters: dict[str, Any], index: int) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    for record in file_index.get("records", []):
        if not isinstance(record, dict):
            continue
        path_value = str(record.get("path_normalized") or record.get("path") or "")
        name = Path(path_value).name.lower()
        if name not in {"changelog.md", "history.md", "release_notes.md", "releases.md"}:
            continue
        evidence_id = evidence_lookup.get(path_value)
        if evidence_id:
            evidence_ids.append(evidence_id)
        try:
            text = read_text_auto_capped(repo_path / path_value, encoding="utf-8", errors="replace", label="telemetry changelog")
        except (OSError, FileSizeLimitError):
            continue
        for line in text.splitlines():
            if not line.startswith("#"):
                continue
            version = re.search(r"\b(v?\d+\.\d+(?:\.\d+)?)\b", line)
            date = re.search(r"\b\d{4}-\d{2}-\d{2}\b", line)
            markers = sorted({marker for marker in ["breaking", "security", "deprecated", "feat", "fix"] if marker in line.lower()})
            if version or markers:
                entries.append({"version": version.group(1) if version else None, "date": date.group(0) if date else None, "type": markers or ["release"], "source_path": path_value})
    if entries:
        return telemetry_record(index, "changelog_parsing", "observed", parameters, {"entries": entries}, sorted(set(evidence_ids)), "changelog", "medium", [])
    return telemetry_record(index, "changelog_parsing", "skipped", parameters, None, [], "changelog", "low", ["no changelog or release notes found"])


def git_history(repo_path: Path, parameters: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], str | None, str | None]:
    args = [
        "log",
        f"--since={parameters['time_window_start']}",
        f"--until={parameters['time_window_end']}",
        "--format=__COMMIT__%x1f%H%x1f%an%x1f%ae%x1f%ad%x1f%s%x1f%D",
        "--date=short",
        "--name-only",
    ]
    if parameters.get("from_ref") and parameters.get("to_ref"):
        args.append(f"{parameters['from_ref']}..{parameters['to_ref']}")
    elif parameters.get("to_ref"):
        args.append(str(parameters["to_ref"]))
    completed, _ = run_git_command(repo_path, args)
    if completed.returncode != 0:
        return [], [], None, None
    commits: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("__COMMIT__"):
            parts = line.split("\x1f")
            tags = sorted(set(re.findall(r"(?:^|, )tag: ([^,]+)", parts[6] if len(parts) > 6 else "")))
            current = {"hash": parts[1], "author_name": parts[2], "author_email": parts[3], "date": parts[4], "subject": parts[5] if len(parts) > 5 else "", "tags": tags, "files": []}
            commits.append(current)
        elif current is not None and line.strip():
            current["files"].append(line.strip())
    dates = [commit["date"] for commit in commits if commit.get("date")]
    return commits, sorted(set(dates)), commits[-1]["hash"] if commits else None, commits[0]["hash"] if commits else None


def skipped_git_record(index: int, category: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return telemetry_record(index, category, "skipped", parameters, None, [], "git_log", "low", ["no git history available"])


def day_gaps(dates: list[str]) -> list[int]:
    parsed = [datetime.strptime(date, "%Y-%m-%d").date() for date in sorted(set(dates))]
    return [(right - left).days for left, right in zip(parsed, parsed[1:])]


def release_cadence_record(index: int, parameters: dict[str, Any], commits: list[dict[str, Any]], dates: list[str], tags: list[str]) -> dict[str, Any]:
    tag_dates: dict[str, str] = {}
    for commit in commits:
        for tag in commit.get("tags", []):
            tag_dates[str(tag)] = str(commit.get("date") or "")
    commit_gaps = day_gaps(dates)
    release_gaps = day_gaps([date for date in tag_dates.values() if date])
    active_days = day_gaps([dates[0], dates[-1]])[0] if len(dates) >= 2 else 0
    value = {
        "commit_count": len(commits),
        "tag_count": len(tags),
        "tags": tags,
        "tag_dates": tag_dates,
        "first_commit_date": dates[0] if dates else None,
        "last_commit_date": dates[-1] if dates else None,
        "active_days": active_days,
        "commits_per_month": round(len(commits) / max(active_days / 30.0, 1.0), 3),
        "commit_gap_days": commit_gaps,
        "max_commit_gap_days": max(commit_gaps) if commit_gaps else 0,
        "release_gap_days": release_gaps,
    }
    return telemetry_record(index, "release_cadence", "observed", parameters, value, [], "git_log_and_tags", "medium", ["cadence proxy from local git history and tags"])


def is_vendored_path(path: str) -> bool:
    parts = set(Path(path).parts)
    return bool(parts & VENDORED_PARTS)


def is_code_path(path: str) -> bool:
    return Path(path).suffix in CODE_SUFFIXES and not is_vendored_path(path)


def contributor_records(commits: list[dict[str, Any]], repo_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    mailmap = load_mailmap(repo_path)
    author_counts: Counter[str] = Counter()
    author_code_touch_counts: Counter[str] = Counter()
    author_files: dict[str, set[str]] = defaultdict(set)
    file_authors: dict[str, set[str]] = defaultdict(set)
    message_counts = {"total": 0, "conventional": 0, "issue_refs": 0, "signed_off_by": 0}
    for commit in commits:
        if is_bot_author(str(commit["author_name"]), str(commit["author_email"])):
            continue
        identity = pseudonymize_identity(normalize_identity(str(commit["author_name"]), str(commit["author_email"]), mailmap))
        author_counts[identity] += 1
        for path in commit.get("files", []):
            path_text = str(path)
            if is_vendored_path(path_text):
                continue
            file_authors[path_text].add(identity)
            author_files[identity].add(path_text)
            if is_code_path(path_text):
                author_code_touch_counts[identity] += 1
        subject = str(commit.get("subject") or "")
        message_counts["total"] += 1
        if re.match(r"^(feat|fix|docs|test|refactor|chore|perf|ci)(\(.+\))?:", subject):
            message_counts["conventional"] += 1
        if re.search(r"#\d+|[A-Z]+-\d+", subject):
            message_counts["issue_refs"] += 1
        if "signed-off-by:" in subject.lower():
            message_counts["signed_off_by"] += 1
    edges = sorted({" -- ".join(sorted(pair)) for authors in file_authors.values() for pair in combinations(authors, 2)})
    ownership_basis = author_code_touch_counts if author_code_touch_counts else author_counts
    total = sum(ownership_basis.values()) or 1
    cumulative = 0
    bus_50 = 0
    bus_80 = 0
    for index, count in enumerate((count for _, count in ownership_basis.most_common()), start=1):
        cumulative += count
        if bus_50 == 0 and cumulative / total >= 0.50:
            bus_50 = index
        if bus_80 == 0 and cumulative / total >= 0.80:
            bus_80 = index
    shares = [count / total for _, count in ownership_basis.most_common()]
    return (
        {"contributors": [{"identity": identity, "commit_count": count, "file_touch_count": len(author_files[identity]), "code_touch_count": author_code_touch_counts[identity]} for identity, count in author_counts.most_common()], "co_touch_edges": edges},
        {"min_contributors_50pct": bus_50, "min_contributors_80pct": bus_80, "basis": "code_touch_count" if author_code_touch_counts else "commit_count"},
        {"top_1": sum(shares[:1]), "top_3": sum(shares[:3]), "top_10": sum(shares[:10]), "basis": "code_touch_count" if author_code_touch_counts else "commit_count"},
        message_counts,
    )


def git_metric_records(start_index: int, parameters: dict[str, Any], repo_path: Path, commits: list[dict[str, Any]], dates: list[str], tags: list[str]) -> list[dict[str, Any]]:
    contributors, bus_factor, ownership, messages = contributor_records(commits, repo_path)
    return [
        release_cadence_record(start_index, parameters, commits, dates, tags),
        telemetry_record(start_index + 1, "contributors_graph", "observed", parameters, contributors, [], "git_log", "medium", ["bot authors excluded by deterministic filter"]),
        telemetry_record(start_index + 2, "bus_factor_proxy", "observed", parameters, bus_factor, [], "git_log", "medium", ["proxy only; not a definitive organizational risk proof"]),
        telemetry_record(start_index + 3, "ownership_concentration", "observed", parameters, ownership, [], "git_log", "medium", ["proxy based on non-vendored code/file touches when available"]),
        telemetry_record(start_index + 4, "commit_message_quality_signal", "observed", parameters, messages, [], "git_log", "medium", ["subject-line proxy only"]),
    ]


def manifest_paths_from_records(manifests: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for record in manifests.get("records", []):
        if not isinstance(record, dict) or record.get("skipped"):
            continue
        path_value = str(record.get("path") or "")
        if path_value and Path(path_value).name in MANIFEST_NAMES:
            paths.append(path_value)
    return sorted(set(paths))


def dependency_line_signal(line: str) -> str | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith(("#", "//")):
        return None
    if re.search(r"([A-Za-z0-9_.@/-]+)\s*(==|~=|>=|<=|=|:|@|\^|~)\s*[vV]?\d", cleaned):
        return cleaned[:200]
    if re.search(r"\b(require|dependencies|devDependencies)\b", cleaned):
        return cleaned[:200]
    return None


def manifest_history(repo_path: Path, manifest_paths: list[str], parameters: dict[str, Any]) -> dict[str, Any]:
    if not manifest_paths:
        return {"available": False, "events": [], "changed_dependency_lines": 0}
    args = [
        "log",
        f"--since={parameters['time_window_start']}",
        f"--until={parameters['time_window_end']}",
        "--format=__COMMIT__%x1f%H%x1f%ad",
        "--date=short",
        "--patch",
        "--unified=0",
        "--",
        *manifest_paths,
    ]
    completed, _ = run_git_command(repo_path, args)
    if completed.returncode != 0 or not completed.stdout.strip():
        return {"available": False, "events": [], "changed_dependency_lines": 0}
    events: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_path: str | None = None
    changed_lines = 0
    for line in completed.stdout.splitlines():
        if line.startswith("__COMMIT__"):
            parts = line.split("\x1f")
            current = {"commit": parts[1], "date": parts[2] if len(parts) > 2 else None, "paths": set(), "dependency_line_changes": 0}
            events.append(current)
            current_path = None
            continue
        if line.startswith("diff --git "):
            match = re.search(r" b/(.+)$", line)
            current_path = match.group(1) if match else None
            if current is not None and current_path:
                current["paths"].add(current_path)
            continue
        if current is None or line.startswith(("+++", "---")) or not line.startswith(("+", "-")):
            continue
        signal = dependency_line_signal(line[1:])
        if signal:
            current["dependency_line_changes"] += 1
            changed_lines += 1
    serializable = [{"commit": event["commit"], "date": event["date"], "paths": sorted(event["paths"]), "dependency_line_changes": event["dependency_line_changes"]} for event in events]
    return {"available": True, "events": serializable, "changed_dependency_lines": changed_lines}


def dependency_churn_record(index: int, manifests: dict[str, Any], parameters: dict[str, Any], repo_path: Path, git_available: bool) -> dict[str, Any]:
    deps: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    for record in manifests.get("records", []):
        if not isinstance(record, dict) or record.get("skipped"):
            continue
        evidence_ids.extend(record.get("evidence_ids") or [])
        for dep in record.get("dependencies") or []:
            if isinstance(dep, dict):
                deps.append(dep)
    if deps:
        history = manifest_history(repo_path, manifest_paths_from_records(manifests), parameters) if git_available else {"available": False, "events": [], "changed_dependency_lines": 0}
        if history["available"]:
            value = {
                "dependency_count": len(deps),
                "current_manifest_only": False,
                "manifest_history": history,
            }
            limitations = ["manifest history is derived from git patch lines; dependency parser remains conservative"]
            return telemetry_record(index, "dependency_upgrade_churn", "observed", parameters, value, sorted(set(evidence_ids)), "manifest_git_history", "medium", limitations)
        return telemetry_record(index, "dependency_upgrade_churn", "observed", parameters, {"dependency_count": len(deps), "current_manifest_only": True}, sorted(set(evidence_ids)), "current_manifest", "low", ["no manifest history comparison available"])
    return telemetry_record(index, "dependency_upgrade_churn", "skipped", parameters, None, [], "current_manifest", "low", ["no dependency manifest records found"])


def api_doc_record(index: int, file_index: dict[str, Any], evidence_lookup: dict[str, str], parameters: dict[str, Any]) -> dict[str, Any]:
    paths: list[str] = []
    evidence_ids: list[str] = []
    for record in file_index.get("records", []):
        if not isinstance(record, dict):
            continue
        path_value = str(record.get("path_normalized") or record.get("path") or "")
        lowered = path_value.lower()
        if any(token in lowered for token in ["api", "openapi", "swagger"]):
            paths.append(path_value)
            if evidence_lookup.get(path_value):
                evidence_ids.append(evidence_lookup[path_value])
    if paths:
        return telemetry_record(index, "api_doc_extraction", "observed", parameters, {"paths": paths}, sorted(set(evidence_ids)), "file_index", "medium", [])
    return telemetry_record(index, "api_doc_extraction", "skipped", parameters, None, [], "file_index", "low", ["no API documentation signal found"])


def validate_github_target(target: str) -> str:
    if not GITHUB_TARGET_PATTERN.fullmatch(target) or ".." in target:
        raise ValueError("GitHub target must be owner/repo without traversal")
    return target


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise HTTPError(req.full_url, code, "redirect blocked", headers, fp)


def fetch_github_repo_signals(target: str) -> dict[str, Any]:
    target = validate_github_target(target)
    base = f"https://api.github.com/repos/{target}"
    endpoints = {
        "repo": base,
        "releases": f"{base}/releases?per_page=10",
        "issues_sample": f"{base}/issues?state=all&per_page=10",
        "pulls_sample": f"{base}/pulls?state=all&per_page=10",
    }
    responses: dict[str, Any] = {}
    opener = build_opener(NoRedirectHandler)
    for key, url in endpoints.items():
        request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "agentic-deep-audit"})
        with opener.open(request, timeout=5) as response:  # noqa: S310 - guarded by explicit network policy.
            responses[key] = json.loads(response.read().decode("utf-8"))
    repo = responses.get("repo") if isinstance(responses.get("repo"), dict) else {}
    releases = responses.get("releases") if isinstance(responses.get("releases"), list) else []
    issues = responses.get("issues_sample") if isinstance(responses.get("issues_sample"), list) else []
    pulls = responses.get("pulls_sample") if isinstance(responses.get("pulls_sample"), list) else []
    return {
        "target": target,
        "open_issues_count": repo.get("open_issues_count"),
        "stars": repo.get("stargazers_count"),
        "forks": repo.get("forks_count"),
        "default_branch": repo.get("default_branch"),
        "sampled_issue_count": len([issue for issue in issues if "pull_request" not in issue]),
        "sampled_pr_count": len(pulls),
        "sampled_release_count": len(releases),
        "latest_release": releases[0].get("tag_name") if releases and isinstance(releases[0], dict) else None,
    }


def issue_pr_record(index: int, audit_dir: Path, parameters: dict[str, Any], provenance: dict[str, Any], fetcher: Any = fetch_github_repo_signals) -> dict[str, Any]:
    snapshot = audit_dir / ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"]
    if not snapshot.exists():
        return telemetry_record(index, "issue_pr_signals", "skipped", parameters, None, [], "github_metadata", "low", ["network metadata disabled or GitHub target unavailable"])
    policy = load_json(snapshot)
    if not decide_network("api.github.com", policy=policy).allowed:
        return telemetry_record(index, "issue_pr_signals", "skipped", parameters, None, [], "github_metadata", "low", ["network policy blocks GitHub metadata"])
    github = provenance.get("github") if isinstance(provenance.get("github"), dict) else {}
    target = github.get("target")
    if not isinstance(target, str) or "/" not in target:
        return telemetry_record(index, "issue_pr_signals", "skipped", parameters, None, [], "github_metadata", "low", ["GitHub target unavailable"])
    try:
        target = validate_github_target(target)
    except ValueError:
        return telemetry_record(index, "issue_pr_signals", "skipped", parameters, None, [], "github_metadata", "low", ["GitHub target invalid"])
    try:
        value = fetcher(target)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return telemetry_record(index, "issue_pr_signals", "skipped", parameters, None, [], "github_metadata", "low", [f"GitHub metadata request failed: {type(exc).__name__}"])
    return telemetry_record(index, "issue_pr_signals", "observed", parameters, value, [], "github_api", "medium", ["network metadata fetched only after explicit policy allow"])


def telemetry_markdown(records: list[dict[str, Any]]) -> str:
    lines = ["# Project Telemetry", ""]
    for record in records:
        lines.extend(
            [
                f"## {record['category']}",
                "",
                f"- Status: {record['status']}",
                f"- Source: {record['source']}",
                f"- Confidence: {record['confidence']}",
                f"- Caveats: {', '.join(record['limitations']) if record['limitations'] else 'none'}",
                "",
            ]
        )
    return "\n".join(lines)


def run_project_telemetry(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    provenance = load_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"])
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"]) if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() else {"records": []}
    evidence_lookup = evidence_by_path(audit_dir)
    repo_path = Path(str((file_index.get("repo") or run_config.get("repo") or {}).get("path") or ".")).resolve()
    records: list[dict[str, Any]] = []
    git = provenance.get("git") if isinstance(provenance.get("git"), dict) else {}
    base_params = default_parameters(as_of=str(provenance.get("generated_at") or ""))
    records.append(parse_changelog(repo_path, file_index, evidence_lookup, base_params, len(records) + 1))
    git_available = False
    if git.get("status") != "observed":
        records.extend(skipped_git_record(len(records) + offset + 1, category, base_params) for offset, category in enumerate(["release_cadence", "contributors_graph", "bus_factor_proxy", "ownership_concentration", "commit_message_quality_signal"]))
    else:
        commits, dates, from_ref, to_ref = git_history(repo_path, base_params)
        params = default_parameters(from_ref=from_ref, to_ref=to_ref, as_of=str(provenance.get("generated_at") or ""))
        git_available = bool(commits)
        records.extend(git_metric_records(len(records) + 1, params, repo_path, commits, dates, list(git.get("tags") or [])))
    records.append(dependency_churn_record(len(records) + 1, manifests, base_params, repo_path, git_available))
    records.append(api_doc_record(len(records) + 1, file_index, evidence_lookup, base_params))
    records.append(issue_pr_record(len(records) + 1, audit_dir, base_params, provenance))
    ordered = sorted(records, key=lambda item: CATEGORIES.index(item["category"]))
    for index, record in enumerate(ordered, start=1):
        record["telemetry_id"] = f"tel-{index:06d}"
    write_json(audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY"], {"schema_version": "1.0", "run_id": run_config.get("run_id"), "records": ordered})
    (audit_dir / ARTIFACT_PATHS["PROJECT_TELEMETRY_MD"]).write_text(telemetry_markdown(ordered), encoding="utf-8")
