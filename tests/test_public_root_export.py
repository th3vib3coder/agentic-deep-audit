"""Authoritative public-root leak gate (S-E01a).

Scans the GIT-TRACKED package tree (what actually ships) for forbidden private-planning
TREE ENTRIES and CONTENT TOKENS per 006 §"Concrete scan commands". Runs in both the monorepo
package subtree and the exported publish-root. The `rg` snippets in the release-gate docs are
human aids; THIS test is the source of truth.
"""

from __future__ import annotations

import re
import subprocess

from agentic_deep_audit.models import PLUGIN_ROOT


# --- Content tokens (006 §Forbidden CONTENT TOKENS). NOT REVIEW_LEDGER / operator_go / bare
# audit/ — those collide with shipped-engine identifiers and are caught by the TREE scan. ---
FORBIDDEN_CONTENT_TOKENS = ("piano_doc", "nuove_skill", "013_ledger", "HAT 2")
FORBIDDEN_CONTENT_REGEXES = (re.compile(r"plugins[/\\]agentic-deep-audit"), re.compile(r"C:\\Users"))

# Whole-file content allowlist (006 §Content-scan allowlist) + the Phase-C/D leak-detection
# tests, which legitimately embed the tokens to assert AGAINST them (they ship but are not leaks).
WHOLE_FILE_CONTENT_ALLOWLIST = {
    "docs/contracts/release_gates_powershell.md",
    "docs/contracts/release_gates_bash.md",
    "tests/test_public_root_export.py",
    "tests/test_adapter_ci_docs.py",
    "tests/test_adapter_claude_code_docs.py",
    "tests/test_ci_workflows.py",
    "tests/test_release_gate_docs.py",
    "tests/test_validate_cli.py",
}

# Fenced-block-only: documented scan commands inside ```-fences are allowed; prose is still scanned.
FENCED_BLOCK_ONLY = {"RELEASE_CHECKLIST.md"}

# Planning-only checkers + their tests require a piano_doc/ planning workspace and ship no product
# value; they are dropped from the public export (sync-gate exclusion, S-E01b.3) and are therefore
# not scanned here. This set mirrors the planning-checker SUBSET of the sync's $publishExclusions;
# the relocated review ledgers are NOT listed here — they are no longer tracked under the package,
# so the tree scan (test_no_private_named_paths_in_tree) owns them.
EXPORT_EXCLUDED = {
    "tests/check_plan_traceability.py",
    "tests/test_plan_traceability.py",
    "tests/check_seq_atomicity.py",
    "tests/test_seq_atomicity.py",
}

# Fixture data (sample target repos) may legitimately embed tokens; 006 excludes tests/fixtures/**
# from the CONTENT scan. Fixture file NAMES remain covered by the tree scan above.
CONTENT_SKIP_PREFIXES = ("tests/fixtures/",)


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(PLUGIN_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def test_no_private_named_paths_in_tree() -> None:
    offenders: list[str] = []
    for rel in _tracked_files():
        top = rel.split("/", 1)[0]
        if top in {"piano_doc", ".pytest_cache", ".audit-tmp", "audit"}:
            offenders.append(rel)
        if rel.startswith("plugins/agentic-deep-audit/"):
            offenders.append(rel)  # the public root must not nest the wrapper path
        if "/" not in rel and (
            rel in {"REVIEW_LEDGER.md", "REVIEWER_PROTOCOL.md"}
            or re.fullmatch(r"REVIEW_LEDGER_ARCHIVE_\d+\.md", rel)
        ):
            offenders.append(rel)
    assert not offenders, f"forbidden private tree entries (git-tracked): {sorted(set(offenders))}"


def _strip_fenced(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def test_no_private_path_strings_in_contents() -> None:
    offenders: list[str] = []
    for rel in _tracked_files():
        if rel in WHOLE_FILE_CONTENT_ALLOWLIST or rel in EXPORT_EXCLUDED:
            continue
        if any(rel.startswith(prefix) for prefix in CONTENT_SKIP_PREFIXES):
            continue
        try:
            text = (PLUGIN_ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary / unreadable: names are covered by the tree scan
        scan = _strip_fenced(text) if rel in FENCED_BLOCK_ONLY else text
        hits = [tok for tok in FORBIDDEN_CONTENT_TOKENS if tok in scan]
        hits += [rx.pattern for rx in FORBIDDEN_CONTENT_REGEXES if rx.search(scan)]
        if hits:
            offenders.append(f"{rel}: {hits}")
    assert not offenders, "private content tokens in shipped files:\n" + "\n".join(sorted(offenders))


def test_release_checklist_documents_public_root_scan() -> None:
    # S-E01d: the release checklist must point operators at this authoritative gate.
    text = (PLUGIN_ROOT / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    assert "## Public-Root Scan Commands" in text
    assert "tests/test_public_root_export.py" in text
