"""Contract tests for the adapter-documentation contract.

These tests assert that the *contract* docs under ``docs/contracts/`` enumerate the
closed adapter-doc list and the nine required adapter-doc fields (S-A02), the closed
status enum and demotion-evidence fields (S-A03), and — later — the seven security
columns on every adapter doc (S-E03).

They deliberately do NOT assert that the nine per-adapter docs under ``docs/adapters/``
exist; each adapter doc's RED/GREEN cycle belongs to its own owning step.

Package files are resolved via ``Path(__file__).resolve().parents[1]`` (the package
root), the convention used by ``tests/conftest.py`` and ``tests/test_release_packaging.py``,
so each assertion is invocation-independent across local shells and CI.
"""

import re
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = PACKAGE_ROOT / "docs" / "contracts"
ADAPTER_CONTRACT = CONTRACTS_DIR / "adapter_contract.md"
RELEASE_CHECKLIST = PACKAGE_ROOT / "RELEASE_CHECKLIST.md"

# Closed adapter-doc list — the nine required doc paths (003 "Closed adapter docs list").
NINE_ADAPTER_DOC_PATHS = (
    "docs/adapters/cli.md",
    "docs/adapters/python-api.md",
    "docs/adapters/codex.md",
    "docs/adapters/claude-code.md",
    "docs/adapters/mcp.md",
    "docs/adapters/github-actions.md",
    "docs/adapters/ci.md",
    "docs/adapters/container.md",
    "docs/adapters/package-managers.md",
)

# The nine required adapter-doc fields (003 "The nine required adapter-doc fields").
NINE_REQUIRED_FIELDS = (
    "adapter id",
    "user entry command",
    "required files",
    "optional files",
    "output directory",
    "security model",
    "expected skipped/deferred behavior",
    "validation command",
    "ownership of docs/tests",
)

# The closed status enum (003 "Status enum (closed — load-bearing)") — exactly twelve labels.
CLOSED_STATUS_ENUM = (
    "planned",
    "documented-beta",
    "first-class",
    "first-class-docs",
    "first-class-handoff",
    "optional",
    "deferred",
    "research-only",
    "staged-alpha",
    "staged-beta",
    "verified",
    "unverified",
)

# Demotion-evidence columns (006 "Demotion Rules"; S-A03).
DEMOTION_FIELDS = ("old status", "new status", "evidence", "next review gate")

# The seven per-adapter security columns (004; S-E03). Every adapter doc must declare all
# seven, and the contract reproduces the same matrix as the source of the standard.
SEVEN_SECURITY_COLUMNS = (
    "target execution",
    "network default",
    "host config access",
    "credentials",
    "redaction verification",
    "no-exec enforcement",
    "write permissions",
)


def test_each_adapter_doc_declares_seven_security_columns():
    missing_by_doc = {}
    for path in NINE_ADAPTER_DOC_PATHS:
        lowered = (PACKAGE_ROOT / path).read_text(encoding="utf-8").lower()
        missing = [column for column in SEVEN_SECURITY_COLUMNS if column not in lowered]
        if missing:
            missing_by_doc[path] = missing
    assert not missing_by_doc, (
        "every adapter doc must declare all seven security columns "
        f"{SEVEN_SECURITY_COLUMNS}; missing per doc: {missing_by_doc}"
    )


def test_adapter_contract_declares_security_matrix_columns():
    lowered = ADAPTER_CONTRACT.read_text(encoding="utf-8").lower()
    missing = [column for column in SEVEN_SECURITY_COLUMNS if column not in lowered]
    assert not missing, (
        "adapter_contract.md must define the security matrix with all seven columns; "
        f"missing: {missing}"
    )


def test_adapter_contract_declares_closed_doc_list_and_nine_fields():
    # read_text raises FileNotFoundError when the contract doc is absent (the RED state).
    text = ADAPTER_CONTRACT.read_text(encoding="utf-8")
    lowered = text.lower()

    missing_paths = [path for path in NINE_ADAPTER_DOC_PATHS if path not in text]
    assert not missing_paths, (
        f"adapter_contract.md must name every adapter doc path; missing: {missing_paths}"
    )

    missing_fields = [field for field in NINE_REQUIRED_FIELDS if field.lower() not in lowered]
    assert not missing_fields, (
        f"adapter_contract.md must define the nine required fields; missing: {missing_fields}"
    )


def _status_enum_section(text):
    """Return the body of the '## Status enum' section (up to the next '## ' heading or EOF)."""
    match = re.search(r"##\s+Status enum\b(.*?)(?=\n##\s|\Z)", text, re.DOTALL)
    return match.group(1) if match else ""


def test_adapter_contract_declares_only_closed_status_labels():
    text = ADAPTER_CONTRACT.read_text(encoding="utf-8")
    section = _status_enum_section(text)
    assert section.strip(), "adapter_contract.md must contain a '## Status enum' section"

    # The first backtick-quoted label in each enum table row (column 1).
    labels = set(re.findall(r"(?m)^\|\s*`([a-z][a-z0-9-]+)`\s*\|", section))
    expected = set(CLOSED_STATUS_ENUM)
    assert labels == expected, (
        "adapter_contract.md status enum must be EXACTLY the twelve closed labels; "
        f"missing={sorted(expected - labels)}, unexpected={sorted(labels - expected)}"
    )


def test_release_checklist_has_demotion_evidence_fields():
    text = RELEASE_CHECKLIST.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "demotion" in lowered, (
        "RELEASE_CHECKLIST.md must declare a demotion-evidence section"
    )
    missing = [field for field in DEMOTION_FIELDS if field not in lowered]
    assert not missing, (
        f"RELEASE_CHECKLIST.md demotion-evidence table missing columns: {missing}"
    )
