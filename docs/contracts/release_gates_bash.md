# Release Gates — POSIX Bash

Run these gates from the **public package root** (the exported engine package) before any
public push. Every command is a package-root command; none reference private planning
material. The authoritative leak gate is the Python test `tests/test_public_root_export.py`
— the `rg` scans below are human aids and require ripgrep on `PATH`; if `rg` is absent they
do not evaluate the tree, so rely on the Python test, not a non-zero `rg` exit.

This is the Bash rendering. `release_gates_powershell.md` is its behavioural twin for
Windows PowerShell; the two must stay in lockstep.

## Core gates

### Unit suite

```bash
python -m pytest tests -q
```

All package tests must pass in the public-root layout.

### Collect-only (stable test count)

```bash
python -m pytest tests --collect-only -q -p no:cacheprovider
```

Record the collected test count in `RELEASE_CHECKLIST.md`.

### CLI smoke (works without any agent host)

```bash
PYTHONPATH=src python -m agentic_deep_audit.cli --help   # PYTHONPATH only when not pip-installed
```

The CLI must print help and exit `0` with no agent host present.

### Compile

```bash
python -m compileall -q -x "tests[\\/]fixtures" src tests
```

## Public-root scan

Rejects committed private planning paths and planning language in shipped file content.
Exit `0` only when no private planning token is found in scanned content.

```bash
bad="$(rg -n 'piano_doc|plugins[/\\]agentic-deep-audit|C:\\\\Users|nuove_skill|013_ledger|HAT 2' . --glob '!tests/fixtures/**' --glob '!.git/**' --glob '!docs/contracts/release_gates_powershell.md' --glob '!docs/contracts/release_gates_bash.md' --glob '!RELEASE_CHECKLIST.md' --glob '!tests/test_public_root_export.py')"
status=$?
if [ "$status" -eq 0 ]; then printf '%s\n' "$bad"; exit 1; fi
if [ "$status" -eq 1 ]; then exit 0; fi
exit "$status"
```

Caches, a committed generated `audit/` output, the wrapper path and private review ledgers
are enforced as forbidden tree entries by `tests/test_public_root_export.py`, not as content
tokens — those names collide with legitimate engine identifiers.

## Adapter path scan

Rejects framing any single host as the whole product. Exit `0` only when no host-exclusive
phrasing remains. The harder adapter-name asymmetry (an identity string naming one primary
agent while omitting the co-equal other) is enforced by
`tests/test_release_packaging.py::test_identity_surfaces_name_both_primary_agents_or_neither`;
both must pass.

```bash
bad="$(rg -n 'Codex v1 plugin|Evidence-first Codex plugin|Codex-only|required by Codex|Claude-only|required by Claude' README.md pyproject.toml RELEASE_CHECKLIST.md docs skills .codex-plugin .claude-plugin hooks --glob '!tests/fixtures/**')"
status=$?
if [ "$status" -eq 0 ]; then printf '%s\n' "$bad"; exit 1; fi
if [ "$status" -eq 1 ]; then exit 0; fi
exit "$status"
```

This runbook quotes the alternation pattern, so the scan will self-match this file and its
PowerShell twin; treat matches confined to the two release-gate runbooks as expected, or add
`--glob '!docs/contracts/release_gates_*.md'` when running the scan by hand.

## Wheel install smoke

Build the wheel, install it into a clean virtual environment, and confirm the `deep-audit`
entry point works — all from the public package root.

```bash
rm -rf .audit-tmp/install-smoke .audit-tmp/wheelhouse
python -m venv .audit-tmp/install-smoke
.audit-tmp/install-smoke/bin/python -m pip install --upgrade pip
.audit-tmp/install-smoke/bin/python -m pip wheel . -w .audit-tmp/wheelhouse
wheel="$(find .audit-tmp/wheelhouse -name 'agentic_deep_audit-*.whl' | head -n 1)"
.audit-tmp/install-smoke/bin/python -m pip install "$wheel"
.audit-tmp/install-smoke/bin/deep-audit --help
```

Expected: the wheel exists, install succeeds, and `bin/deep-audit --help` exits `0`. The
Windows path convention (`Scripts\deep-audit.exe`) is covered in `release_gates_powershell.md`.
