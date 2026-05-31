# Release Gates — Windows PowerShell

Run these gates from the **public package root** (the exported engine package) before any
public push. Every command is a package-root command; none reference private planning
material. The authoritative leak gate is the Python test `tests/test_public_root_export.py`
— the `rg` scans below are human aids and require ripgrep on `PATH`; if `rg` is absent they
do not evaluate the tree, so rely on the Python test, not a non-zero `rg` exit.

This is the PowerShell rendering. `release_gates_bash.md` is its behavioural twin for POSIX
shells; the two must stay in lockstep.

## Core gates

### Unit suite

```powershell
python -m pytest tests -q
```

All package tests must pass in the public-root layout.

### Collect-only (stable test count)

```powershell
python -m pytest tests --collect-only -q -p no:cacheprovider
```

Record the collected test count in `RELEASE_CHECKLIST.md`.

### CLI smoke (works without any agent host)

```powershell
$env:PYTHONPATH = "src"   # only when not pip-installed
python -m agentic_deep_audit.cli --help
```

The CLI must print help and exit `0` with no agent host present.

### Compile

```powershell
python -m compileall -q -x "tests[\\/]fixtures" src tests
```

## Public-root scan

Rejects committed private planning paths and planning language in shipped file content.
Exit `0` only when no private planning token is found in scanned content.

```powershell
$bad = rg -n "piano_doc|plugins[/\\]agentic-deep-audit|C:\\\\Users|nuove_skill|013_ledger|HAT 2" . --glob "!tests/fixtures/**" --glob "!.git/**" --glob "!docs/contracts/release_gates_powershell.md" --glob "!docs/contracts/release_gates_bash.md" --glob "!RELEASE_CHECKLIST.md" --glob "!tests/test_public_root_export.py"
if ($LASTEXITCODE -eq 0) { $bad; exit 1 }
if ($LASTEXITCODE -eq 1) { exit 0 }
exit $LASTEXITCODE
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

```powershell
$bad = rg -n "Codex v1 plugin|Evidence-first Codex plugin|Codex-only|required by Codex|Claude-only|required by Claude" README.md pyproject.toml RELEASE_CHECKLIST.md docs skills .codex-plugin .claude-plugin hooks --glob "!tests/fixtures/**"
if ($LASTEXITCODE -eq 0) { $bad; exit 1 }
if ($LASTEXITCODE -eq 1) { exit 0 }
exit $LASTEXITCODE
```

This runbook quotes the alternation pattern, so the scan will self-match this file and its
POSIX twin; treat matches confined to the two release-gate runbooks as expected, or add
`--glob "!docs/contracts/release_gates_*.md"` when running the scan by hand.

## Wheel install smoke

Build the wheel, install it into a clean virtual environment, and confirm the `deep-audit`
entry point works — all from the public package root.

```powershell
Remove-Item -Recurse -Force .audit-tmp/install-smoke -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .audit-tmp/wheelhouse -ErrorAction SilentlyContinue
python -m venv .audit-tmp/install-smoke
.\.audit-tmp\install-smoke\Scripts\python.exe -m pip install --upgrade pip
.\.audit-tmp\install-smoke\Scripts\python.exe -m pip wheel . -w .audit-tmp\wheelhouse
$wheel = Get-ChildItem .audit-tmp\wheelhouse\agentic_deep_audit-*.whl | Select-Object -First 1
.\.audit-tmp\install-smoke\Scripts\python.exe -m pip install $wheel.FullName
.\.audit-tmp\install-smoke\Scripts\deep-audit.exe --help
```

Expected: the wheel exists, install succeeds, and `deep-audit.exe --help` exits `0`. The
POSIX path convention (`bin/deep-audit`) is covered in `release_gates_bash.md`.
