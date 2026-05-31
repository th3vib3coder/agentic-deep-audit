# Package Managers Adapter

Status: `staged-beta` (target `verified` per OS, after a green install smoke on that OS). The
package-managers adapter installs the engine as a CLI app via `pip` or `pipx` and confirms the
`deep-audit` entry point works. It declares the nine required adapter-doc fields from
`docs/contracts/adapter_contract.md`.

## adapter id

`package-managers`

## user entry command

`pip install` (into a virtual environment) or `pipx install` (isolated app), then `deep-audit
--help`. See the per-shell install sequences below.

### pip — Windows PowerShell

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

### pip — POSIX Bash

```bash
rm -rf .audit-tmp/install-smoke .audit-tmp/wheelhouse
python -m venv .audit-tmp/install-smoke
.audit-tmp/install-smoke/bin/python -m pip install --upgrade pip
.audit-tmp/install-smoke/bin/python -m pip wheel . -w .audit-tmp/wheelhouse
wheel="$(find .audit-tmp/wheelhouse -name 'agentic_deep_audit-*.whl' | head -n 1)"
.audit-tmp/install-smoke/bin/python -m pip install "$wheel"
.audit-tmp/install-smoke/bin/deep-audit --help
```

### pipx — both shells

```bash
pipx install .        # isolated CLI app; exposes deep-audit on PATH
deep-audit --help
```

```powershell
pipx install .
deep-audit --help
```

## required files

- `pyproject.toml` — declares the `deep-audit` console entry point under `[project.scripts]`.

## optional files

- a built wheel under `.audit-tmp/wheelhouse/` for offline install.

## output directory

`.audit-tmp/` holds the build/install smoke artifacts; the installed `deep-audit` CLI writes the
`audit/` tree in whatever target repo it is run against.

## security model

- target-repo code execution: none beyond the package's own console entry point;
- network: `pip`/`pipx` reach the package index at install time (use a prebuilt wheel for an
  offline install); the audit itself runs network-denied;
- host config access: none — install touches no developer host config;
- credentials: none required;
- redaction verification: the installed-wheel resource and provenance tests cover the package;
- write permissions: install writes to the venv / pipx app dir and `.audit-tmp/` only.

## Security

The seven adapter security columns for `package-managers`:

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (static, read-only audit; nothing runs beyond the package's own console entry point) | `pip`/`pipx` reach the package index at install time (use a prebuilt wheel for an offline install); the audit itself runs network-denied (default-deny) | none (install touches no developer host config) | none read (none required) | covered by the provenance/MCP redaction tests and the installed-wheel resource tests | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | confined to the generated `audit/` output tree, plus the venv / pipx app dir and `.audit-tmp/` (build/install smoke) |

## expected skipped/deferred behavior

`conda` and OS system package managers (apt, brew, choco) are out of scope and not provided;
`pip` and `pipx` are the supported paths. The adapter stays `staged-beta` until a green install
smoke is recorded on each claimed OS. Windows exposes the entry point at
`Scripts\deep-audit.exe`; POSIX at `bin/deep-audit`.

## validation command

`python -m pytest tests/test_package_install_smoke.py tests/test_release_packaging.py -q`

## ownership of docs/tests

`tests/test_package_install_smoke.py`.
