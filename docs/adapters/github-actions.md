# GitHub Actions Adapter

Status: `staged-beta` (target `verified` per OS, granted only after a green CI run on that
runner). The GitHub Actions adapter runs the package-root gates across a cross-OS matrix. It
declares the nine required adapter-doc fields from `docs/contracts/adapter_contract.md`.

## adapter id

`github-actions`

## user entry command

Push to any branch or open a pull request — GitHub runs the matrix workflow automatically.
There is no separate per-user command; the workflow file is the entry surface. The same gates
run locally from the package root (`python -m pytest tests -q`, the release-gate runbooks in
`docs/contracts/release_gates_*.md`).

## required files

- `.github/workflows/agentic-deep-audit.yml` — the package-root workflow (matrix job).

## optional files

- a runbook extension documenting how to add a deferred runner (e.g. `macos-latest`) via a
  ledger amendment.

## output directory

CI run logs (GitHub-hosted, ephemeral) plus the generated `audit/` artifacts produced by the
smoke and git-dependent steps. Nothing is written outside the runner workspace.

## security model

- target-repo code execution: none beyond the package's own test suite;
- network: only the runner's package installs (`pip`); audit logic itself runs network-denied;
- host config access: none — the runner is ephemeral and carries no developer host config;
- credentials: no secrets are referenced by the workflow; it needs none;
- redaction verification: the git/GitHub provenance redaction tests run in the matrix;
- write permissions: confined to the runner workspace (`audit/`, `.audit-tmp/`).

## Security

The seven adapter security columns for `github-actions`:

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (the audit never executes target-repo code; only the package's own test suite runs) | the audit runs network-denied (default-deny); only the runner's package install (`pip`) uses network | none (the runner is ephemeral and carries no developer host config) | none read (no secrets are referenced by the workflow; it needs none) | covered by the provenance/MCP redaction tests, run as the git/GitHub provenance tests in the matrix | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | confined to the generated `audit/` output tree and `.audit-tmp/` (build/install smoke) within the runner workspace |

## expected skipped/deferred behavior

`macos-latest` is `deferred (SD-4)` — present only as a comment in the workflow matrix, never
an active job, until a green macOS run is recorded via ledger amendment. Python `3.13` may be
added as `staged-alpha`. The "git-dependent coverage must not skip" step asserts that
git/GitHub provenance tests do **not** silently skip on the runner.

## validation command

`python -m pytest tests/test_ci_workflows.py -q`

## ownership of docs/tests

`tests/test_ci_workflows.py`.

## Matrix scope (SD-4)

| Runner | Shell | Python versions | Status |
|---|---|---|---|
| `ubuntu-latest` | bash | `3.10`, `3.11`, `3.12` | `unverified` until green CI |
| `windows-latest` | bash (Git-Bash via `defaults.run.shell`) | `3.10`, `3.11`, `3.12` | `unverified` until green CI |
| `macos-latest` | — | — | `deferred (SD-4)` — add via ledger amendment |

The job sets `defaults.run.shell: bash` so the Bash idioms (`set -o pipefail`, `tee`, `grep`,
`mkdir -p`, line continuations) run identically on `windows-latest` (GitHub-hosted Windows
ships Git-Bash). No runner may be marketed as `verified` until its CI is green; macOS must not
be claimed until a `macos-latest` job is green.
