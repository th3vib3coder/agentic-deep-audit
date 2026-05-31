# Generic CI Adapter

Status: `documented-beta`. This adapter documents how to run the package-root gates on any CI
system other than GitHub Actions (which has its own first-class adapter, `github-actions.md`).
It declares the nine required adapter-doc fields from `docs/contracts/adapter_contract.md`.

Target CI systems (documented, not yet per-system verified): **GitLab CI**, **Azure
Pipelines**, **Buildkite**. Each is `unverified` until a green run on that system is recorded.

## adapter id

`ci`

## user entry command

Invoke the package-root gates from a CI job in either shell. The commands are identical across
systems; only the YAML/pipeline wrapper differs.

```bash
PYTHONPATH=src python -m agentic_deep_audit.cli --help        # CLI smoke; no agent host required
python -m pytest tests -q                                     # unit suite
python -m pytest tests --collect-only -q -p no:cacheprovider  # stable collected test count
```

```powershell
$env:PYTHONPATH = "src"; python -m agentic_deep_audit.cli --help
python -m pytest tests -q
python -m pytest tests --collect-only -q -p no:cacheprovider
```

## required files

None beyond the package itself. The CI wrapper config (`.gitlab-ci.yml`, `azure-pipelines.yml`,
`.buildkite/pipeline.yml`) lives in the host CI system and is the maintainer's to author; this
repository ships no such file for these systems.

## optional files

A pipeline config for the chosen CI system, plus the cross-shell release-gate runbooks
`docs/contracts/release_gates_bash.md` and `docs/contracts/release_gates_powershell.md`.

## output directory

CI run logs (host-managed, ephemeral) plus the generated `audit/` artifacts. Nothing is written
outside the runner workspace.

## security model

- target-repo code execution: none beyond the package's own test suite;
- network: only the runner's package install step; audit logic runs network-denied;
- host config access: none — CI runners carry no developer host config;
- credentials: the gates need no secrets;
- redaction verification: the provenance redaction tests run as part of the unit suite;
- write permissions: confined to the runner workspace (`audit/`, `.audit-tmp/`).

## expected skipped/deferred behavior

GitLab CI, Azure Pipelines and Buildkite are documented targets, not per-system validation-
tested; each stays `unverified` until a green run is recorded. Git-dependent provenance tests
skip cleanly if `git` is unavailable on the runner and must be surfaced (`-rs`), not hidden.

## validation command

`python -m pytest tests/test_adapter_ci_docs.py -q`

## ownership of docs/tests

`tests/test_adapter_ci_docs.py`.
