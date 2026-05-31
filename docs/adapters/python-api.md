# Python API Adapter

Status: `documented-beta`. The Python API is a neutral integration surface for embedding the audit
engine in custom agents and scripts. It is documented and tested, but `documented-beta`: the public
surface and argument shapes may change before promotion. See the promotion contract below and
`docs/contracts/adapter_contract.md`. Do not market it as `first-class`/`verified`/`supported`.

## adapter id

`python-api`

## user entry command

Import the frozen public surface and call it:

```python
from agentic_deep_audit import bootstrap_audit, validate_audit

audit_dir = bootstrap_audit(run_config, cwd)   # phase-0 bootstrap of an audit directory
result = validate_audit(audit_dir)             # returns a ValidationResult (ok / errors / warnings)
```

## required files

- the installed `agentic-deep-audit` package.

## optional files

- a caller-supplied run config (dict or `audit.config.yaml`);
- a validated `.network_policy.json` (network is denied by default).

## output directory

Caller-specified via the run config `output_dir` (the portable `audit/` tree by default).

## security model

- target-repo code execution: blocked by default;
- network: denied by default;
- host config access: none; credentials are caller-owned injection only when policy allows;
- redaction verification: caller-payload redaction tests;
- write permissions: caller-specified audit output only.

## Security

The seven adapter security columns for `python-api`:

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (static, read-only audit; the engine never executes target-repo code) | denied (default-deny network policy) | none | none read (any credential is caller-owned injection only when policy allows) | covered by the provenance/caller-payload redaction tests | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | confined to the caller-specified `audit/` output tree |

## expected skipped/deferred behavior

Unavailable optional tools are recorded as `skipped`/`degraded` in the tool-status artifact; missing
optional tools are never presented as successful coverage.

## validation command

`python -m pytest tests/test_python_api_contract.py -q`

## ownership of docs/tests

`tests/test_python_api_contract.py` and `tests/test_adapter_docs_contract.py`.

## Promotion contract

The Python API starts `documented-beta`. Promotion to `first-class` requires, recorded in the
release checklist or review packet:

- a **frozen documented public API surface** — exactly `bootstrap_audit` and `validate_audit`,
  re-exported via `agentic_deep_audit.__all__`; adding a name requires a recorded amendment;
- a **semantic versioning (semver)** policy covering the public import paths and argument
  compatibility;
- tests proving **import-path stability** (this contract test);
- a published **deprecation policy**: a deprecation notice ships in the release notes at least one
  minor version before any public API is removed or changed incompatibly;
- a **promotion trigger**: three stable releases without breaking API changes, or explicit operator
  approval after external review.
