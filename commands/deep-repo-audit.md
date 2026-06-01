---
description: Run or plan an Agentic Deep Audit workflow for a local or GitHub repository.
argument-hint: [GitHub URL or target path or audit config]
---

# /deep-repo-audit

Use the `deep-repo-audit` skill and the installed `deep-audit` CLI suite.

## URL Mode

If the argument starts with `https://github.com/<owner>/<repo>`, run the URL workflow:

1. Validate the URL (URL threat model anchor: `003_threat_model_url.md`).
2. Invoke the CLI:

   ```powershell
   deep-audit url https://github.com/<owner>/<repo> --profile standard
   ```

3. Default `--output-dir` is `./audit_runs/<safe_repo_name>/`.
4. Default `--profile` is `standard` (supported profiles: `minimal`, `standard`, `extended`, `research`).
5. The target repository is cloned to `./audit_runs/<safe_repo_name>/_clone/` as an engine primitive bound by the network policy exception (anchor: `003b_network_policy_exception.md`).
6. The Phase 0-9 pipeline runs against the clone; no code from the target is executed.
7. Final audit artifacts land in `./audit_runs/<safe_repo_name>/audit/`.

Dry-run plan (no clone, no pipeline):

```powershell
deep-audit url https://github.com/<owner>/<repo> --dry-run
```

Errors:

- Invalid URL: exit 2.
- Clone failure: exit 3.
- Config failure: exit 4.
- Pipeline failure: exit 5 or the exit code propagated from `deep-audit run`.

The target repository is treated as untrusted: no scripts, install commands, hooks, or submodule fetching are executed during clone. The clone is bounded to `https://github.com/<owner>/<repo>` per the URL workflow threat model (anchor: `003_threat_model_url.md`) and the network policy exception (anchor: `003b_network_policy_exception.md`).

## Local Path Mode

Default behavior when the argument is a local path or an existing audit config:

1. Treat the target repository as untrusted input.
2. Read `skills/deep-repo-audit/references/audit_contract.md`, `profiles.md`, `safety_policy.md`, `output_artifacts.md`, and `review_protocol.md` before making coverage claims.
3. Prefer `deep-audit run --config audit.config.yaml` or `deep-audit validate --audit-dir audit` when a config or audit directory already exists.
4. Write only to the configured audit output directory unless the operator explicitly asks for package installation or project edits.
5. Record skipped optional tools explicitly in `TOOL_STATUS.json`; do not present missing coverage as success.

Common commands:

```powershell
deep-audit run --config audit.config.yaml
deep-audit validate --audit-dir audit
deep-audit run --config audit.config.yaml --dry-run
```

If no config exists, create a minimal `audit.config.yaml` only after confirming the target path and output directory.

## Release Sync

The source-of-truth for this command file is `<plugin>/commands/deep-repo-audit.md`. Release sync to the Codex CLI plugin cache (`~/.codex/plugins/cache/.../commands/`) happens through the Codex CLI plugin install or refresh step (see open question Q-NEW-4).
