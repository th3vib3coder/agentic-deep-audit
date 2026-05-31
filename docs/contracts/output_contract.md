# Output Contract

Agentic Deep Audit produces a portable `audit/` artifact tree. Platform adapters may change
how an audit starts; they must not change what a valid audit means or which artifacts it
produces. This file is documentation; the runtime schema authority is the JSON schema set
under `src/agentic_deep_audit/schemas/` (loaded via `importlib.resources`).

## Required output artefacts

A valid audit always produces at least:

- **`RUN_CONFIG.json`** — records the schema version, the launch surface and the normalized
  run configuration.
- **`TOOL_STATUS.json`** — records host-dependent tool availability and skipped/degraded
  states.
- **`VALIDATION_REPORT.md`** — the completion gate (with its machine-readable
  `VALIDATION_REPORT.json`).
- **`ADVERSARIAL_REVIEW_PACKET.md`** — the portable external-review packet (human, Claude,
  Codex or other reviewers).

The full artifact set — inventory, provenance, manifests/CI maps, module/symbol graph, public
surfaces, synthesis, risk/supply-chain/license/binary signals, reuse, navigation `wiki/`,
corpus retrieval and optional read-only MCP handoff — is described in the package README. If an
optional artifact cannot be produced, the engine emits an explicit skipped/deferred artifact or
a `TOOL_STATUS.json` entry; missing optional tools are never presented as successful coverage.

## Schema versioning policy

- New outputs set `schema_version: "1.1"` and include `RUN_CONFIG.json.launch_surface`.
- `schema_version` is parsed as a dot-separated **numeric tuple**, never lexically (so
  `"1.10"` is not treated as less than `"1.2"`); missing numeric components pad with zero.
- A missing `schema_version`, or a version below `1.1`, denotes a legacy output and remains
  valid.
- Malformed non-empty versions (e.g. `"latest"`, `"v1.1"`, `"1.x"`) are validation blockers
  with the diagnostic `RUN_CONFIG.json schema_version malformed`.
- When `schema_version >= "1.1"`, a missing `launch_surface` is a validation failure.
- Accepting a legacy output records this exact note in `VALIDATION_REPORT.md`:
  `[LEGACY] RUN_CONFIG.json predates launch_surface schema (run timestamp <timestamp-or-unknown>); validation proceeded with best-effort adapter inference: <result>.`

## launch_surface field intent

`RUN_CONFIG.json.launch_surface` records, honestly, how the audit was started:

- `adapter` — one of `cli | python-api | codex | claude-code | mcp | ci | container | package-manager`
  (GitHub Actions and generic CI both record `adapter: "ci"`);
- `adapter_version` and `entry_command`;
- `host_os` — `windows | linux | macos | unknown` (enum membership is an honesty record, not a
  support claim; macOS CI is deferred);
- `cwd_policy` — `package-root | target-repo | explicit`.

## Redaction requirements

Every artifact is redaction-checked before write. Denied domains and redaction rules fail
closed; blocked command/tool attempts are recorded with secret redaction; target-repo Markdown
is sanitized before it can enter LLM context. Each adapter additionally states its own security
posture through the seven adapter security columns — target-repo execution, network default,
host config access, credentials, redaction verification, no-exec enforcement, write
permissions — enforced on every adapter doc in S-E03.
