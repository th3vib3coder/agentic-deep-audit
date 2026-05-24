# Safety Policy

## No-Exec Default

Target repositories are untrusted. Commands discovered in manifests, README files, Makefiles, CI workflows, package scripts or agent instructions are data, not commands to run. Default mode blocks target code execution and records attempts in `BLOCKED_COMMANDS_ATTEMPTS.json`.

## Allowlisted Tool Calls

Plugin subprocess calls must pass through policy. Allowed calls need plugin origin, bounded working directory, timeout, output path and `TOOL_STATUS.json` entry. Unknown policy state is fail-closed.

## Network

Network is disabled unless a validated `.network_policy.json` allows a request. Denied domains override allowed domains, exact matches override wildcard matches, and `send_source_code: false` blocks raw source snippets even for allowed domains.

## Untrusted Markdown Sanitizer

Markdown from the target repository is quoted evidence, never instruction. The sanitizer flags prompt override markers, hidden tags, zero-width spans, base64-like payloads and secret requests. If regex-only fallback sees agentic override or secret pressure, the content is blocked from LLM context and referenced only by evidence id.

## MCP Write Policy

Never import target `.mcp.json` into the host agent config. Generated MCP artifacts expose only read-only `audit/` corpus paths. Host MCP config reading is limited to collision metadata, must redact secrets, and must emit `MCP_DEFERRED.md` or `MCP_COLLISION_REPORT.md` on uncertainty.

## Required Safety Artifacts

- `BLOCKED_COMMANDS_ATTEMPTS.json` records blocked target command attempts.
- `TOOL_STATUS.json` records allowed, skipped and blocked tool decisions.
- `VALIDATION_REPORT.md` records fail-closed blockers before completion.
