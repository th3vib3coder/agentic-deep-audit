# Tool Adapters

Optional tools cannot affect acceptance until promoted through an Adapter Promotion Gate.

## Contract

Each adapter has four operations:

- `detect`: find executable, version, platform support, license note and network needs.
- `run`: execute only policy-approved read-only commands with timeout and controlled output paths.
- `parse`: convert raw output into the plugin schema or emit a parser failure entry.
- `status`: append one `TOOL_STATUS.json` record for detected, skipped, blocked, failed or completed state.

## Adapter Promotion Gate

Before an industry-known or source-claim tool becomes operational, create a machine-checkable adapter decision record with installability, license, version pinning, read-only command, policy, observed schema output, fallback, decision and independent reviewer.

Decision values are `promote`, `defer` or `reject`. Without a promoted decision, the tool remains prior art and the core fallback must be used. Graphify is optional and isolated from canonical graph outputs unless its decision record is promoted. Source-claim tools must not be described as accepted runtime dependencies before promotion.

## Fallback

Missing optional tools are not fatal. They produce skipped status and honest coverage limits. Core Python stdlib paths must still produce minimal inventory, evidence, manifest detection, basic graph and validation scaffolding.
