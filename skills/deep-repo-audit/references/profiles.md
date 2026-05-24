# Profiles And Fallbacks

Profile selection controls expected depth, not truth status. `TOOL_STATUS.json` remains the observed source for a concrete run.

## Minimal Offline

- Produced: config normalization, inventory, provenance, manifests, static graph, public surfaces, synthesis, wiki, canonical graph, corpus when SQLite FTS5 is available, validation report.
- Skipped/gated: GitHub metadata without network policy, Graphify, MCP host writes, binary triage and external security tooling.

## Standard Local

- Produced: Minimal outputs plus SBOM when Syft/cdxgen is available, local SAST results when a promoted adapter exists, license scan, supported-language module graph, SQLite+FTS5 corpus with hybrid retrieval, Graphify output or fallback renderer/skipped note, and deeper risk report.
- Skipped/gated: SBOM, SAST and Graphify are skipped or deferred when tools are unavailable, unpromoted or policy-blocked; external CVE, package registry and cloud tools remain gated.

## Extended With MCP/Cloud

- Produced: Standard outputs plus GitHub metadata, issue/PR/release/CI insight, current CVE and security advisory data, external scorecards, advanced graph/code intelligence and optional read-only MCP config.
- Skipped/gated: requires `.network_policy.json`, scope-limited credentials and deterministic redaction; missing policy skips network adapters; host MCP collision or unreadable host config produces `MCP_DEFERRED.md` or `MCP_COLLISION_REPORT.md`.

## Research/Binary

- Produced: Standard outputs plus binary artifact triage and scientific provenance when explicit signals exist.
- Skipped/gated: binary analysis requires `binary_triage_consent`; scientific claims require provenance records for versions, organism/taxon, annotation, seed and confounders or an open question.

## Windows Fallback

Windows is supported through the same Python package and artifact contracts. Optional tool availability is qualitative until recorded in `TOOL_STATUS.json`. Path normalization differences and missing commands must be recorded as skipped/degraded rather than hidden.
