# Audit Contract

The audit pipeline is deterministic first and agentic second. Scripts produce structured artifacts; agents enrich only from persisted evidence.

## Phase 0 - Bootstrap Secure Run

Normalize config, snapshot policy files, initialize `audit/`, record `RUN_CONFIG.json`, `TOOL_STATUS.json` and `PROGRESS.md`.

## Phase 1 - Inventory And Provenance

Enumerate files, hashes, binary flags, repository metadata and provenance without executing target code.

## Phase 2 - Manifests, Build, Test And CI

Parse manifests, lockfiles, build files and CI files as observed data. Do not execute discovered commands.

## Phase 3 - Code Graph And Module Graph

Build module graph, symbol index, optional call graph or skipped rationale, and baseline architecture.

## Phase 4 - Public Surfaces

Extract API, CLI, MCP, plugin, config, environment and permission surfaces with evidence links.

## Phase 5 - Features, Patterns And Reuse Candidates

Synthesize features, architecture patterns, special implementations and scientific provenance from validated evidence.

## Phase 6 - Risk, Supply Chain And Licenses

Run allowed policy-checked adapters or deterministic fallbacks for risk, supply chain, license and binary artifact signals.

## Phase 7 - Performance, Quality And Reuse

Separate observed benchmarks from static proxies, record project telemetry and produce context-aware reuse cards.

## Phase 8 - Wiki, Graph And Corpus

Generate Obsidian-compatible wiki pages, canonical graph exports, corpus index, optional FTS and optional MCP artifacts.

## Phase 9 - Validation, Report And Review Packet

Validate schemas, links, evidence coverage and safety gates; then emit final report, open questions and adversarial review packet.
