# MCP Adapter

Status: documented-beta until host-specific smoke evidence is recorded.

The generated MCP config exposes only read-only audit artifacts through `agentic_deep_audit.mcp_readonly_server`.

Default host discovery checks known Codex, Claude Code, Cursor, Continue, Goose, Zed, Windsurf, Antigravity and VS Code MCP config locations. If no host config is found or a configured host cannot be safely read, the export writes `MCP_DEFERRED.md` and does not generate `mcp/.mcp.json`.

The generated server is valid only when:

- the host collision check finds no generated-name collision;
- the config contains exactly the generated `agentic_deep_audit` server;
- command, args and env match the read-only server invocation;
- every generated tool and resource is marked `read_only`;
- no target MCP config is imported into a host config.

Target repository MCP files are audit evidence only. They must not be copied into host MCP configuration.
