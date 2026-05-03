# @mcp-label/inspector

Runtime inspection module for [mcp-label](https://github.com/hardiksethi22/mcp-label) — a privacy, safety, and permissions label for MCP servers.

> ⚠️ **This package is a scaffold.** Runtime inspection is not yet fully implemented. See the [roadmap](https://github.com/hardiksethi22/mcp-label/blob/main/docs/roadmap.md) for details.

## Purpose

Provides optional runtime inspection of MCP servers — connecting to a running server to enumerate its actual tools, resources, prompts, and capabilities.

This is **explicitly opt-in** and requires user confirmation. Default `mcp-label scan` never uses this package.

## Planned features

- Connect to MCP servers via stdio, HTTP, and SSE transports
- Enumerate tools, resources, prompts, and server capabilities
- Create snapshots for diffing and rug-pull detection
- Compare snapshots to detect permission changes over time
- Redact all secrets in snapshots

## Safety

- **Never runs during default scans** — requires explicit `mcp-label inspect` command
- **Warns before connecting** — requires user confirmation unless `--yes` is passed
- **Secrets are redacted** — never saved in snapshots

## License

MIT

