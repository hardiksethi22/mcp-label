# @mcp-label/core

Core analysis engine for [mcp-label](https://github.com/mcp-label/mcp-label) — a privacy, safety, and permissions label for MCP servers.

## What's inside

- **Types & schemas** — Zod-validated types for reports, findings, policies, and configs
- **Config parsing** — Parse MCP configs from Claude, Cursor, GitHub Copilot, and more
- **Static analysis** — Infer permissions and install risks from server configurations
- **Scoring** — Multi-dimensional scoring: capability impact, effective risk, hardening grade, publisher trust, install hygiene, config hardening, and analysis confidence
- **Known server profiles** — Built-in profiles for well-known MCP servers (Playwright, GitHub, filesystem)
- **Policy evaluation** — Evaluate configs against policy-as-code rules
- **Exporters** — JSON, Markdown, SVG, and terminal output formats

## Install

```bash
npm install @mcp-label/core
```

## Usage

```typescript
import { parseConfigFile, scan } from '@mcp-label/core';

// Parse an MCP config file
const config = parseConfigFile('./mcp.json');

// Run a full scan
const report = scan(config, {
  configPaths: ['./mcp.json'],
  discovered: false,
});

console.log(report.summary.overallGrade); // 'A' | 'B' | 'C' | 'D' | 'F'
console.log(report.summary.overallRisk);  // 'low' | 'medium' | 'high' | 'critical'
```

## Supported config formats

- `mcpServers` key (Claude Desktop, Cursor)
- `servers` key (GitHub Copilot, IntelliJ)
- stdio servers (command + args)
- HTTP/SSE servers (url + headers)

## Safety guarantees

- **Never executes** configured MCP server commands
- **Never reads** secret values — only env variable and header names
- **No telemetry** — fully local, no network calls
- **No cloud dependencies** — works offline

## License

MIT

