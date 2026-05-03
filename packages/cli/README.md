# @mcp-label/cli

Command-line interface for [mcp-label](https://github.com/hardiksethi22/mcp-label) — a privacy, safety, and permissions label for MCP servers.

## Install

```bash
npm install -g @mcp-label/cli
```

Or use directly with npx:

```bash
npx @mcp-label/cli scan
```

## Commands

### `scan` — Scan MCP server configurations

```bash
# Auto-discover configs (Claude, Cursor, GitHub Copilot)
mcp-label scan

# Scan a specific config file
mcp-label scan --config ./mcp.json

# Output JSON report
mcp-label scan --config ./mcp.json --json

# Output Markdown
mcp-label scan --config ./mcp.json --markdown

# Write JSON report to file
mcp-label scan --config ./mcp.json --output report.json

# Fail CI if risk is high or above
mcp-label scan --config ./mcp.json --fail-on high

# Show scoring rationale
mcp-label scan --config ./mcp.json --explain
```

### `export` — Export a report to another format

```bash
mcp-label export --input report.json --format markdown --output LABEL.md
mcp-label export --input report.json --format svg --output label.svg
```

### `policy` — Evaluate against policy rules

```bash
mcp-label policy check --config ./mcp.json --policy ./policy.yaml
```

### `harden` — Generate safer config suggestions

```bash
mcp-label harden --config ./mcp.json --server github
```

### `diff` — Compare two reports or snapshots

```bash
mcp-label diff old-report.json new-report.json
```

### `init` — Create starter files for maintainers

```bash
mcp-label init
```

## Supported config locations

Auto-discovery checks these paths:

| Platform | Paths |
|----------|-------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json`, `~/.cursor/mcp.json`, `~/.config/github-copilot/intellij/mcp.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json`, `~/.cursor/mcp.json`, `~/.config/github-copilot/intellij/mcp.json` |
| Windows | `%APPDATA%/Claude/claude_desktop_config.json`, `%USERPROFILE%/.cursor/mcp.json` |

## Example output

```
Config: ./.cursor/mcp.json
Servers: 2
Overall: C / HIGH

github (known.github-mcp)
  Capability: High  Risk: High  Hardening: C  Trust: High

  Expected capabilities:
    HIGH    secrets.env       (expected) Environment variable detected: GITHUB_PERSONAL_ACCESS_TOKEN
    MEDIUM  repo.read         (expected) GitHub MCP server inferred
    HIGH    repo.write        (expected) Possible write access inferred

  Recommendations:
    - Use a fine-grained GitHub token.
    - Prefer read-only scopes where possible.
```

## Safety

- Default scan is **static only** — no MCP servers are started or contacted
- Secret values are **never printed** — only variable names are shown
- No telemetry, no cloud calls

## Docs

- [Publishing to npm](../../docs/publishing.md) — Full publish workflow and CI/CD setup

## License

MIT

