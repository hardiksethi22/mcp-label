# Architecture

`mcp-label` is organized as a pnpm workspace monorepo.

## Package Map

```
mcp-label/
  packages/
    core/          → Types, schemas, analysis, scoring, policy, exporters
    cli/           → Command-line interface
    rules/         → Rule packs (base, OWASP, enterprise)
    inspector/     → Runtime inspection (opt-in, future)
    github-action/ → CI integration (future)
    web/           → Web label viewer (future)
    vscode-extension/ → VS Code integration (future)
  schemas/         → JSON Schema definitions
  examples/        → Example configs and policies
  docs/            → Documentation
```

## Data Flow

```
MCP Config File
     ↓
  parseConfigFile()     — Parse and validate JSON
     ↓
  analyzeServer()       — Static rule engine (permissions + install risks)
     ↓
  computeScore()        — Score each server (0-100)
  scoreToGrade()        — Map to A/B/C/D/F
  computeRisk()         — Map to low/medium/high/critical
     ↓
  evaluatePolicy()      — Optional policy-as-code checks
     ↓
  scan()                — High-level API producing McpLabelReport
     ↓
  exportTerminal()      — Terminal output
  exportMarkdown()      — Markdown report
  exportSvg()           — SVG card
  exportJson()          — JSON report
```

## Key Design Decisions

1. **Static by default**: Default scanning never executes configured commands.
2. **No secrets in output**: Only env variable names are reported, never values.
3. **Heuristic transparency**: Every finding includes evidence, confidence, and explanation.
4. **Modular analysis**: Each permission domain (filesystem, GitHub, Docker, etc.) has its own analyzer.
5. **Extensible schemas**: Versioned schemas allow forward-compatible evolution.

## Package Dependencies

```
@mcp-label/cli → @mcp-label/core
@mcp-label/rules → @mcp-label/core
@mcp-label/inspector → @mcp-label/core
@mcp-label/github-action → @mcp-label/core
```

The `core` package has no dependency on other workspace packages.

