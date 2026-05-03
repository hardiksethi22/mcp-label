# @mcp-label/github-action

GitHub Action for [mcp-label](https://github.com/mcp-label/mcp-label) — a privacy, safety, and permissions label for MCP servers.

> ⚠️ **This package is a scaffold.** The GitHub Action is not yet fully implemented.

## Planned usage

```yaml
name: MCP Label

on:
  pull_request:
  push:
    branches: [main]

jobs:
  mcp-label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mcp-label/action@v1
        with:
          config: ./.cursor/mcp.json
          fail-on: high
          output: mcp-label.json
```

## Planned features

- Run `mcp-label scan` in CI
- Post PR comments with permission summaries
- Fail builds based on policy or risk threshold
- Upload JSON/Markdown/SVG artifacts
- Compare labels between branches (diff)

## License

MIT

