# MCP Label

[![npm version](https://img.shields.io/npm/v/@mcp-label/cli.svg)](https://www.npmjs.com/package/@mcp-label/cli)
[![npm version](https://img.shields.io/npm/v/@mcp-label/core.svg?label=core)](https://www.npmjs.com/package/@mcp-label/core)
[![npm version](https://img.shields.io/npm/v/@mcp-label/rules.svg?label=rules)](https://www.npmjs.com/package/@mcp-label/rules)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A privacy, safety, and permissions label for Model Context Protocol servers.

`mcp-label` helps developers understand what an MCP server can **read, write, execute, access, or expose** — before they install it.

Think of it as a **nutrition label for AI tools**.

```txt
MCP Safety Label
Overall grade: B
Overall risk: Medium
Servers: 3
Top concerns: secrets.env, repo.write, docker-unpinned
```

> **Disclaimer:** `mcp-label` is a static heuristic analyzer by default. It does not prove that an MCP server is safe or unsafe. It gives developers and teams a readable summary of likely permissions and install risks based on configuration, package metadata, and optional runtime inspection.

---

## Why This Exists

MCP servers connect AI applications to files, repositories, databases, browsers, SaaS tools, cloud accounts, and local systems. That power is useful, but it also makes permissions hard to reason about.

A developer looking at an MCP config may not immediately know:

- Which files a server can access
- Whether it can write or delete data
- Whether it receives API tokens or credentials
- Whether it can execute shell commands
- Whether it controls a browser session
- Whether a Docker image or package is unpinned

`mcp-label` gives that information a readable, shareable shape.

---

## Quick Start

### Install

```bash
# Install globally
npm install -g @mcp-label/cli

# Or use directly with npx (no install needed)
npx @mcp-label/cli scan
```

### Published Packages

| Package | Version | Description |
|---------|---------|-------------|
| [`@mcp-label/cli`](https://www.npmjs.com/package/@mcp-label/cli) | ![npm](https://img.shields.io/npm/v/@mcp-label/cli.svg) | Command-line interface |
| [`@mcp-label/core`](https://www.npmjs.com/package/@mcp-label/core) | ![npm](https://img.shields.io/npm/v/@mcp-label/core.svg) | Core analysis, scoring, exporters |
| [`@mcp-label/rules`](https://www.npmjs.com/package/@mcp-label/rules) | ![npm](https://img.shields.io/npm/v/@mcp-label/rules.svg) | Rule packs (base, OWASP, enterprise) |

### Usage

```bash
npx @mcp-label/cli scan
```

Scan a specific config:

```bash
npx @mcp-label/cli scan --config ./.cursor/mcp.json
```

Write a JSON report:

```bash
npx @mcp-label/cli scan --config ./.cursor/mcp.json --output mcp-label.json
```

Generate a Markdown report:

```bash
npx @mcp-label/cli export --input mcp-label.json --format markdown --output MCP_LABEL.md
```

Generate an SVG label:

```bash
npx @mcp-label/cli export --input mcp-label.json --format svg --output mcp-label.svg
```

Use in CI:

```bash
npx @mcp-label/cli scan --config ./.cursor/mcp.json --fail-on high
```

---

## Example Terminal Output

```txt
MCP Label Report
Config: ./.cursor/mcp.json
Servers: 2
Overall: D / HIGH
Static analysis only: yes

github
  Grade: C
  Risk: HIGH

  Permissions:
    HIGH    secrets.env       Environment variable: GITHUB_PERSONAL_ACCESS_TOKEN
    MEDIUM  repo.read         Detected GitHub MCP server
    HIGH    repo.write        Token may permit write operations

  Install risks:
    MEDIUM  docker-latest     Docker image uses the :latest tag
    HIGH    docker-secret-env Secret passed through Docker env

  Recommendations:
    - Use a fine-grained GitHub token.
    - Prefer read-only token scopes where possible.
    - Pin Docker image tags or digests.

filesystem
  Grade: D
  Risk: HIGH

  Permissions:
    HIGH    filesystem.read   Broad path argument: /Users/me
    HIGH    filesystem.write  Filesystem MCP server may modify files

  Install risks:
    MEDIUM  npx-unpinned      npx package is not pinned to a version

  Recommendations:
    - Restrict filesystem access to the smallest project folder needed.
    - Pin package versions in installation commands.
```

---

## CLI Commands

### `scan`

```bash
mcp-label scan [options]
```

| Option | Description |
|--------|-------------|
| `--config <path>` | Path to MCP config file |
| `--output <path>` | Write JSON report to file |
| `--json` | Print JSON report to stdout |
| `--markdown` | Print Markdown report to stdout |
| `--svg` | Print SVG report to stdout |
| `--no-discover` | Do not auto-discover config files |
| `--fail-on <level>` | Exit non-zero if risk is at or above: low, medium, high, critical |
| `--policy <path>` | Evaluate against a policy file |
| `--strict` | Use stricter inference |

### `export`

```bash
mcp-label export --input mcp-label.json --format markdown --output MCP_LABEL.md
```

Formats: `json`, `markdown`, `svg`, `terminal`

### `policy check`

```bash
mcp-label policy check --config ./.cursor/mcp.json --policy ./mcp-policy.yaml
```

### `harden`

```bash
mcp-label harden --config ./.cursor/mcp.json --server github
```

### `diff`

```bash
mcp-label diff old-label.json new-label.json
```

### `init`

```bash
mcp-label init
```

Creates starter files: `mcp-label.config.json`, `MCP_PERMISSIONS.md`, CI workflow, and example policy.

---

## Permission Ontology

`mcp-label` maps findings to a versioned set of permission IDs:

| Permission | Description |
|------------|-------------|
| `filesystem.read` | Read files from the filesystem |
| `filesystem.write` | Write or create files |
| `shell.execute` | Execute shell commands |
| `network.fetch` | Make outbound network requests |
| `browser.control` | Control a browser instance |
| `repo.read` | Read repository data |
| `repo.write` | Write to repositories |
| `database.query` | Query a database |
| `database.mutate` | Modify database data |
| `cloud.read` | Read cloud resources |
| `cloud.write` | Modify cloud resources |
| `secrets.env` | Receives secrets via environment |
| `payments.charge` | Initiate financial transactions |
| … | [Full list in docs](docs/permission-ontology.md) |

---

## Scoring

Each server starts at **100 points** and receives deductions based on findings.

| Grade | Score |
|-------|-------|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | Below 40 |

See [docs/scoring.md](docs/scoring.md) for the full deduction table.

---

## Policy-as-Code

```yaml
version: "0.1"
rules:
  - id: no-shell-exec
    description: Block MCP servers that can execute shell commands.
    deny:
      permissions:
        - shell.execute

  - id: docker-must-be-pinned
    description: Docker images must be pinned.
    require:
      install:
        dockerPinned: true
```

```bash
mcp-label policy check --config ./.cursor/mcp.json --policy ./mcp-policy.yaml --fail-on deny
```

---

## GitHub Action

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
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: npx @mcp-label/cli scan --config ./.cursor/mcp.json --fail-on high
```

---

## Project Structure

```
mcp-label/
  packages/
    core/              Types, schemas, analysis, scoring, exporters
    cli/               Command-line interface
    rules/             Rule packs (base, OWASP, enterprise)
    inspector/         Runtime inspection (opt-in)
    github-action/     CI integration
    web/               Web label viewer (future)
    vscode-extension/  VS Code integration (future)
  schemas/             JSON Schema definitions
  examples/            Example configs and policies
  docs/                Documentation
```

---

## Privacy & Security

`mcp-label` is **local-first**.

- ✅ Does not execute MCP servers by default
- ✅ Does not send configs anywhere
- ✅ Does not collect telemetry
- ✅ Does not print secret values
- ✅ Redacts env values — reports only env names

Runtime inspection (`mcp-label inspect`) is opt-in and may start servers. Use only for servers you trust.

---

## Development

```bash
git clone https://github.com/hardiksethi22/mcp-label.git
cd mcp-label
pnpm install
pnpm build
pnpm test
```

Run the CLI locally:

```bash
pnpm --filter @mcp-label/cli dev scan --config examples/risky.mcp.json
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## References

- [MCP Specification](https://modelcontextprotocol.io/specification)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [MCP Registry](https://github.com/modelcontextprotocol/registry)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

---

## License

MIT

