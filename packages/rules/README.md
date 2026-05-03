# @mcp-label/rules

Rule packs for [mcp-label](https://github.com/hardiksethi22/mcp-label) — a privacy, safety, and permissions label for MCP servers.

## What's inside

Versioned, composable rule packs for MCP server configuration analysis:

- **Base rules** — Core permission and install risk detection rules
- **OWASP rules** — Rules inspired by the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- **Enterprise rules** — Stricter rules for organizational use (pinning requirements, secret handling, network restrictions)

## Install

```bash
npm install @mcp-label/rules
```

## Usage

```typescript
import { baseRules, owaspRules, enterpriseRules } from '@mcp-label/rules';

// Each rule pack exports an array of rule definitions
console.log(baseRules.length);       // number of base rules
console.log(owaspRules.length);      // number of OWASP rules
console.log(enterpriseRules.length); // number of enterprise rules
```

## Rule structure

Each rule includes:

- `id` — Unique identifier
- `name` — Human-readable name
- `description` — What the rule checks
- `severity` — `info` | `low` | `medium` | `high` | `critical`
- `category` — Permission category it applies to
- `version` — Rule version for tracking changes

## License

MIT

