# Runtime Inspection

Runtime inspection is **opt-in** and **never used during default scans**.

## Overview

The `mcp-label inspect` command connects to a running MCP server to enumerate:

- Tools (names, descriptions, input schemas)
- Resources
- Prompts
- Server capabilities

## Warning

**Inspection may start the MCP server.** Only inspect servers you trust and are willing to execute.

## Usage

```bash
mcp-label inspect --config ./mcp.json --server github --output github.snapshot.json
```

## Snapshots

Inspection produces a snapshot file that can be diffed:

```bash
mcp-label diff old.snapshot.json new.snapshot.json
```

This detects:
- New or removed tools
- Changed tool descriptions (possible rug-pull)
- Changed input schemas
- New permissions or capabilities

## Current Status

The inspector package is scaffolded but not yet fully implemented. Full implementation will use the MCP TypeScript SDK for server communication.

