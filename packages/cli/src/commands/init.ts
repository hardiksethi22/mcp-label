/**
 * `mcp-label init` command.
 *
 * Creates starter files for maintainers.
 */

import { Command } from 'commander';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const initCommand = new Command('init')
  .description('Create starter mcp-label files for maintainers.')
  .action(() => {
    const files: { path: string; content: string }[] = [
      {
        path: 'mcp-label.config.json',
        content: JSON.stringify(
          {
            $schema: 'https://mcp-label.dev/schemas/mcp-label-config.schema.json',
            scan: {
              configs: ['./.cursor/mcp.json'],
              strict: false,
            },
            policy: 'examples/mcp-policy.yaml',
            output: {
              json: 'mcp-label.json',
              markdown: 'MCP_LABEL.md',
            },
          },
          null,
          2,
        ),
      },
      {
        path: 'MCP_PERMISSIONS.md',
        content: `# MCP Permissions

This project uses MCP servers. Below is a summary of their permissions.

> Run \`npx mcp-label scan\` to regenerate this file.

<!-- mcp-label report will be placed here -->
`,
      },
      {
        path: join('.github', 'workflows', 'mcp-label.yml'),
        content: `name: MCP Label

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
      - run: npx mcp-label scan --config ./.cursor/mcp.json --fail-on high
`,
      },
      {
        path: join('examples', 'mcp-policy.yaml'),
        content: `version: "0.1"
rules:
  - id: no-shell-exec
    description: Block MCP servers that can execute shell commands.
    deny:
      permissions:
        - shell.execute

  - id: no-broad-filesystem
    description: Block broad filesystem access.
    deny:
      permissions:
        - filesystem.read
      evidenceIncludes:
        - "/"
        - "$HOME"
        - "~"

  - id: docker-must-be-pinned
    description: Docker images must be pinned.
    require:
      install:
        dockerPinned: true
`,
      },
    ];

    for (const file of files) {
      if (existsSync(file.path)) {
        console.log(`Exists, skipping: ${file.path}`);
        continue;
      }

      // Ensure directory exists
      const dir = file.path.includes('/') ? file.path.substring(0, file.path.lastIndexOf('/')) : '';
      if (dir) {
        mkdirSync(dir, { recursive: true });
      }

      writeFileSync(file.path, file.content, 'utf-8');
      console.log(`Created: ${file.path}`);
    }

    console.log('\nDone! Review the generated files and customize for your project.');
  });

