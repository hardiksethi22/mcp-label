/**
 * Base rule definitions for mcp-label.
 */

import type { PermissionId, FindingLevel } from '@mcp-label/core';

export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  category: 'permission' | 'install-risk' | 'supply-chain';
  permission?: PermissionId;
  defaultLevel: FindingLevel;
  recommendation: string;
}

export const baseRules: RuleDefinition[] = [
  {
    id: 'secrets-env',
    name: 'Secret Environment Variable',
    description: 'The server receives a secret or credential through its environment.',
    category: 'permission',
    permission: 'secrets.env',
    defaultLevel: 'high',
    recommendation: 'Use the least-privileged credential possible and rotate it if exposed.',
  },
  {
    id: 'filesystem-read',
    name: 'Filesystem Read Access',
    description: 'The server can read files from the local filesystem.',
    category: 'permission',
    permission: 'filesystem.read',
    defaultLevel: 'medium',
    recommendation: 'Restrict filesystem access to the smallest project folder needed.',
  },
  {
    id: 'filesystem-write',
    name: 'Filesystem Write Access',
    description: 'The server may modify or create files on the local filesystem.',
    category: 'permission',
    permission: 'filesystem.write',
    defaultLevel: 'high',
    recommendation: 'Use read-only mode if available, or restrict to a project folder.',
  },
  {
    id: 'shell-execute',
    name: 'Shell Execution',
    description: 'The server can execute shell commands.',
    category: 'permission',
    permission: 'shell.execute',
    defaultLevel: 'critical',
    recommendation: 'Avoid shell commands in MCP server configurations where possible.',
  },
  {
    id: 'repo-read',
    name: 'Repository Read',
    description: 'The server can read repository data.',
    category: 'permission',
    permission: 'repo.read',
    defaultLevel: 'medium',
    recommendation: 'Scope access to specific repositories.',
  },
  {
    id: 'repo-write',
    name: 'Repository Write',
    description: 'The server may write to repositories.',
    category: 'permission',
    permission: 'repo.write',
    defaultLevel: 'high',
    recommendation: 'Use a fine-grained token with read-only scopes unless write is required.',
  },
  {
    id: 'browser-control',
    name: 'Browser Control',
    description: 'The server can control a browser instance.',
    category: 'permission',
    permission: 'browser.control',
    defaultLevel: 'high',
    recommendation: 'Use an isolated browser profile and avoid sensitive sessions.',
  },
  {
    id: 'database-query',
    name: 'Database Query',
    description: 'The server can query a database.',
    category: 'permission',
    permission: 'database.query',
    defaultLevel: 'medium',
    recommendation: 'Use read-only database credentials where possible.',
  },
  {
    id: 'database-mutate',
    name: 'Database Mutation',
    description: 'The server may modify database data.',
    category: 'permission',
    permission: 'database.mutate',
    defaultLevel: 'high',
    recommendation: 'Use read-only database credentials and restrict DML permissions.',
  },
  {
    id: 'docker-latest',
    name: 'Unpinned Docker Image',
    description: 'Docker image uses the :latest tag, which can change over time.',
    category: 'install-risk',
    defaultLevel: 'medium',
    recommendation: 'Pin Docker images to explicit versions or immutable digests.',
  },
  {
    id: 'npx-unpinned',
    name: 'Unpinned npx Package',
    description: 'npx package is not pinned to a specific version.',
    category: 'install-risk',
    defaultLevel: 'medium',
    recommendation: 'Pin package versions in installation commands.',
  },
  {
    id: 'docker-privileged',
    name: 'Privileged Docker Container',
    description: 'Docker container runs in privileged mode with full host access.',
    category: 'install-risk',
    defaultLevel: 'critical',
    recommendation: 'Remove --privileged and use specific capabilities instead.',
  },
  {
    id: 'curl-pipe-shell',
    name: 'Curl Pipe Shell',
    description: 'A remote script is piped directly into a shell for execution.',
    category: 'supply-chain',
    defaultLevel: 'critical',
    recommendation: 'Download scripts first, inspect them, then execute.',
  },
];

