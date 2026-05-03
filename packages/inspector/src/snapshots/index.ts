/**
 * Snapshot creation for MCP runtime inspection.
 *
 * Placeholder implementation — full implementation will use the MCP SDK.
 */

import type { McpRuntimeSnapshot } from '@mcp-label/core';
import { createHash } from 'node:crypto';

function hashData(data: unknown): string {
  return createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

/**
 * Create a placeholder snapshot. Full implementation pending MCP SDK integration.
 */
export function createSnapshot(serverName: string): McpRuntimeSnapshot {
  return {
    schemaVersion: '0.1',
    generatedAt: new Date().toISOString(),
    server: serverName,
    tools: [],
    resources: [],
    prompts: [],
    capabilities: {},
    hashes: {
      toolsHash: hashData([]),
      resourcesHash: hashData([]),
      promptsHash: hashData([]),
    },
  };
}

