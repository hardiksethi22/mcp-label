/**
 * @mcp-label/inspector
 *
 * Runtime inspection for MCP servers.
 * This package is opt-in and never used during default scans.
 *
 * WARNING: Inspection may start MCP servers.
 *
 * Future implementation will:
 * - Connect to MCP servers using the MCP TypeScript SDK
 * - Enumerate tools, resources, prompts, and capabilities
 * - Create snapshots for diffing and drift detection
 */

export { createSnapshot } from './snapshots/index.js';

