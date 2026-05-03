/**
 * MCP config file parsing and auto-discovery.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { McpConfigFileSchema } from '../schemas/index.js';
import type { McpConfigFile } from '../types.js';

/**
 * Parse an MCP config file from a path.
 * Supports both `mcpServers` (Claude/Cursor) and `servers` (GitHub Copilot/IntelliJ) keys.
 * Throws on invalid JSON or schema mismatch.
 */
export function parseConfigFile(filePath: string): McpConfigFile {
  const raw = readFileSync(filePath, 'utf-8');
  const json = JSON.parse(raw);
  const parsed = McpConfigFileSchema.parse(json);

  // Normalize: if config uses `servers` instead of `mcpServers`, map it
  const mcpServers = parsed.mcpServers ?? parsed.servers ?? {};
  return { ...parsed, mcpServers } as McpConfigFile;
}

/**
 * Redact secret values from an env record.
 * Returns only the env variable names.
 */
export function redactEnvValues(env: Record<string, string> | undefined): string[] {
  if (!env) return [];
  return Object.keys(env);
}

/**
 * Returns a list of well-known MCP config paths for the current platform.
 */
export function getDiscoveryPaths(): string[] {
  const home = homedir();
  const os = platform();
  const paths: string[] = [];

  if (os === 'darwin') {
    paths.push(
      join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      join(home, '.cursor', 'mcp.json'),
      join(process.cwd(), '.cursor', 'mcp.json'),
      join(home, '.config', 'github-copilot', 'intellij', 'mcp.json'),
      join(home, '.config', 'github-copilot', 'vscode', 'mcp.json'),
    );
  } else if (os === 'win32') {
    const appData = process.env.APPDATA || join(home, 'AppData', 'Roaming');
    paths.push(
      join(appData, 'Claude', 'claude_desktop_config.json'),
      join(home, '.cursor', 'mcp.json'),
      join(process.cwd(), '.cursor', 'mcp.json'),
      join(home, '.config', 'github-copilot', 'intellij', 'mcp.json'),
      join(home, '.config', 'github-copilot', 'vscode', 'mcp.json'),
    );
  } else {
    // Linux / other
    paths.push(
      join(home, '.config', 'Claude', 'claude_desktop_config.json'),
      join(home, '.cursor', 'mcp.json'),
      join(process.cwd(), '.cursor', 'mcp.json'),
      join(home, '.config', 'github-copilot', 'intellij', 'mcp.json'),
      join(home, '.config', 'github-copilot', 'vscode', 'mcp.json'),
    );
  }

  return paths;
}

/**
 * Discover MCP config files from well-known locations.
 * Returns only paths that exist and parse successfully.
 */
export function discoverConfigFiles(): { path: string; config: McpConfigFile }[] {
  const results: { path: string; config: McpConfigFile }[] = [];

  for (const configPath of getDiscoveryPaths()) {
    if (!existsSync(configPath)) continue;
    try {
      const config = parseConfigFile(configPath);
      results.push({ path: configPath, config });
    } catch {
      // Skip files that don't parse — don't fail discovery
    }
  }

  return results;
}

/**
 * Merge multiple MCP configs into one.
 * Later configs override earlier ones for the same server name.
 */
export function mergeConfigs(configs: McpConfigFile[]): McpConfigFile {
  const merged: McpConfigFile = { mcpServers: {} };
  for (const config of configs) {
    Object.assign(merged.mcpServers, config.mcpServers);
  }
  return merged;
}

