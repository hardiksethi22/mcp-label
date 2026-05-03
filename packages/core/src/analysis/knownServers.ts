/**
 * Known server profiles for mcp-label.
 *
 * These profiles encode publisher trust, expected capabilities,
 * and recommended hardening controls for well-known MCP servers.
 *
 * Expected capabilities are not treated as suspicious — they are
 * part of the server's intended function.
 */

import type { PermissionId, Confidence } from '../types.js';
import type { McpServerConfig } from '../types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PublisherTrust = 'unknown' | 'low' | 'medium' | 'high';

export interface KnownServerProfile {
  id: string;
  displayName: string;
  match: {
    packageNames?: string[];
    repos?: string[];
    dockerImages?: string[];
    commands?: string[];
  };
  publisher: {
    name: string;
    trust: PublisherTrust;
    evidence: string;
  };
  expectedCapabilities: PermissionId[];
  recommendedControls: string[];
}

// ---------------------------------------------------------------------------
// Profile Registry
// ---------------------------------------------------------------------------

export const KNOWN_SERVER_PROFILES: KnownServerProfile[] = [
  {
    id: 'known.playwright-mcp',
    displayName: 'Microsoft Playwright MCP',
    match: {
      packageNames: ['@playwright/mcp', 'playwright-mcp'],
      repos: ['github.com/microsoft/playwright-mcp', 'microsoft/playwright-mcp'],
    },
    publisher: {
      name: 'Microsoft',
      trust: 'high',
      evidence: 'Official Microsoft Playwright MCP package/repository match.',
    },
    expectedCapabilities: [
      'browser.control',
      'network.fetch',
      'browser.session_persistence',
      'filesystem.read_possible',
      'code.execution',
    ],
    recommendedControls: [
      'Pin @playwright/mcp to a specific version.',
      'Use --isolated unless persistent login state is intentionally needed.',
      'Use --allowed-origins or --blocked-origins to limit browser egress.',
      'Avoid sensitive logged-in browser sessions.',
      'Require explicit approval for browser_run_code_unsafe or disable it via client tool allowlists.',
    ],
  },
  {
    id: 'known.mcp-filesystem',
    displayName: 'MCP Filesystem Server',
    match: {
      packageNames: ['@modelcontextprotocol/server-filesystem'],
    },
    publisher: {
      name: 'Anthropic (Model Context Protocol)',
      trust: 'high',
      evidence: 'Official Model Context Protocol reference server.',
    },
    expectedCapabilities: [
      'filesystem.read',
      'filesystem.write',
    ],
    recommendedControls: [
      'Restrict filesystem access to the smallest project folder needed.',
      'Use read-only mode if available.',
      'Pin the package to a specific version.',
    ],
  },
  {
    id: 'known.github-mcp',
    displayName: 'GitHub MCP Server',
    match: {
      packageNames: ['github-mcp-server', '@github/mcp-server'],
      dockerImages: ['ghcr.io/github/github-mcp-server'],
    },
    publisher: {
      name: 'GitHub',
      trust: 'high',
      evidence: 'Official GitHub MCP server package/image match.',
    },
    expectedCapabilities: [
      'repo.read',
      'repo.write',
      'secrets.env',
      'network.egress',
    ],
    recommendedControls: [
      'Use a fine-grained personal access token with minimal scopes.',
      'Prefer read-only scopes unless write actions are required.',
      'Pin the Docker image or package to a specific version.',
    ],
  },
];

// ---------------------------------------------------------------------------
// Profile Matching
// ---------------------------------------------------------------------------

/**
 * Find a known server profile that matches the given config.
 * Returns null if no known profile matches.
 */
export function findKnownProfile(
  name: string,
  config: McpServerConfig,
): KnownServerProfile | null {
  const args = config.args || [];
  const command = config.command || '';
  const allText = [command, ...args].join(' ').toLowerCase();

  for (const profile of KNOWN_SERVER_PROFILES) {
    // Check package names
    if (profile.match.packageNames) {
      for (const pkg of profile.match.packageNames) {
        if (allText.includes(pkg.toLowerCase())) {
          return profile;
        }
      }
    }

    // Check repos
    if (profile.match.repos) {
      for (const repo of profile.match.repos) {
        if (allText.includes(repo.toLowerCase())) {
          return profile;
        }
      }
    }

    // Check docker images
    if (profile.match.dockerImages) {
      for (const image of profile.match.dockerImages) {
        if (allText.includes(image.toLowerCase())) {
          return profile;
        }
      }
    }
  }

  return null;
}

/**
 * Check if a capability is expected for a known server profile.
 */
export function isExpectedCapability(
  profile: KnownServerProfile | null,
  permission: PermissionId,
): boolean {
  if (!profile) return false;
  return profile.expectedCapabilities.includes(permission);
}

