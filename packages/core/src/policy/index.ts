/**
 * Policy-as-code engine for mcp-label.
 *
 * Evaluates MCP label reports against team-defined policies.
 */

import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import { PolicyFileSchema } from '../schemas/index.js';
import type { PolicyFile, PolicyResult, ServerLabel } from '../types.js';

/**
 * Parse a YAML or JSON policy file.
 */
export function parsePolicyFile(filePath: string): PolicyFile {
  const raw = readFileSync(filePath, 'utf-8');
  let parsed: unknown;

  if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
    parsed = YAML.parse(raw);
  } else {
    parsed = JSON.parse(raw);
  }

  return PolicyFileSchema.parse(parsed);
}

/**
 * Evaluate a single server against a policy.
 */
export function evaluatePolicy(server: ServerLabel, policy: PolicyFile): PolicyResult[] {
  const results: PolicyResult[] = [];

  for (const rule of policy.rules) {
    const result = evaluateRule(server, rule);
    results.push(result);
  }

  return results;
}

function evaluateRule(
  server: ServerLabel,
  rule: PolicyFile['rules'][0],
): PolicyResult {
  // Deny rules: if server has matching permission, fail
  if (rule.deny?.permissions) {
    for (const deniedPerm of rule.deny.permissions) {
      const matchingFindings = server.permissions.filter(
        (f) => f.permission === deniedPerm,
      );

      if (matchingFindings.length > 0) {
        // If evidenceIncludes is also specified, only fail if evidence matches
        if (rule.deny.evidenceIncludes && rule.deny.evidenceIncludes.length > 0) {
          const evidenceMatch = matchingFindings.some((f) =>
            rule.deny!.evidenceIncludes!.some((pattern) =>
              f.evidence.includes(pattern),
            ),
          );
          if (evidenceMatch) {
            return {
              ruleId: rule.id,
              description: rule.description,
              passed: false,
              server: server.name,
              details: `Denied permission ${deniedPerm} with matching evidence found.`,
            };
          }
        } else {
          return {
            ruleId: rule.id,
            description: rule.description,
            passed: false,
            server: server.name,
            details: `Denied permission ${deniedPerm} detected.`,
          };
        }
      }
    }
  }

  // Require rules
  if (rule.require?.install) {
    if (rule.require.install.dockerPinned) {
      const hasUnpinnedDocker = server.installRisks.some(
        (r) =>
          r.id === 'docker-latest' ||
          r.id === 'docker-untagged',
      );
      if (hasUnpinnedDocker) {
        return {
          ruleId: rule.id,
          description: rule.description,
          passed: false,
          server: server.name,
          details: 'Docker image is not pinned to an explicit version or digest.',
        };
      }
    }
    if (rule.require.install.packagePinned) {
      const hasUnpinnedPkg = server.installRisks.some(
        (r) =>
          r.id === 'npx-unpinned' ||
          r.id === 'npx-latest' ||
          r.id === 'uvx-unpinned',
      );
      if (hasUnpinnedPkg) {
        return {
          ruleId: rule.id,
          description: rule.description,
          passed: false,
          server: server.name,
          details: 'Package is not pinned to a specific version.',
        };
      }
    }
  }

  return {
    ruleId: rule.id,
    description: rule.description,
    passed: true,
    server: server.name,
    details: 'Rule passed.',
  };
}

