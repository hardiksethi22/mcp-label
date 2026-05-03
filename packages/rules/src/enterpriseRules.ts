/**
 * Enterprise-oriented rules for MCP servers.
 */

import type { RuleDefinition } from './baseRules.js';

export const enterpriseRules: RuleDefinition[] = [
  {
    id: 'enterprise-approved-servers',
    name: 'Approved Server List',
    description:
      'Enterprise environments should maintain an approved list of MCP servers.',
    category: 'supply-chain',
    defaultLevel: 'medium',
    recommendation:
      'Maintain an allowlist of approved MCP server packages and images.',
  },
  {
    id: 'enterprise-audit-trail',
    name: 'Audit Trail',
    description:
      'MCP server tool invocations should be logged for compliance.',
    category: 'permission',
    defaultLevel: 'medium',
    recommendation:
      'Enable MCP client audit logging and retain logs per retention policy.',
  },
  {
    id: 'enterprise-network-egress',
    name: 'Network Egress Control',
    description:
      'MCP servers with network access should be restricted to approved domains.',
    category: 'permission',
    permission: 'network.fetch',
    defaultLevel: 'high',
    recommendation:
      'Use network policies or proxy servers to restrict outbound connections.',
  },
];

