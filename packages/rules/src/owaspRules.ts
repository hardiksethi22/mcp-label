/**
 * OWASP-inspired rules for MCP servers.
 *
 * Based on the OWASP MCP Security Cheat Sheet:
 * https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
 */

import type { RuleDefinition } from './baseRules.js';

export const owaspRules: RuleDefinition[] = [
  {
    id: 'owasp-tool-injection',
    name: 'Tool Injection Risk',
    description:
      'MCP servers can change tool descriptions and schemas after initial approval, potentially enabling tool injection.',
    category: 'supply-chain',
    defaultLevel: 'high',
    recommendation:
      'Regularly inspect server tools and compare snapshots to detect schema drift.',
  },
  {
    id: 'owasp-excessive-permissions',
    name: 'Excessive Permissions',
    description:
      'The MCP server configuration grants more permissions than needed for its stated purpose.',
    category: 'permission',
    defaultLevel: 'high',
    recommendation:
      'Apply the principle of least privilege. Only grant permissions required for the server\'s function.',
  },
  {
    id: 'owasp-secret-exposure',
    name: 'Secret Exposure in Configuration',
    description:
      'Secrets passed to MCP servers may be accessible to the AI model or logged in tool responses.',
    category: 'permission',
    permission: 'secrets.env',
    defaultLevel: 'high',
    recommendation:
      'Use token vaults or secret managers. Never pass secrets that the AI model should not access.',
  },
  {
    id: 'owasp-rug-pull',
    name: 'Rug Pull Risk',
    description:
      'MCP server tools or schemas may change between inspections, altering behavior without notice.',
    category: 'supply-chain',
    defaultLevel: 'medium',
    recommendation:
      'Use mcp-label inspect and diff to detect changes between versions.',
  },
];

