/**
 * Rule packs for mcp-label.
 *
 * Rules provide metadata for findings. The analysis engine in @mcp-label/core
 * performs the actual detection. These packs provide categorized rule definitions
 * and recommendations for reporting and documentation.
 */

export { baseRules, type RuleDefinition } from './baseRules.js';
export { owaspRules } from './owaspRules.js';
export { enterpriseRules } from './enterpriseRules.js';

