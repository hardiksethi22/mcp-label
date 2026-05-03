/**
 * Terminal exporter for mcp-label reports.
 */

import type { McpLabelReport } from '../types.js';

const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

function levelColor(level: string): string {
  switch (level) {
    case 'critical': return RED;
    case 'high': return RED;
    case 'medium': return YELLOW;
    case 'low': return GREEN;
    default: return DIM;
  }
}

function trustColor(trust: string): string {
  switch (trust) {
    case 'high': return GREEN;
    case 'medium': return YELLOW;
    case 'low': return RED;
    case 'unknown': return DIM;
    default: return DIM;
  }
}

function padRight(str: string, len: number): string {
  return str.padEnd(len);
}

function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

export function exportTerminal(report: McpLabelReport, options?: { explain?: boolean }): string {
  const lines: string[] = [];

  lines.push(`${BOLD}MCP Safety Label${RESET}`);
  lines.push(
    `Config: ${report.source.configPaths.join(', ') || 'auto-discovered'}`,
  );
  lines.push(`Servers: ${report.summary.serverCount}`);
  lines.push('');

  // Multi-dimensional summary
  const s = report.summary;
  if (s.capabilityImpact) {
    lines.push(`  Capability impact:  ${levelColor(s.capabilityImpact)}${capitalize(s.capabilityImpact)}${RESET}`);
    lines.push(`  Effective risk:     ${levelColor(s.effectiveRisk!)}${capitalize(s.effectiveRisk!)}${RESET}`);
    lines.push(`  Hardening grade:    ${BOLD}${s.hardeningGrade}${RESET}`);
    lines.push(`  Publisher trust:    ${trustColor(s.publisherTrust!)}${capitalize(s.publisherTrust!)}${RESET}`);
    lines.push(`  Install hygiene:    ${BOLD}${s.installHygiene}${RESET}`);
    lines.push(`  Config hardening:   ${BOLD}${s.configHardening}${RESET}`);
    lines.push(`  Static confidence:  ${capitalize(s.analysisConfidence!)}`);
  } else {
    lines.push(`  Overall: ${BOLD}${s.overallGrade}${RESET} / ${levelColor(s.overallRisk)}${s.overallRisk.toUpperCase()}${RESET}`);
  }
  lines.push(`  Static analysis only: ${report.source.staticOnly ? 'yes' : 'no'}`);
  lines.push('');

  for (const server of report.servers) {
    lines.push(`${BOLD}${CYAN}${server.name}${RESET}${server.knownServerProfile ? ` ${DIM}(${server.knownServerProfile})${RESET}` : ''}`);
    if (server.capabilityImpact) {
      lines.push(`  Capability: ${levelColor(server.capabilityImpact)}${capitalize(server.capabilityImpact)}${RESET}  Risk: ${levelColor(server.effectiveRisk!)}${capitalize(server.effectiveRisk!)}${RESET}  Hardening: ${BOLD}${server.hardeningGrade}${RESET}  Trust: ${trustColor(server.publisherTrust!)}${capitalize(server.publisherTrust!)}${RESET}`);
    } else {
      lines.push(`  Grade: ${BOLD}${server.grade}${RESET}  Risk: ${levelColor(server.risk)}${server.risk.toUpperCase()}${RESET}`);
    }
    lines.push('');

    if (server.permissions.length > 0) {
      // Split into expected and unexpected
      const expected = server.permissions.filter((p) => p.expectation === 'expected');
      const other = server.permissions.filter((p) => p.expectation !== 'expected');

      if (expected.length > 0) {
        lines.push(`  ${BOLD}Expected capabilities:${RESET}`);
        for (const perm of expected) {
          const lvl = padRight(perm.level.toUpperCase(), 10);
          const id = padRight(perm.permission, 28);
          lines.push(
            `    ${levelColor(perm.level)}${lvl}${RESET}${id}${DIM}(expected)${RESET} ${perm.evidence}`,
          );
        }
        lines.push('');
      }

      if (other.length > 0) {
        lines.push(`  ${BOLD}Permissions:${RESET}`);
        for (const perm of other) {
          const lvl = padRight(perm.level.toUpperCase(), 10);
          const id = padRight(perm.permission, 28);
          lines.push(
            `    ${levelColor(perm.level)}${lvl}${RESET}${id}${perm.evidence}`,
          );
        }
        lines.push('');
      }
    }

    if (server.installRisks.length > 0) {
      lines.push(`  ${BOLD}Install risks:${RESET}`);
      for (const risk of server.installRisks) {
        const lvl = padRight(risk.level.toUpperCase(), 10);
        const id = padRight(risk.id, 26);
        lines.push(
          `    ${levelColor(risk.level)}${lvl}${RESET}${id}${risk.explanation}`,
        );
      }
      lines.push('');
    }

    if (server.recommendations.length > 0) {
      lines.push(`  ${BOLD}Recommendations:${RESET}`);
      for (const rec of server.recommendations) {
        lines.push(`    - ${rec}`);
      }
      lines.push('');
    }

    // Scoring explanation (shown with --explain or always in compact form)
    if (options?.explain && server.scoringTrace) {
      lines.push(`  ${BOLD}Why this result?${RESET}`);
      lines.push(`    ${server.scoringTrace.explanation.replace(/\*\*/g, '')}`);
      lines.push('');
    }
  }

  lines.push(
    `${DIM}mcp-label is a heuristic analyzer. It does not prove safety. High impact ≠ malicious. Use it as a review aid.${RESET}`,
  );

  return lines.join('\n');
}


