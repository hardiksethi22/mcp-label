/**
 * SVG exporter for mcp-label reports.
 *
 * Generates a standalone SVG card with no external fonts or remote assets.
 */

import type { McpLabelReport } from '../types.js';
import { summarizeConcerns } from '../utils/index.js';

function riskColor(risk: string): string {
  switch (risk) {
    case 'critical':
      return '#dc2626';
    case 'high':
      return '#ea580c';
    case 'medium':
      return '#ca8a04';
    case 'low':
      return '#16a34a';
    default:
      return '#6b7280';
  }
}

function gradeColor(grade: string): string {
  switch (grade) {
    case 'A':
      return '#16a34a';
    case 'B':
      return '#65a30d';
    case 'C':
      return '#ca8a04';
    case 'D':
      return '#ea580c';
    case 'F':
      return '#dc2626';
    default:
      return '#6b7280';
  }
}

function trustColor(trust: string): string {
  switch (trust) {
    case 'high':
      return '#16a34a';
    case 'medium':
      return '#ca8a04';
    case 'low':
      return '#ea580c';
    case 'unknown':
    default:
      return '#6b7280';
  }
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function exportSvg(report: McpLabelReport): string {
  const width = 420;
  // Use pre-computed topConcerns from report, or compute from all servers
  let topConcerns = report.summary.topConcerns.slice(0, 3);
  if (topConcerns.length === 0 && report.servers.length > 0) {
    const allPerms = report.servers.flatMap((s) => s.permissions);
    const allRisks = report.servers.flatMap((s) => s.installRisks);
    topConcerns = summarizeConcerns(allPerms, allRisks, 3);
  }

  const impact = report.summary.capabilityImpact || report.summary.overallRisk;
  const risk = report.summary.effectiveRisk || report.summary.overallRisk;
  const hardening = report.summary.hardeningGrade || report.summary.overallGrade;
  const trust = report.summary.publisherTrust || 'unknown';
  const hygiene = report.summary.installHygiene || report.summary.overallGrade;
  const date = new Date(report.generatedAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });

  // Calculate height based on content
  const baseHeight = 220;
  const concernHeight = topConcerns.length * 22;
  const height = baseHeight + concernHeight;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <defs>
    <style>
      .title { font: bold 16px system-ui, -apple-system, sans-serif; fill: #1f2937; }
      .label { font: 12px system-ui, -apple-system, sans-serif; fill: #6b7280; }
      .value { font: bold 13px system-ui, -apple-system, sans-serif; }
      .grade { font: bold 28px system-ui, -apple-system, sans-serif; }
      .concern { font: 12px monospace; fill: #374151; }
      .footer { font: 10px system-ui, -apple-system, sans-serif; fill: #9ca3af; }
    </style>
  </defs>
  <rect width="${width}" height="${height}" rx="8" fill="#ffffff" stroke="#e5e7eb" stroke-width="1"/>
  
  <!-- Header -->
  <text x="20" y="30" class="title">MCP Safety Label</text>
  
  <!-- Hardening grade circle -->
  <circle cx="48" cy="72" r="26" fill="${gradeColor(hardening)}" opacity="0.1"/>
  <text x="48" y="82" class="grade" fill="${gradeColor(hardening)}" text-anchor="middle">${escapeXml(hardening)}</text>
  
  <!-- Dimensions -->
  <text x="90" y="56" class="label">Capability</text>
  <text x="90" y="72" class="value" fill="${riskColor(impact)}">${escapeXml(capitalize(impact))}</text>
  
  <text x="170" y="56" class="label">Risk</text>
  <text x="170" y="72" class="value" fill="${riskColor(risk)}">${escapeXml(capitalize(risk))}</text>
  
  <text x="240" y="56" class="label">Trust</text>
  <text x="240" y="72" class="value" fill="${trustColor(trust)}">${escapeXml(capitalize(trust))}</text>
  
  <text x="320" y="56" class="label">Hygiene</text>
  <text x="320" y="72" class="value" fill="${gradeColor(hygiene)}">${escapeXml(hygiene)}</text>

  <!-- Stats row -->
  <text x="90" y="98" class="label">Servers: ${report.summary.serverCount}</text>
  <text x="170" y="98" class="label">Findings: ${report.summary.totalFindings}</text>
  
  <!-- Divider -->
  <line x1="20" y1="115" x2="${width - 20}" y2="115" stroke="#e5e7eb" stroke-width="1"/>
  
  <!-- Top concerns -->
  <text x="20" y="135" class="label">Top Concerns</text>
  ${topConcerns
    .map(
      (c, i) =>
        `<text x="20" y="${155 + i * 22}" class="concern">${escapeXml(c)}</text>`,
    )
    .join('\n  ')}
  
  <!-- Mitigations -->
  ${(report.summary.topMitigations?.length ?? 0) > 0 ? `
  <line x1="20" y1="${155 + topConcerns.length * 22 + 5}" x2="${width - 20}" y2="${155 + topConcerns.length * 22 + 5}" stroke="#e5e7eb" stroke-width="1"/>
  <text x="20" y="${155 + topConcerns.length * 22 + 22}" class="label">Top Mitigations</text>
  ${report.summary.topMitigations?.slice(0, 2).map((m, i) => `<text x="20" y="${155 + topConcerns.length * 22 + 40 + i * 18}" class="concern">${escapeXml(m)}</text>`).join('\n  ')}` : ''}
  
  <!-- Footer -->
  <text x="20" y="${height - 10}" class="footer">Generated ${escapeXml(date)} · mcp-label · static analysis only</text>
</svg>`;

  return svg;
}

