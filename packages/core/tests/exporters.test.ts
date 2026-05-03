import { describe, it, expect } from 'vitest';
import { exportMarkdown } from '../src/exporters/markdown.js';
import { exportSvg } from '../src/exporters/svg.js';
import { exportJson } from '../src/exporters/index.js';
import { exportTerminal } from '../src/exporters/terminal.js';
import type { McpLabelReport } from '../src/types.js';

const mockReport: McpLabelReport = {
  schemaVersion: '0.2',
  generatedAt: '2025-01-01T00:00:00.000Z',
  source: {
    configPaths: ['test.mcp.json'],
    discovered: false,
    staticOnly: true,
  },
  summary: {
    serverCount: 1,
    capabilityImpact: 'high',
    effectiveRisk: 'high',
    hardeningGrade: 'C',
    publisherTrust: 'high',
    installHygiene: 'C',
    configHardening: 'C',
    analysisConfidence: 'medium',
    totalFindings: 3,
    topConcerns: ['secrets.env', 'repo.write', 'docker-latest'],
    topMitigations: ['Pin Docker image version'],
    overallGrade: 'C',
    overallRisk: 'high',
    highestRisk: 'high',
  },
  servers: [
    {
      name: 'github',
      command: 'docker',
      args: ['run', 'ghcr.io/github/github-mcp-server:latest'],
      envVars: ['GITHUB_PERSONAL_ACCESS_TOKEN'],
      capabilityImpact: 'high',
      effectiveRisk: 'high',
      hardeningGrade: 'C',
      publisherTrust: 'high',
      installHygiene: 'C',
      configHardening: 'C',
      analysisConfidence: 'medium',
      knownServerProfile: 'known.github-mcp',
      permissions: [
        {
          id: 'secrets-env-github',
          permission: 'secrets.env',
          level: 'high',
          confidence: 'high',
          evidence: 'Environment variable: GITHUB_PERSONAL_ACCESS_TOKEN',
          explanation: 'The server receives a secret through its environment.',
          expectation: 'expected',
        },
        {
          id: 'repo-read',
          permission: 'repo.read',
          level: 'medium',
          confidence: 'medium',
          evidence: 'Detected GitHub MCP server',
          explanation: 'The server can read repository data.',
          expectation: 'expected',
        },
      ],
      installRisks: [
        {
          id: 'docker-latest',
          level: 'medium',
          confidence: 'high',
          evidence: 'ghcr.io/github/github-mcp-server:latest',
          explanation: 'Docker image uses :latest tag.',
          recommendation: 'Pin Docker images.',
        },
      ],
      recommendations: ['Use a fine-grained GitHub token.', 'Pin Docker images.'],
      saferConfigSuggestions: [],
      scoringTrace: {
        adjustments: [],
        explanation: 'Capability impact is **high**. Publisher trust is **high**.',
      },
      score: 60,
      grade: 'C',
      risk: 'high',
    },
  ],
};

describe('Markdown export', () => {
  it('should produce valid Markdown', () => {
    const md = exportMarkdown(mockReport);
    expect(md).toContain('# MCP Safety Label');
    expect(md).toContain('Capability impact: **High**');
    expect(md).toContain('## github');
    expect(md).toContain('`secrets.env`');
    expect(md).not.toContain('ghp_'); // No secret values
  });
});

describe('SVG export', () => {
  it('should produce valid SVG', () => {
    const svg = exportSvg(mockReport);
    expect(svg).toContain('<svg');
    expect(svg).toContain('MCP Safety Label');
    expect(svg).toContain('</svg>');
  });

  it('should not have external references', () => {
    const svg = exportSvg(mockReport);
    const withoutXmlns = svg.replace('http://www.w3.org/2000/svg', '');
    expect(withoutXmlns).not.toContain('http://');
    expect(withoutXmlns).not.toContain('https://');
    expect(svg).not.toContain('href');
  });
});

describe('JSON export', () => {
  it('should produce valid JSON', () => {
    const json = exportJson(mockReport);
    const parsed = JSON.parse(json);
    expect(parsed.schemaVersion).toBe('0.2');
    expect(parsed.servers.length).toBe(1);
  });
});

describe('Terminal export', () => {
  it('should produce readable output', () => {
    const output = exportTerminal(mockReport);
    expect(output).toContain('MCP Safety Label');
    expect(output).toContain('github');
    expect(output).toContain('secrets.env');
  });
});
