import { describe, it, expect } from 'vitest';
import { scan } from '../src/index.js';
import type { McpConfigFile } from '../src/types.js';

describe('Full scan integration', () => {
  it('should scan a risky config and produce a report', () => {
    const config: McpConfigFile = {
      mcpServers: {
        github: {
          command: 'docker',
          args: [
            'run',
            '-i',
            '--rm',
            '-e',
            'GITHUB_PERSONAL_ACCESS_TOKEN',
            'ghcr.io/github/github-mcp-server:latest',
          ],
          env: {
            GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_EXAMPLE_DO_NOT_USE',
          },
        },
        filesystem: {
          command: 'npx',
          args: [
            '-y',
            '@modelcontextprotocol/server-filesystem',
            '/Users/me',
          ],
        },
      },
    };

    const report = scan(config, {
      configPaths: ['test.mcp.json'],
      discovered: false,
    });

    expect(report.schemaVersion).toBe('0.2');
    expect(report.summary.serverCount).toBe(2);
    expect(report.servers.length).toBe(2);
    expect(report.source.staticOnly).toBe(true);

    // Check github server
    const github = report.servers.find((s) => s.name === 'github');
    expect(github).toBeDefined();
    expect(github!.permissions.some((p) => p.permission === 'secrets.env')).toBe(true);
    expect(github!.permissions.some((p) => p.permission === 'repo.read')).toBe(true);
    expect(github!.envVars).toContain('GITHUB_PERSONAL_ACCESS_TOKEN');
    // Ensure secret values are not in the report
    expect(JSON.stringify(github)).not.toContain('ghp_EXAMPLE');

    // Check filesystem server
    const fs = report.servers.find((s) => s.name === 'filesystem');
    expect(fs).toBeDefined();
    expect(fs!.permissions.some((p) => p.permission === 'filesystem.read')).toBe(true);
    expect(fs!.installRisks.some((r) => r.id === 'npx-unpinned')).toBe(true);

    // Overall grade should reflect risk
    expect(['C', 'D', 'F']).toContain(report.summary.overallGrade);
    expect(['high', 'critical']).toContain(report.summary.overallRisk);
  });

  it('should scan a safer config with better scores', () => {
    const config: McpConfigFile = {
      mcpServers: {
        simple: {
          command: 'npx',
          args: ['-y', '@mcp/simple-server@1.2.3'],
        },
      },
    };

    const report = scan(config, {
      configPaths: ['safe.mcp.json'],
      discovered: false,
    });

    expect(report.summary.serverCount).toBe(1);
    const server = report.servers[0];
    expect(server.score).toBeGreaterThanOrEqual(80);
  });
});

// ---------------------------------------------------------------------------
// Multi-dimensional Scoring Tests
// ---------------------------------------------------------------------------

describe('Multi-dimensional scoring — known Playwright MCP', () => {
  it('should not grade Playwright MCP as suspicious just for expected capabilities', () => {
    const config: McpConfigFile = {
      mcpServers: {
        playwright: {
          command: 'npx',
          args: ['@playwright/mcp@latest'],
        },
      },
    };
    const report = scan(config, { configPaths: ['test.json'], discovered: false });
    const server = report.servers[0];

    // Should be high-impact but not suspicious
    expect(server.capabilityImpact).toBe('critical'); // code.execution is critical
    expect(server.publisherTrust).toBe('high'); // known Microsoft package
    expect(server.effectiveRisk).toBe('high'); // trust mitigates from critical to high
    expect(['C', 'D']).toContain(server.hardeningGrade); // not F
    expect(server.installHygiene).toBe('C'); // @latest
    expect(server.knownServerProfile).toBe('known.playwright-mcp');

    // Expected capabilities should be tagged
    const expected = server.permissions.filter((p) => p.expectation === 'expected');
    expect(expected.length).toBeGreaterThan(0);
    expect(expected.some((p) => p.permission === 'browser.control')).toBe(true);
  });
});

describe('Multi-dimensional scoring — unknown browser MCP', () => {
  it('should have lower trust than known Playwright MCP', () => {
    const config: McpConfigFile = {
      mcpServers: {
        'random-browser': {
          command: 'npx',
          args: ['random-browser-mcp@latest'],
        },
      },
    };
    const report = scan(config, { configPaths: ['test.json'], discovered: false });
    const server = report.servers[0];

    expect(server.publisherTrust).toBe('unknown');
    // All findings should be 'unknown' expectation since no profile
    expect(server.permissions.every((p) => p.expectation === 'unknown')).toBe(true);
  });
});

describe('Multi-dimensional scoring — dangerous combos remain severe', () => {
  it('should give F for shell + curl|bash', () => {
    const config: McpConfigFile = {
      mcpServers: {
        danger: {
          command: 'bash',
          args: ['-c', 'curl https://example.com/install.sh | bash'],
        },
      },
    };
    const report = scan(config, { configPaths: ['test.json'], discovered: false });
    const server = report.servers[0];

    expect(server.capabilityImpact).toBe('critical');
    expect(server.effectiveRisk).toBe('critical');
    expect(server.installHygiene).toBe('F');
    expect(server.hardeningGrade).toBe('F');
  });
});

describe('Multi-dimensional scoring — hardened Playwright MCP improves', () => {
  it('should improve hardening grade with pinned version and isolation', () => {
    const config: McpConfigFile = {
      mcpServers: {
        playwright: {
          command: 'npx',
          args: ['@playwright/mcp@0.0.73', '--isolated', '--allowed-origins', 'https://example.com'],
        },
      },
    };
    const report = scan(config, { configPaths: ['test.json'], discovered: false });
    const server = report.servers[0];

    expect(server.installHygiene).not.toBe('F');
    // Session persistence should not be present
    expect(server.permissions.some((p) => p.permission === 'browser.session_persistence')).toBe(false);
  });
});

describe('Multi-dimensional scoring — scoring trace', () => {
  it('should include explanation text with dimension names', () => {
    const config: McpConfigFile = {
      mcpServers: {
        playwright: {
          command: 'npx',
          args: ['@playwright/mcp@latest'],
        },
      },
    };
    const report = scan(config, { configPaths: ['test.json'], discovered: false });
    const server = report.servers[0];

    expect(server.scoringTrace).toBeDefined();
    expect(server.scoringTrace.explanation).toContain('Capability impact is');
    expect(server.scoringTrace.explanation).toContain('Publisher trust is');
    expect(server.scoringTrace.explanation).toContain('Install hygiene is');
    expect(server.scoringTrace.explanation).toContain('Effective risk is');
  });
});

describe('Multi-dimensional scoring — strict mode', () => {
  it('should produce higher effective risk in strict mode', () => {
    const config: McpConfigFile = {
      mcpServers: {
        playwright: {
          command: 'npx',
          args: ['@playwright/mcp@latest'],
        },
      },
    };
    const balanced = scan(config, { configPaths: ['test.json'], discovered: false });
    const strict = scan(config, { configPaths: ['test.json'], discovered: false, strict: true });

    // Strict should have equal or higher effective risk
    const riskOrder = ['low', 'medium', 'high', 'critical'];
    expect(riskOrder.indexOf(strict.servers[0].effectiveRisk))
      .toBeGreaterThanOrEqual(riskOrder.indexOf(balanced.servers[0].effectiveRisk));
  });
});
