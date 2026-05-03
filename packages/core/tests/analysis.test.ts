import { describe, it, expect } from 'vitest';
import {
  analyzeSecrets,
  analyzeFilesystem,
  analyzeGitHub,
  analyzeBrowser,
  analyzeDatabase,
  analyzeCloud,
  analyzeShellExecution,
  analyzeDockerRisks,
  analyzeNpxRisks,
  analyzeCurlPipeRisks,
  analyzeServer,
  analyzeX402,
  analyzeNetworkEgress,
  analyzePayments,
  analyzeUvxRisks,
  analyzeUvWithRisks,
  analyzeRemoteGitRisks,
  analyzeLocalScriptRisks,
  analyzePlaywrightMcp,
  isPlaywrightMcp,
} from '../src/analysis/index.js';
import type { McpServerConfig } from '../src/types.js';
import { summarizeConcerns } from '../src/utils/index.js';
import { computeScore, scoreToGrade, computeRisk } from '../src/scoring/index.js';

describe('Secret analysis', () => {
  it('should detect secret env vars', () => {
    const config: McpServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'redacted', API_KEY: 'redacted' },
    };
    const findings = analyzeSecrets('test', config);
    expect(findings.length).toBe(2);
    expect(findings[0].permission).toBe('secrets.env');
    expect(findings[0].level).toBe('high');
    // Ensure no secret values in evidence
    expect(findings[0].evidence).not.toContain('redacted');
  });

  it('should not flag non-secret env vars', () => {
    const config: McpServerConfig = {
      command: 'node',
      env: { NODE_ENV: 'production', PORT: '3000' },
    };
    const findings = analyzeSecrets('test', config);
    expect(findings.length).toBe(0);
  });
});

describe('Filesystem analysis', () => {
  it('should detect filesystem server', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', '/Users/me'],
    };
    const findings = analyzeFilesystem('filesystem', config);
    expect(findings.some((f) => f.permission === 'filesystem.read')).toBe(true);
    expect(findings.some((f) => f.permission === 'filesystem.write')).toBe(true);
  });

  it('should flag broad paths as high', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', '/Users/me'],
    };
    const findings = analyzeFilesystem('filesystem', config);
    const readFinding = findings.find((f) => f.permission === 'filesystem.read');
    expect(readFinding?.level).toBe('high');
    expect(readFinding?.evidence).toContain('/Users/me');
  });

  it('should not flag non-filesystem servers', () => {
    const config: McpServerConfig = {
      command: 'node',
      args: ['api-server.js'],
    };
    const findings = analyzeFilesystem('api', config);
    expect(findings.length).toBe(0);
  });
});

describe('GitHub analysis', () => {
  it('should detect GitHub server with token', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: ['run', 'ghcr.io/github/github-mcp-server:latest'],
      env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'redacted' },
    };
    const findings = analyzeGitHub('github', config);
    expect(findings.some((f) => f.permission === 'repo.read')).toBe(true);
    expect(findings.some((f) => f.permission === 'repo.write')).toBe(true);
  });

  it('should NOT emit repo.read/write for git install URL', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['--from', 'git+https://github.com/org/repo', 'server'],
      env: {},
    };
    const findings = analyzeGitHub('paymcp-demo', config);
    expect(findings.some((f) => f.permission === 'repo.read')).toBe(false);
    expect(findings.some((f) => f.permission === 'repo.write')).toBe(false);
  });

  it('should detect GitHub server via npx with GITHUB_TOKEN', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['github-mcp-server'],
      env: { GITHUB_TOKEN: 'redacted' },
    };
    const findings = analyzeGitHub('my-server', config);
    expect(findings.some((f) => f.permission === 'repo.read')).toBe(true);
    expect(findings.some((f) => f.permission === 'repo.write')).toBe(true);
  });
});

describe('Browser analysis', () => {
  it('should detect browser automation', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@anthropic/mcp-playwright'],
    };
    const findings = analyzeBrowser('playwright', config);
    expect(findings.some((f) => f.permission === 'browser.control')).toBe(true);
    expect(findings.some((f) => f.permission === 'network.fetch')).toBe(true);
  });
});

describe('Database analysis', () => {
  it('should detect database server', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@mcp/postgres-server'],
      env: { DATABASE_URL: 'postgres://...' },
    };
    const findings = analyzeDatabase('postgres', config);
    expect(findings.some((f) => f.permission === 'database.query')).toBe(true);
    expect(findings.some((f) => f.permission === 'database.mutate')).toBe(true);
  });
});

describe('Cloud analysis', () => {
  it('should detect cloud server', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@mcp/aws-server'],
      env: { AWS_ACCESS_KEY_ID: 'redacted' },
    };
    const findings = analyzeCloud('aws', config);
    expect(findings.some((f) => f.permission === 'cloud.read')).toBe(true);
  });
});

describe('Shell execution analysis', () => {
  it('should detect direct shell command', () => {
    const config: McpServerConfig = {
      command: 'bash',
      args: ['-c', 'node server.js'],
    };
    const findings = analyzeShellExecution('shell', config);
    expect(findings.some((f) => f.permission === 'shell.execute')).toBe(true);
    expect(findings[0].level).toBe('critical');
  });

  it('should detect shell-like server names', () => {
    const config: McpServerConfig = {
      command: 'node',
      args: ['shell-server.js'],
    };
    const findings = analyzeShellExecution('shell-runner', config);
    expect(findings.some((f) => f.permission === 'shell.execute')).toBe(true);
  });
});

describe('Docker risk analysis', () => {
  it('should detect :latest tag', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: ['run', '-i', '--rm', 'ghcr.io/example/server:latest'],
    };
    const { risks } = analyzeDockerRisks('test', config);
    expect(risks.some((r) => r.id === 'docker-latest')).toBe(true);
  });

  it('should detect --privileged', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: ['run', '--privileged', 'some-image:1.0'],
    };
    const { risks } = analyzeDockerRisks('test', config);
    expect(risks.some((r) => r.id === 'docker-privileged')).toBe(true);
    expect(risks.find((r) => r.id === 'docker-privileged')?.level).toBe('critical');
  });

  it('should detect --network host', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: ['run', '--network', 'host', 'some-image:1.0'],
    };
    const { risks } = analyzeDockerRisks('test', config);
    expect(risks.some((r) => r.id === 'docker-host-network')).toBe(true);
  });

  it('should detect broad volume mounts', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: ['run', '-v', '/:/mnt', 'some-image:1.0'],
    };
    const { risks } = analyzeDockerRisks('test', config);
    expect(risks.some((r) => r.id === 'docker-broad-mount')).toBe(true);
  });

  it('should detect secret env in docker -e', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: ['run', '-e', 'AWS_SECRET_ACCESS_KEY', 'some-image:1.0'],
      env: { AWS_SECRET_ACCESS_KEY: 'redacted' },
    };
    const { risks } = analyzeDockerRisks('test', config);
    expect(risks.some((r) => r.id.startsWith('docker-secret-env'))).toBe(true);
  });
});

describe('npx risk analysis', () => {
  it('should detect unpinned npx packages', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem'],
    };
    const { risks } = analyzeNpxRisks('test', config);
    expect(risks.some((r) => r.id === 'npx-unpinned')).toBe(true);
  });

  it('should detect @latest packages', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem@latest'],
    };
    const { risks } = analyzeNpxRisks('test', config);
    expect(risks.some((r) => r.id === 'npx-latest')).toBe(true);
  });

  it('should not flag pinned packages', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3'],
    };
    const { risks } = analyzeNpxRisks('test', config);
    expect(risks.length).toBe(0);
  });
});

describe('curl pipe shell analysis', () => {
  it('should detect curl | bash', () => {
    const config: McpServerConfig = {
      command: 'bash',
      args: ['-c', 'curl -sSL https://example.com/install.sh | bash'],
    };
    const risks = analyzeCurlPipeRisks('test', config);
    expect(risks.some((r) => r.id === 'curl-pipe-shell')).toBe(true);
    expect(risks[0].level).toBe('critical');
  });
});

describe('Remote Git install risk', () => {
  it('should detect remote-git-source and remote-git-unpinned for uvx --from git URL', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['--from', 'git+https://github.com/org/repo', 'server'],
      env: {},
    };
    const { risks } = analyzeUvxRisks('test', config);
    expect(risks.some((r) => r.id === 'remote-git-source')).toBe(true);
    expect(risks.some((r) => r.id === 'remote-git-unpinned')).toBe(true);
    expect(risks.some((r) => r.id === 'uvx-remote-source')).toBe(true);
  });

  it('should detect branch ref pin as medium', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['--from', 'git+https://github.com/org/repo@main', 'server'],
      env: {},
    };
    const { risks } = analyzeUvxRisks('test', config);
    expect(risks.some((r) => r.id === 'remote-git-source')).toBe(true);
    expect(risks.some((r) => r.id === 'remote-git-branch-ref')).toBe(true);
    expect(risks.some((r) => r.id === 'remote-git-unpinned')).toBe(false);
  });

  it('should accept version tag pins', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['--from', 'git+https://github.com/org/repo@v1.2.3', 'server'],
      env: {},
    };
    const { risks } = analyzeUvxRisks('test', config);
    expect(risks.some((r) => r.id === 'remote-git-source')).toBe(true);
    expect(risks.some((r) => r.id === 'remote-git-unpinned')).toBe(false);
    expect(risks.some((r) => r.id === 'remote-git-branch-ref')).toBe(false);
  });

  it('should accept commit SHA pins', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['--from', 'git+https://github.com/org/repo@abcdef1234567', 'server'],
      env: {},
    };
    const { risks } = analyzeUvxRisks('test', config);
    expect(risks.some((r) => r.id === 'remote-git-unpinned')).toBe(false);
    expect(risks.some((r) => r.id === 'remote-git-branch-ref')).toBe(false);
  });
});

describe('x402 detection', () => {
  it('should detect x402 payment protocol and receive', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['paymcp-x402-server'],
      env: {
        X402_PAY_TO_ADDRESS: '0xabc',
        OPENAI_API_KEY: 'redacted',
      },
    };
    const findings = analyzeX402('paymcp-x402', config);
    expect(findings.some((f) => f.permission === 'payment_protocol.x402')).toBe(true);
    expect(findings.some((f) => f.permission === 'payments.receive')).toBe(true);
  });

  it('should NOT auto-classify as payments.charge without evidence', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: ['paymcp-x402-server'],
      env: {
        X402_PAY_TO_ADDRESS: '0xabc',
      },
    };
    const allFindings = [
      ...analyzeX402('paymcp-x402', config),
      ...analyzePayments('paymcp-x402', config),
    ];
    // Should not have payments.charge unless there's a Stripe secret
    const chargeFindings = allFindings.filter((f) => f.permission === 'payments.charge');
    // If any charge finding exists, explanation must contain "possible" or "inferred"
    for (const f of chargeFindings) {
      expect(f.explanation.toLowerCase()).toMatch(/possible|inferred/);
    }
  });
});

describe('Network egress detection', () => {
  it('should infer network egress from OPENAI_API_KEY', () => {
    const config: McpServerConfig = {
      command: 'python',
      args: ['server.py'],
      env: { OPENAI_API_KEY: 'sk-test' },
    };
    const findings = analyzeNetworkEgress('test', config);
    expect(findings.some((f) => f.permission === 'network.egress')).toBe(true);
    expect(findings.some((f) => f.explanation.includes('OpenAI'))).toBe(true);
  });

  it('should infer network egress from STRIPE_SECRET_KEY', () => {
    const config: McpServerConfig = {
      command: 'python',
      args: ['server.py'],
      env: { STRIPE_SECRET_KEY: 'sk_live_test' },
    };
    const findings = analyzeNetworkEgress('test', config);
    expect(findings.some((f) => f.explanation.includes('Stripe'))).toBe(true);
  });

  it('should not leak env values in evidence', () => {
    const config: McpServerConfig = {
      command: 'python',
      args: ['server.py'],
      env: { OPENAI_API_KEY: 'sk-SUPER-SECRET-VALUE' },
    };
    const findings = analyzeNetworkEgress('test', config);
    for (const f of findings) {
      expect(f.evidence).not.toContain('sk-SUPER-SECRET-VALUE');
    }
  });
});

describe('uv --with unpinned dependencies', () => {
  it('should detect unpinned --with deps', () => {
    const config: McpServerConfig = {
      command: 'uv',
      args: ['run', 'mcp', 'install', 'server.py', '--with', 'openai', '--with', 'paymcp', '--with', 'requests', '--with', 'Pillow'],
    };
    const risks = analyzeUvWithRisks('test', config);
    expect(risks.filter((r) => r.id === 'uv-with-unpinned').length).toBe(4);
  });

  it('should not flag pinned --with deps', () => {
    const config: McpServerConfig = {
      command: 'uv',
      args: ['run', 'mcp', 'install', 'server.py', '--with', 'openai==1.2.3', '--with', 'requests>=2.0'],
    };
    const risks = analyzeUvWithRisks('test', config);
    expect(risks.length).toBe(0);
  });

  it('should detect local-script in uv run command', () => {
    const config: McpServerConfig = {
      command: 'uv',
      args: ['run', 'mcp', 'install', 'server.py', '--with', 'openai'],
    };
    const risks = analyzeLocalScriptRisks('test', config);
    expect(risks.some((r) => r.id === 'local-script')).toBe(true);
  });
});

describe('Main concern deduplication', () => {
  it('should deduplicate and count repeated concerns', () => {
    const permissions = [
      { id: 's1', permission: 'secrets.env' as const, level: 'high' as const, confidence: 'high' as const, evidence: 'e1', explanation: 'x' },
      { id: 's2', permission: 'secrets.env' as const, level: 'high' as const, confidence: 'high' as const, evidence: 'e2', explanation: 'x' },
      { id: 's3', permission: 'secrets.env' as const, level: 'high' as const, confidence: 'high' as const, evidence: 'e3', explanation: 'x' },
      { id: 'p1', permission: 'payments.charge' as const, level: 'critical' as const, confidence: 'medium' as const, evidence: 'e4', explanation: 'x' },
      { id: 'n1', permission: 'network.egress' as const, level: 'medium' as const, confidence: 'medium' as const, evidence: 'e5', explanation: 'x' },
    ];
    const result = summarizeConcerns(permissions, []);
    expect(result).toContain('secrets.env x3');
    expect(result).toContain('payments.charge');
    expect(result).toContain('network.egress');
    expect(result).not.toContain('secrets.env, secrets.env');
  });
});

describe('Wording accuracy', () => {
  it('should use inferred/possible wording for Stripe payment findings', () => {
    const config: McpServerConfig = {
      command: 'python',
      args: ['server.py'],
      env: { STRIPE_SECRET_KEY: 'sk_live_test' },
    };
    const findings = analyzePayments('stripe-server', config);
    const chargeFinding = findings.find((f) => f.permission === 'payments.charge');
    expect(chargeFinding).toBeDefined();
    expect(chargeFinding!.explanation.toLowerCase()).toMatch(/possible|inferred/);
    expect(chargeFinding!.explanation).not.toMatch(/^Payment charge capability detected$/);
  });

  it('should use inferred wording for database mutate', () => {
    const config: McpServerConfig = {
      command: 'python',
      args: ['server.py'],
      env: { REDIS_URL: 'redis://localhost:6379' },
    };
    const findings = analyzeDatabase('redis-server', config);
    const mutateFinding = findings.find((f) => f.permission === 'database.mutate');
    expect(mutateFinding).toBeDefined();
    expect(mutateFinding!.explanation.toLowerCase()).toMatch(/possible|inferred/);
  });
});

describe('Secret redaction', () => {
  it('should never include secret values in findings', () => {
    const config: McpServerConfig = {
      command: 'python',
      args: ['server.py'],
      env: {
        STRIPE_SECRET_KEY: 'sk_live_EXAMPLE_DO_NOT_USE',
        OPENAI_API_KEY: 'sk-EXAMPLE_DO_NOT_USE',
        WALLEOT_API_KEY: 'wlt_EXAMPLE_DO_NOT_USE',
      },
    };
    const result = analyzeServer('test', config);
    const allText = JSON.stringify(result);
    expect(allText).not.toContain('sk_live_EXAMPLE_DO_NOT_USE');
    expect(allText).not.toContain('sk-EXAMPLE_DO_NOT_USE');
    expect(allText).not.toContain('wlt_EXAMPLE_DO_NOT_USE');
  });
});

describe('Full server analysis - PayMCP demo', () => {
  it('should NOT report repo.read/write for paymcp-demo with git install URL', () => {
    const config: McpServerConfig = {
      command: 'uvx',
      args: [
        '--from',
        'git+https://github.com/blustAI/python-paymcp-server-demo',
        'server',
      ],
      env: {
        OPENAI_API_KEY: 'sk-EXAMPLE',
        STRIPE_SECRET_KEY: 'sk_live_EXAMPLE',
        WALLEOT_API_KEY: 'wlt_EXAMPLE',
      },
    };
    const result = analyzeServer('paymcp-demo', config);
    expect(result.permissions.some((f) => f.permission === 'repo.read')).toBe(false);
    expect(result.permissions.some((f) => f.permission === 'repo.write')).toBe(false);
    expect(result.installRisks.some((r) => r.id === 'remote-git-source')).toBe(true);
    expect(result.installRisks.some((r) => r.id === 'remote-git-unpinned')).toBe(true);
    expect(result.permissions.some((f) => f.permission === 'network.egress')).toBe(true);
  });
});

describe('Full server analysis', () => {
  it('should produce a complete analysis for a risky server', () => {
    const config: McpServerConfig = {
      command: 'docker',
      args: [
        'run',
        '--privileged',
        '-e',
        'AWS_SECRET_ACCESS_KEY',
        'some-image:latest',
      ],
      env: { AWS_SECRET_ACCESS_KEY: 'redacted' },
    };
    const result = analyzeServer('risky', config);
    expect(result.permissions.length).toBeGreaterThan(0);
    expect(result.installRisks.length).toBeGreaterThan(0);
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Playwright MCP Known-Server Detection
// ---------------------------------------------------------------------------

describe('Playwright MCP detection', () => {
  it('should detect @playwright/mcp in args regardless of server name', () => {
    expect(isPlaywrightMcp('browser-agent', {
      command: 'npx',
      args: ['@playwright/mcp@latest'],
    })).toBe(true);
  });

  it('should detect playwright-mcp variant', () => {
    expect(isPlaywrightMcp('foo', {
      command: 'npx',
      args: ['playwright-mcp'],
    })).toBe(true);
  });

  it('should NOT detect generic playwright without @playwright/mcp package', () => {
    expect(isPlaywrightMcp('playwright', {
      command: 'node',
      args: ['server.js', '--uses-playwright'],
    })).toBe(false);
  });
});

describe('Playwright MCP — basic config', () => {
  const config: McpServerConfig = {
    command: 'npx',
    args: ['@playwright/mcp@latest'],
    env: {},
  };

  it('should report browser.control', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    expect(findings.some((f) => f.permission === 'browser.control')).toBe(true);
  });

  it('should report network.fetch', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    expect(findings.some((f) => f.permission === 'network.fetch')).toBe(true);
  });

  it('should report code.execution (critical) for browser_run_code_unsafe', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    const codeExec = findings.find((f) => f.permission === 'code.execution');
    expect(codeExec).toBeDefined();
    expect(codeExec!.level).toBe('critical');
    expect(codeExec!.evidence).toContain('browser_run_code_unsafe');
  });

  it('should report browser.session_persistence when --isolated is absent', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    expect(findings.some((f) => f.permission === 'browser.session_persistence')).toBe(true);
  });

  it('should report filesystem.read_possible for file upload/drop interactions', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    expect(findings.some((f) => f.permission === 'filesystem.read_possible')).toBe(true);
  });

  it('should report npx-latest install risk', () => {
    const result = analyzeServer('playwright', config);
    expect(result.installRisks.some((r) => r.id === 'npx-latest')).toBe(true);
  });

  it('should produce F grade / critical risk for default Playwright MCP config', () => {
    const result = analyzeServer('playwright', config);
    const score = computeScore(result.permissions, result.installRisks);
    const grade = scoreToGrade(score);
    const risk = computeRisk(score, result.permissions, result.installRisks);
    expect(risk).toBe('critical');
    expect(['D', 'F']).toContain(grade);
  });
});

describe('Playwright MCP — --isolated suppresses session persistence', () => {
  const config: McpServerConfig = {
    command: 'npx',
    args: ['@playwright/mcp@latest', '--isolated'],
    env: {},
  };

  it('should NOT report browser.session_persistence when --isolated is present', () => {
    const findings = analyzePlaywrightMcp('browser', config)!;
    expect(findings.some((f) => f.permission === 'browser.session_persistence')).toBe(false);
  });

  it('should still report browser.control and code.execution', () => {
    const findings = analyzePlaywrightMcp('browser', config)!;
    expect(findings.some((f) => f.permission === 'browser.control')).toBe(true);
    expect(findings.some((f) => f.permission === 'code.execution')).toBe(true);
  });

  it('should not recommend adding --isolated', () => {
    const result = analyzeServer('browser', config);
    for (const rec of result.recommendations) {
      expect(rec).not.toContain('Add --isolated');
    }
    for (const sug of result.saferConfigSuggestions) {
      expect(sug.id).not.toBe('playwright-add-isolated');
    }
  });
});

describe('Playwright MCP — --allowed-origins adjusts recommendation', () => {
  const config: McpServerConfig = {
    command: 'npx',
    args: ['@playwright/mcp@latest', '--allowed-origins', 'https://example.com'],
    env: {},
  };

  it('should still report network.fetch', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    expect(findings.some((f) => f.permission === 'network.fetch')).toBe(true);
  });

  it('should recommend verifying allowlist rather than adding one', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    const networkFinding = findings.find((f) => f.id === 'playwright-network-fetch');
    expect(networkFinding!.recommendation).toContain('Verify');
    expect(networkFinding!.recommendation).not.toContain('Use --allowed-origins');
  });
});

describe('Playwright MCP — --allow-unrestricted-file-access escalates filesystem finding', () => {
  const config: McpServerConfig = {
    command: 'npx',
    args: ['@playwright/mcp@latest', '--allow-unrestricted-file-access'],
    env: {},
  };

  it('should report high filesystem.read with flag evidence', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    const fsFinding = findings.find((f) => f.id === 'playwright-unrestricted-file-access');
    expect(fsFinding).toBeDefined();
    expect(fsFinding!.permission).toBe('filesystem.read');
    expect(fsFinding!.level).toBe('high');
    expect(fsFinding!.evidence).toContain('--allow-unrestricted-file-access');
  });

  it('should NOT report filesystem.read_possible when unrestricted flag is present', () => {
    const findings = analyzePlaywrightMcp('playwright', config)!;
    expect(findings.some((f) => f.permission === 'filesystem.read_possible')).toBe(false);
  });
});

describe('Playwright MCP — package detection independent of server name', () => {
  it('should produce same findings regardless of server name', () => {
    const config: McpServerConfig = {
      command: 'npx',
      args: ['@playwright/mcp@latest'],
      env: {},
    };
    const findingsByName = analyzePlaywrightMcp('browser-agent', config)!;
    const findingsByDefault = analyzePlaywrightMcp('playwright', config)!;
    expect(findingsByName.map((f) => f.id).sort()).toEqual(
      findingsByDefault.map((f) => f.id).sort(),
    );
  });
});

describe('Generic Playwright browser automation (not @playwright/mcp)', () => {
  it('should detect generic browser.control but NOT code.execution', () => {
    const config: McpServerConfig = {
      command: 'node',
      args: ['server.js', '--uses-playwright'],
    };
    const result = analyzeServer('custom-browser', config);
    expect(result.permissions.some((f) => f.permission === 'browser.control')).toBe(true);
    expect(result.permissions.some((f) => f.permission === 'network.fetch')).toBe(true);
    // Should NOT get Playwright MCP-specific findings
    expect(result.permissions.some((f) => f.permission === 'code.execution')).toBe(false);
    expect(result.permissions.some((f) => f.id === 'playwright-run-code-unsafe')).toBe(false);
  });
});

