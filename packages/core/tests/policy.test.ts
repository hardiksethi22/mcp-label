import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../src/policy/index.js';
import type { ServerLabel, PolicyFile } from '../src/types.js';

const mockServer: ServerLabel = {
  name: 'test-server',
  command: 'docker',
  args: ['run', 'some-image:latest'],
  envVars: ['API_KEY'],
  permissions: [
    {
      id: 'shell-execute',
      permission: 'shell.execute',
      level: 'critical',
      confidence: 'high',
      evidence: 'Shell command: bash',
      explanation: 'Shell execution detected.',
    },
    {
      id: 'filesystem-read',
      permission: 'filesystem.read',
      level: 'high',
      confidence: 'high',
      evidence: 'Broad path argument: /',
      explanation: 'Filesystem read access.',
    },
  ],
  installRisks: [
    {
      id: 'docker-latest',
      level: 'medium',
      confidence: 'high',
      evidence: 'some-image:latest',
      explanation: 'Docker latest tag.',
      recommendation: 'Pin image.',
    },
  ],
  recommendations: [],
  saferConfigSuggestions: [],
  score: 30,
  grade: 'F',
  risk: 'critical',
};

describe('Policy evaluation', () => {
  it('should deny based on permission', () => {
    const policy: PolicyFile = {
      version: '0.1',
      rules: [
        {
          id: 'no-shell',
          description: 'Block shell execution.',
          deny: { permissions: ['shell.execute'] },
        },
      ],
    };
    const results = evaluatePolicy(mockServer, policy);
    expect(results[0].passed).toBe(false);
    expect(results[0].ruleId).toBe('no-shell');
  });

  it('should deny with evidence matching', () => {
    const policy: PolicyFile = {
      version: '0.1',
      rules: [
        {
          id: 'no-broad-fs',
          description: 'Block broad filesystem.',
          deny: {
            permissions: ['filesystem.read'],
            evidenceIncludes: ['/'],
          },
        },
      ],
    };
    const results = evaluatePolicy(mockServer, policy);
    expect(results[0].passed).toBe(false);
  });

  it('should pass when evidence does not match', () => {
    const policy: PolicyFile = {
      version: '0.1',
      rules: [
        {
          id: 'no-home-fs',
          description: 'Block home filesystem.',
          deny: {
            permissions: ['filesystem.read'],
            evidenceIncludes: ['$HOME'],
          },
        },
      ],
    };
    const results = evaluatePolicy(mockServer, policy);
    expect(results[0].passed).toBe(true);
  });

  it('should require docker pinning', () => {
    const policy: PolicyFile = {
      version: '0.1',
      rules: [
        {
          id: 'docker-pinned',
          description: 'Docker must be pinned.',
          require: { install: { dockerPinned: true } },
        },
      ],
    };
    const results = evaluatePolicy(mockServer, policy);
    expect(results[0].passed).toBe(false);
  });

  it('should pass when no matching violations', () => {
    const cleanServer: ServerLabel = {
      ...mockServer,
      permissions: [],
      installRisks: [],
    };
    const policy: PolicyFile = {
      version: '0.1',
      rules: [
        {
          id: 'no-shell',
          description: 'Block shell.',
          deny: { permissions: ['shell.execute'] },
        },
      ],
    };
    const results = evaluatePolicy(cleanServer, policy);
    expect(results[0].passed).toBe(true);
  });
});

