import { describe, it, expect } from 'vitest';
import { computeScore, scoreToGrade, computeRisk } from '../src/scoring/index.js';
import type { PermissionFinding, InstallRisk } from '../src/types.js';

describe('Scoring', () => {
  it('should start at 100 with no findings', () => {
    expect(computeScore([], [])).toBe(100);
  });

  it('should deduct for high findings', () => {
    const findings: PermissionFinding[] = [
      {
        id: 'test',
        permission: 'secrets.env',
        level: 'high',
        confidence: 'high',
        evidence: 'test',
        explanation: 'test',
      },
    ];
    const score = computeScore(findings, []);
    expect(score).toBeLessThan(100);
  });

  it('should deduct for critical findings', () => {
    const findings: PermissionFinding[] = [
      {
        id: 'test',
        permission: 'shell.execute',
        level: 'critical',
        confidence: 'high',
        evidence: 'test',
        explanation: 'test',
      },
    ];
    const score = computeScore(findings, []);
    expect(score).toBeLessThanOrEqual(40);
  });

  it('should deduct for install risks', () => {
    const risks: InstallRisk[] = [
      {
        id: 'docker-privileged',
        level: 'critical',
        confidence: 'high',
        evidence: 'test',
        explanation: 'test',
        recommendation: 'test',
      },
    ];
    const score = computeScore([], risks);
    expect(score).toBeLessThan(100);
  });

  it('should clamp score to 0-100', () => {
    const findings: PermissionFinding[] = Array(10).fill({
      id: 'test',
      permission: 'shell.execute',
      level: 'critical',
      confidence: 'high',
      evidence: 'test',
      explanation: 'test',
    });
    expect(computeScore(findings, [])).toBe(0);
  });
});

describe('Grade mapping', () => {
  it('should return A for 90+', () => expect(scoreToGrade(95)).toBe('A'));
  it('should return B for 75-89', () => expect(scoreToGrade(80)).toBe('B'));
  it('should return C for 60-74', () => expect(scoreToGrade(65)).toBe('C'));
  it('should return D for 40-59', () => expect(scoreToGrade(50)).toBe('D'));
  it('should return F for below 40', () => expect(scoreToGrade(20)).toBe('F'));
});

describe('Risk mapping', () => {
  it('should return low for clean configs', () => {
    expect(computeRisk(95, [], [])).toBe('low');
  });

  it('should return critical for critical findings', () => {
    const findings: PermissionFinding[] = [
      {
        id: 'test',
        permission: 'shell.execute',
        level: 'critical',
        confidence: 'high',
        evidence: 'test',
        explanation: 'test',
      },
    ];
    expect(computeRisk(30, findings, [])).toBe('critical');
  });

  it('should return high for high findings', () => {
    const findings: PermissionFinding[] = [
      {
        id: 'test',
        permission: 'secrets.env',
        level: 'high',
        confidence: 'high',
        evidence: 'test',
        explanation: 'test',
      },
    ];
    expect(computeRisk(60, findings, [])).toBe('high');
  });
});

