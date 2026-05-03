/**
 * Scoring model for mcp-label.
 *
 * Multi-dimensional scoring separates:
 * - Capability impact (what can it do?)
 * - Publisher trust (who made it?)
 * - Install hygiene (is the install reproducible?)
 * - Config hardening (is the config locked down?)
 * - Effective risk (practical risk of this config)
 * - Analysis confidence (how confident is the scanner?)
 *
 * Legacy single-score model is preserved for backward compatibility.
 */

import type {
  PermissionFinding,
  InstallRisk,
  SafetyGrade,
  RiskLevel,
  FindingLevel,
  CapabilityImpact,
  EffectiveRisk,
  PublisherTrust,
  AnalysisConfidence,
  ScoreAdjustment,
  ScoringTrace,
  SaferConfigSuggestion,
} from '../types.js';
import type { KnownServerProfile } from '../analysis/knownServers.js';

// ---------------------------------------------------------------------------
// Legacy Deduction Table (kept for backward compatibility)
// ---------------------------------------------------------------------------

const FINDING_DEDUCTIONS: Record<FindingLevel, number> = {
  info: 0,
  low: -5,
  medium: -12,
  high: -25,
  critical: -40,
};

const INSTALL_RISK_DEDUCTIONS: Record<string, number> = {
  'npx-unpinned': -10,
  'npx-latest': -10,
  'uvx-unpinned': -10,
  'uvx-remote-source': -15,
  'docker-latest': -10,
  'docker-untagged': -10,
  'docker-privileged': -30,
  'docker-host-network': -15,
  'docker-broad-mount': -25,
  'curl-pipe-shell': -40,
  'local-script': -10,
  'remote-git-source': -10,
  'remote-git-unpinned': -20,
  'remote-git-branch-ref': -10,
  'uv-with-unpinned': -8,
};

// ---------------------------------------------------------------------------
// Capability Impact
// ---------------------------------------------------------------------------

const CRITICAL_CAPABILITIES: string[] = [
  'shell.execute',
  'code.execution',
  'payments.charge',
  'cloud.admin',
];

const HIGH_CAPABILITIES: string[] = [
  'browser.control',
  'filesystem.write',
  'filesystem.delete',
  'repo.write',
  'repo.admin',
  'database.mutate',
  'cloud.write',
  'email.send',
  'payments.write',
  'payments.charge_possible',
];

const MEDIUM_CAPABILITIES: string[] = [
  'filesystem.read',
  'network.fetch',
  'network.egress',
  'repo.read',
  'database.query',
  'cloud.read',
  'email.read',
  'payments.read',
  'secrets.env',
  'browser.session_persistence',
  'filesystem.read_possible',
  'payment_protocol.x402',
  'payments.receive',
];

export function computeCapabilityImpact(
  permissions: PermissionFinding[],
): CapabilityImpact {
  const ids = permissions.map((p) => p.permission);
  if (ids.some((id) => CRITICAL_CAPABILITIES.includes(id))) return 'critical';
  if (ids.some((id) => HIGH_CAPABILITIES.includes(id))) return 'high';
  if (ids.some((id) => MEDIUM_CAPABILITIES.includes(id))) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// Install Hygiene
// ---------------------------------------------------------------------------

export function computeInstallHygiene(
  installRisks: InstallRisk[],
): SafetyGrade {
  const ids = installRisks.map((r) => r.id);
  const levels = installRisks.map((r) => r.level);

  // F: curl|bash, privileged Docker
  if (ids.includes('curl-pipe-shell') || ids.includes('docker-privileged')) return 'F';

  // D: unpinned remote Git, local script + risky, unpinned Docker + risky
  if (ids.includes('remote-git-unpinned') || ids.includes('uvx-remote-source')) return 'D';

  // C: @latest or unpinned from any runner
  if (ids.includes('npx-latest') || ids.includes('npx-unpinned') ||
      ids.includes('uvx-unpinned') || ids.includes('docker-latest') ||
      ids.includes('docker-untagged') || ids.includes('uv-with-unpinned')) return 'C';

  if (installRisks.length > 0) return 'B';
  return 'A';
}

// ---------------------------------------------------------------------------
// Config Hardening
// ---------------------------------------------------------------------------

export function computeConfigHardening(
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
  saferSuggestions: SaferConfigSuggestion[],
  profile: KnownServerProfile | null,
): SafetyGrade {
  let score = 100;

  // Dangerous combinations → F
  const hasShell = permissions.some((p) => p.permission === 'shell.execute');
  const hasSecret = permissions.some((p) => p.permission === 'secrets.env');
  const hasBroadFs = permissions.some(
    (p) => p.permission === 'filesystem.write' || (p.permission === 'filesystem.read' && p.evidence.includes('Broad path')),
  );
  const hasRemoteUnpinned = installRisks.some((r) => r.id === 'remote-git-unpinned');

  if (hasShell && hasRemoteUnpinned) return 'F';
  if (hasBroadFs && hasSecret && hasShell) return 'F';
  if (installRisks.some((r) => r.id === 'curl-pipe-shell')) return 'F';

  // Missing hardening controls
  const missingControls = saferSuggestions.length;
  score -= missingControls * 8;

  // Unpinned installs
  if (installRisks.some((r) => r.id === 'npx-latest' || r.id === 'npx-unpinned')) score -= 10;

  // Broad access without controls
  if (hasBroadFs) score -= 15;
  if (hasSecret && permissions.some((p) =>
    p.permission === 'repo.write' || p.permission === 'filesystem.write' ||
    p.permission === 'database.mutate' || p.permission === 'cloud.write')) {
    score -= 15;
  }

  // Browser without isolation
  if (permissions.some((p) => p.id === 'playwright-session-persistence')) score -= 8;

  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// Analysis Confidence
// ---------------------------------------------------------------------------

export function computeAnalysisConfidence(
  permissions: PermissionFinding[],
  profile: KnownServerProfile | null,
): AnalysisConfidence {
  if (profile) {
    // Known server with explicit profile = high confidence
    const highConfidenceCount = permissions.filter((p) => p.confidence === 'high').length;
    if (highConfidenceCount >= permissions.length * 0.6) return 'high';
    return 'medium';
  }

  // Unknown server — depends on evidence quality
  const highCount = permissions.filter((p) => p.confidence === 'high').length;
  const medCount = permissions.filter((p) => p.confidence === 'medium').length;
  const total = permissions.length || 1;

  if (highCount / total >= 0.5) return 'medium';
  if (medCount / total >= 0.5) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// Effective Risk
// ---------------------------------------------------------------------------

export function computeEffectiveRisk(
  capabilityImpact: CapabilityImpact,
  publisherTrust: PublisherTrust,
  installHygiene: SafetyGrade,
  configHardening: SafetyGrade,
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
): EffectiveRisk {
  // Always critical for truly dangerous combos
  const hasShell = permissions.some((p) => p.permission === 'shell.execute');
  const hasCurlPipe = installRisks.some((r) => r.id === 'curl-pipe-shell');
  const hasDockerPriv = installRisks.some((r) => r.id === 'docker-privileged');
  if (hasCurlPipe || hasDockerPriv || (hasShell && installRisks.some((r) => r.id === 'remote-git-unpinned'))) {
    return 'critical';
  }

  // High publisher trust can mitigate from critical to high
  // but not lower — capabilities are still powerful
  if (capabilityImpact === 'critical') {
    if (publisherTrust === 'high') return 'high';
    return 'critical';
  }

  if (capabilityImpact === 'high') {
    if (publisherTrust === 'high' && (configHardening === 'A' || configHardening === 'B')) return 'medium';
    if (publisherTrust === 'high') return 'high';
    if (publisherTrust === 'unknown' || publisherTrust === 'low') return 'high';
    return 'high';
  }

  if (capabilityImpact === 'medium') {
    if (configHardening === 'A' || configHardening === 'B') return 'low';
    return 'medium';
  }

  return 'low';
}

// ---------------------------------------------------------------------------
// Hardening Grade (user-facing letter grade)
// ---------------------------------------------------------------------------

export function computeHardeningGrade(
  installHygiene: SafetyGrade,
  configHardening: SafetyGrade,
): SafetyGrade {
  const gradeOrder: Record<SafetyGrade, number> = { 'A': 4, 'B': 3, 'C': 2, 'D': 1, 'F': 0 };
  const avg = (gradeOrder[installHygiene] + gradeOrder[configHardening]) / 2;
  if (avg >= 3.5) return 'A';
  if (avg >= 2.5) return 'B';
  if (avg >= 1.5) return 'C';
  if (avg >= 0.5) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// Scoring Trace Generator
// ---------------------------------------------------------------------------

export function generateScoringTrace(
  capabilityImpact: CapabilityImpact,
  publisherTrust: PublisherTrust,
  installHygiene: SafetyGrade,
  configHardening: SafetyGrade,
  effectiveRisk: EffectiveRisk,
  analysisConfidence: AnalysisConfidence,
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
  profile: KnownServerProfile | null,
): ScoringTrace {
  const adjustments: ScoreAdjustment[] = [];

  // Capability impact explanation
  const critCaps = permissions.filter((p) => CRITICAL_CAPABILITIES.includes(p.permission));
  const highCaps = permissions.filter((p) => HIGH_CAPABILITIES.includes(p.permission));

  if (critCaps.length > 0) {
    adjustments.push({
      dimension: 'capabilityImpact',
      reason: `Critical capabilities detected: ${critCaps.map((c) => c.permission).join(', ')}`,
      evidence: critCaps.map((c) => c.evidence).join('; '),
    });
  } else if (highCaps.length > 0) {
    adjustments.push({
      dimension: 'capabilityImpact',
      reason: `High-impact capabilities detected: ${highCaps.map((c) => c.permission).join(', ')}`,
    });
  }

  // Publisher trust
  if (profile) {
    adjustments.push({
      dimension: 'publisherTrust',
      reason: `Known server profile matched: ${profile.displayName} (${profile.publisher.name})`,
      evidence: profile.publisher.evidence,
    });
  } else {
    adjustments.push({
      dimension: 'publisherTrust',
      reason: 'No known server profile matched. Publisher trust is unknown.',
    });
  }

  // Install hygiene
  if (installRisks.length > 0) {
    adjustments.push({
      dimension: 'installHygiene',
      reason: `Install risks found: ${installRisks.map((r) => r.id).join(', ')}`,
    });
  }

  // Config hardening
  const expectedCount = permissions.filter((p) => p.expectation === 'expected').length;
  const unexpectedCount = permissions.filter((p) => p.expectation === 'unexpected').length;
  if (unexpectedCount > 0) {
    adjustments.push({
      dimension: 'configHardening',
      reason: `${unexpectedCount} unexpected capability/capabilities detected`,
    });
  }

  // Build explanation
  const parts: string[] = [];
  parts.push(`Capability impact is **${capabilityImpact}** because ${capabilityImpact === 'low' ? 'no high-impact capabilities were detected' : `the server has ${capabilityImpact}-impact capabilities (${permissions.map((p) => p.permission).filter((v, i, a) => a.indexOf(v) === i).slice(0, 3).join(', ')})`}.`);
  parts.push(`Publisher trust is **${publisherTrust}**${profile ? ` because the package matches a known ${profile.publisher.name} profile` : ' because no known publisher profile was matched'}.`);
  parts.push(`Install hygiene is **${installHygiene}**${installRisks.length > 0 ? ` because ${installRisks[0].explanation.toLowerCase()}` : ' because no install risks were found'}.`);
  parts.push(`Config hardening is **${configHardening}**.`);
  parts.push(`Effective risk is **${effectiveRisk}**.`);

  return {
    adjustments,
    explanation: parts.join(' '),
  };
}

// ---------------------------------------------------------------------------
// Legacy Scoring (backward compatible)
// ---------------------------------------------------------------------------

export function computeScore(
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
): number {
  let score = 100;

  for (const finding of permissions) {
    score += FINDING_DEDUCTIONS[finding.level] ?? 0;
  }

  for (const risk of installRisks) {
    const specificDeduction = INSTALL_RISK_DEDUCTIONS[risk.id];
    if (specificDeduction !== undefined) {
      score += specificDeduction;
    } else {
      score += FINDING_DEDUCTIONS[risk.level] ?? 0;
    }
  }

  // Compound deductions
  const hasSecret = permissions.some((p) => p.permission === 'secrets.env');
  const hasWrite = permissions.some(
    (p) =>
      p.permission === 'repo.write' ||
      p.permission === 'filesystem.write' ||
      p.permission === 'database.mutate' ||
      p.permission === 'cloud.write' ||
      p.permission === 'cloud.admin',
  );
  if (hasSecret && hasWrite) score -= 15;

  const hasPaymentCharge = permissions.some(
    (p) => p.permission === 'payments.charge' || p.permission === 'payments.charge_possible',
  );
  if (hasSecret && hasPaymentCharge) score -= 10;

  const hasLocalScript = installRisks.some((r) => r.id === 'local-script');
  if (hasLocalScript && hasSecret && hasPaymentCharge) score -= 10;

  const hasRemoteGitUnpinned = installRisks.some((r) => r.id === 'remote-git-unpinned');
  if (hasRemoteGitUnpinned && hasSecret) score -= 10;

  const hasShell = permissions.some((p) => p.permission === 'shell.execute');
  if (hasShell) score -= 20;

  const hasCodeExecution = permissions.some((p) => p.permission === 'code.execution');
  const hasBrowserControl = permissions.some((p) => p.permission === 'browser.control');
  if (hasCodeExecution && hasBrowserControl) score -= 5;

  return Math.max(0, Math.min(100, score));
}

export function scoreToGrade(score: number): SafetyGrade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function computeRisk(
  score: number,
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
): RiskLevel {
  const allFindings = [...permissions, ...installRisks];
  const hasCritical = allFindings.some((f) => f.level === 'critical');
  const hasHigh = allFindings.some((f) => f.level === 'high');

  if (hasCritical || score < 40) return 'critical';
  if (hasHigh || score < 70) return 'high';
  if (score < 85) return 'medium';
  return 'low';
}

export function computeOverallRisk(serverRisks: RiskLevel[]): RiskLevel {
  const order: RiskLevel[] = ['critical', 'high', 'medium', 'low'];
  for (const level of order) {
    if (serverRisks.includes(level)) return level;
  }
  return 'low';
}

export function computeOverallGrade(serverScores: number[]): SafetyGrade {
  if (serverScores.length === 0) return 'A';
  const avg = serverScores.reduce((a, b) => a + b, 0) / serverScores.length;
  return scoreToGrade(avg);
}
