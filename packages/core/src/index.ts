/**
 * Main entry point for @mcp-label/core.
 *
 * Provides the full scanning pipeline: parse config → analyze → score → report.
 */

// Re-export types
export * from './types.js';

// Re-export schemas
export * from './schemas/index.js';

// Re-export config utilities
export {
  parseConfigFile,
  redactEnvValues,
  getDiscoveryPaths,
  discoverConfigFiles,
  mergeConfigs,
} from './config/index.js';

// Re-export analysis
export { analyzeServer } from './analysis/index.js';

// Re-export known servers
export { findKnownProfile, KNOWN_SERVER_PROFILES } from './analysis/knownServers.js';
export type { KnownServerProfile } from './analysis/knownServers.js';

// Re-export scoring
export {
  computeScore,
  scoreToGrade,
  computeRisk,
  computeOverallRisk,
  computeOverallGrade,
  computeCapabilityImpact,
  computeInstallHygiene,
  computeConfigHardening,
  computeAnalysisConfidence,
  computeEffectiveRisk,
  computeHardeningGrade,
  generateScoringTrace,
} from './scoring/index.js';

// Re-export policy
export { parsePolicyFile, evaluatePolicy } from './policy/index.js';

// Re-export exporters
export {
  exportTerminal,
  exportMarkdown,
  exportSvg,
  exportJson,
} from './exporters/index.js';

// Re-export utils
export { now, unique, summarizeConcerns } from './utils/index.js';

// ---------------------------------------------------------------------------
// High-level scan API
// ---------------------------------------------------------------------------

import type {
  McpConfigFile,
  McpLabelReport,
  ServerLabel,
  PolicyFile,
  RiskLevel,
  CapabilityImpact,
  PublisherTrust,
  SafetyGrade,
} from './types.js';
import { redactEnvValues } from './config/index.js';
import { analyzeServer } from './analysis/index.js';
import { findKnownProfile, isExpectedCapability } from './analysis/knownServers.js';
import {
  computeScore, scoreToGrade, computeRisk, computeOverallRisk, computeOverallGrade,
  computeCapabilityImpact, computeInstallHygiene, computeConfigHardening,
  computeAnalysisConfidence, computeEffectiveRisk, computeHardeningGrade,
  generateScoringTrace,
} from './scoring/index.js';
import { evaluatePolicy } from './policy/index.js';
import { now, unique, summarizeConcerns } from './utils/index.js';

export interface ScanOptions {
  configPaths: string[];
  discovered: boolean;
  policy?: PolicyFile;
  strict?: boolean;
  explain?: boolean;
  noKnownProfiles?: boolean;
}

/**
 * Scan an MCP config and produce a full label report.
 */
export function scan(config: McpConfigFile, options: ScanOptions): McpLabelReport {
  const servers: ServerLabel[] = [];

  for (const [name, serverConfig] of Object.entries(config.mcpServers)) {
    const {
      permissions,
      installRisks,
      recommendations,
      saferConfigSuggestions,
      packageName,
      dockerImage,
    } = analyzeServer(name, serverConfig);

    // Find known server profile
    const profile = options.noKnownProfiles ? null : findKnownProfile(name, serverConfig);

    // Tag findings as expected/unexpected based on known profile
    for (const perm of permissions) {
      if (profile) {
        perm.expectation = isExpectedCapability(profile, perm.permission) ? 'expected' : 'unexpected';
      } else {
        perm.expectation = 'unknown';
      }
    }

    // Legacy scoring
    const score = computeScore(permissions, installRisks);
    const grade = scoreToGrade(score);
    const risk = computeRisk(score, permissions, installRisks);

    // Multi-dimensional scoring
    const capabilityImpact = computeCapabilityImpact(permissions);
    const publisherTrust: PublisherTrust = profile?.publisher.trust ?? 'unknown';
    const installHygiene = computeInstallHygiene(installRisks);
    const configHardening = computeConfigHardening(permissions, installRisks, saferConfigSuggestions, profile);
    const analysisConfidence = computeAnalysisConfidence(permissions, profile);
    const hardeningGrade = computeHardeningGrade(installHygiene, configHardening);

    // In strict mode, don't let publisher trust mitigate risk
    const effectiveTrust = options.strict ? 'unknown' as PublisherTrust : publisherTrust;
    const effectiveRisk = computeEffectiveRisk(
      capabilityImpact, effectiveTrust, installHygiene, configHardening,
      permissions, installRisks,
    );

    // Scoring trace
    const scoringTrace = generateScoringTrace(
      capabilityImpact, publisherTrust, installHygiene, configHardening,
      effectiveRisk, analysisConfidence, permissions, installRisks, profile,
    );

    const serverLabel: ServerLabel = {
      name,
      command: serverConfig.command,
      args: serverConfig.args || [],
      packageName,
      dockerImage,
      envVars: [
        ...redactEnvValues(serverConfig.env),
        ...Object.keys(serverConfig.requestInit?.headers || {}).map((h) => `[header] ${h}`),
      ],

      capabilityImpact,
      effectiveRisk,
      hardeningGrade,
      publisherTrust,
      installHygiene,
      configHardening,
      analysisConfidence,
      knownServerProfile: profile?.id,

      permissions,
      installRisks,
      recommendations,
      saferConfigSuggestions,
      scoringTrace,

      // Legacy
      score,
      grade,
      risk,
    };

    if (options.policy) {
      serverLabel.policyResults = evaluatePolicy(serverLabel, options.policy);
    }

    servers.push(serverLabel);
  }

  // Compute overall summary
  const allRisks = servers.map((s) => s.risk);
  const allScores = servers.map((s) => s.score);
  const overallRisk = computeOverallRisk(allRisks);
  const overallGrade = computeOverallGrade(allScores);
  const totalFindings = servers.reduce(
    (sum, s) => sum + s.permissions.length + s.installRisks.length,
    0,
  );

  const allPermissions = servers.flatMap((s) => s.permissions);
  const allInstallRisks = servers.flatMap((s) => s.installRisks);
  const topConcerns = summarizeConcerns(allPermissions, allInstallRisks, 5);

  // Top mitigations from recommendations
  const topMitigations = servers
    .flatMap((s) => s.saferConfigSuggestions.map((sug) => sug.title))
    .filter((v, i, a) => a.indexOf(v) === i)
    .slice(0, 5);

  // Overall multi-dimensional (worst-case across servers)
  const impactOrder: CapabilityImpact[] = ['critical', 'high', 'medium', 'low'];
  const trustOrder: PublisherTrust[] = ['unknown', 'low', 'medium', 'high'];
  const gradeOrder: SafetyGrade[] = ['F', 'D', 'C', 'B', 'A'];
  const confOrder: ('low' | 'medium' | 'high')[] = ['low', 'medium', 'high'];

  const worstImpact = impactOrder.find((l) => servers.some((s) => s.capabilityImpact === l)) ?? 'low';
  const worstEffRisk = impactOrder.find((l) => servers.some((s) => s.effectiveRisk === l)) ?? 'low';
  const worstTrust = trustOrder.find((l) => servers.some((s) => s.publisherTrust === l)) ?? 'unknown';
  const worstInstHyg = gradeOrder.find((g) => servers.some((s) => s.installHygiene === g)) ?? 'A';
  const worstConfHard = gradeOrder.find((g) => servers.some((s) => s.configHardening === g)) ?? 'A';
  const worstHardGrade = gradeOrder.find((g) => servers.some((s) => s.hardeningGrade === g)) ?? 'A';
  const lowestConf = confOrder.find((c) => servers.some((s) => s.analysisConfidence === c)) ?? 'low';

  const report: McpLabelReport = {
    schemaVersion: '0.2',
    generatedAt: now(),
    source: {
      configPaths: options.configPaths,
      discovered: options.discovered,
      staticOnly: true,
    },
    summary: {
      serverCount: servers.length,
      capabilityImpact: worstImpact as CapabilityImpact,
      effectiveRisk: worstEffRisk as CapabilityImpact,
      hardeningGrade: worstHardGrade,
      publisherTrust: worstTrust as PublisherTrust,
      installHygiene: worstInstHyg,
      configHardening: worstConfHard,
      analysisConfidence: lowestConf as 'low' | 'medium' | 'high',
      totalFindings,
      topConcerns,
      topMitigations,
      // Legacy
      overallGrade,
      overallRisk,
      highestRisk: computeOverallRisk(allRisks),
    },
    servers,
  };

  return report;
}

