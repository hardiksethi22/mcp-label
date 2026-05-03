/**
 * Zod schemas for mcp-label data structures.
 * Used for validation and JSON Schema generation.
 */

import { z } from 'zod';
import { PERMISSION_IDS } from '../types.js';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const PermissionIdSchema = z.enum(PERMISSION_IDS);

export const FindingLevelSchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);

export const ConfidenceSchema = z.enum(['low', 'medium', 'high']);

export const SafetyGradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);

export const RiskLevelSchema = z.enum(['low', 'medium', 'high', 'critical']);

export const PublisherTrustSchema = z.enum(['unknown', 'low', 'medium', 'high']);

export const FindingExpectationSchema = z.enum(['expected', 'unexpected', 'unknown']);

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export const PermissionFindingSchema = z.object({
  id: z.string(),
  permission: PermissionIdSchema,
  level: FindingLevelSchema,
  confidence: ConfidenceSchema,
  evidence: z.string(),
  explanation: z.string(),
  recommendation: z.string().optional(),
  expectation: FindingExpectationSchema.optional(),
});

export const InstallRiskSchema = z.object({
  id: z.string(),
  level: FindingLevelSchema,
  confidence: ConfidenceSchema,
  evidence: z.string(),
  explanation: z.string(),
  recommendation: z.string(),
});

// ---------------------------------------------------------------------------
// Scoring Trace
// ---------------------------------------------------------------------------

export const ScoreAdjustmentSchema = z.object({
  dimension: z.string(),
  reason: z.string(),
  evidence: z.string().optional(),
});

export const ScoringTraceSchema = z.object({
  adjustments: z.array(ScoreAdjustmentSchema),
  explanation: z.string(),
});

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export const PolicyRuleSchema = z.object({
  id: z.string(),
  description: z.string(),
  deny: z
    .object({
      permissions: z.array(PermissionIdSchema).optional(),
      evidenceIncludes: z.array(z.string()).optional(),
    })
    .optional(),
  require: z
    .object({
      install: z
        .object({
          dockerPinned: z.boolean().optional(),
          packagePinned: z.boolean().optional(),
        })
        .optional(),
    })
    .optional(),
  allow: z
    .object({
      domains: z.array(z.string()).optional(),
    })
    .optional(),
});

export const PolicyFileSchema = z.object({
  version: z.string(),
  rules: z.array(PolicyRuleSchema),
});

export const PolicyResultSchema = z.object({
  ruleId: z.string(),
  description: z.string(),
  passed: z.boolean(),
  server: z.string(),
  details: z.string(),
});

// ---------------------------------------------------------------------------
// Safer Config
// ---------------------------------------------------------------------------

export const SaferConfigSuggestionSchema = z.object({
  id: z.string(),
  title: z.string(),
  explanation: z.string(),
  before: z.string().optional(),
  after: z.string().optional(),
  confidence: ConfidenceSchema,
});

// ---------------------------------------------------------------------------
// Server Label
// ---------------------------------------------------------------------------

export const ServerLabelSchema = z.object({
  name: z.string(),
  command: z.string().optional(),
  args: z.array(z.string()),
  packageName: z.string().optional(),
  dockerImage: z.string().optional(),
  envVars: z.array(z.string()),

  // Multi-dimensional scoring
  capabilityImpact: RiskLevelSchema.optional(),
  effectiveRisk: RiskLevelSchema.optional(),
  hardeningGrade: SafetyGradeSchema.optional(),
  publisherTrust: PublisherTrustSchema.optional(),
  installHygiene: SafetyGradeSchema.optional(),
  configHardening: SafetyGradeSchema.optional(),
  analysisConfidence: ConfidenceSchema.optional(),
  knownServerProfile: z.string().optional(),

  permissions: z.array(PermissionFindingSchema),
  installRisks: z.array(InstallRiskSchema),
  policyResults: z.array(PolicyResultSchema).optional(),
  recommendations: z.array(z.string()),
  saferConfigSuggestions: z.array(SaferConfigSuggestionSchema),
  scoringTrace: ScoringTraceSchema.optional(),

  // Legacy
  score: z.number(),
  grade: SafetyGradeSchema,
  risk: RiskLevelSchema,
});

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export const McpLabelReportSchema = z.object({
  schemaVersion: z.union([z.literal('0.1'), z.literal('0.2')]),
  generatedAt: z.string(),
  source: z.object({
    configPaths: z.array(z.string()),
    discovered: z.boolean(),
    staticOnly: z.boolean(),
  }),
  summary: z.object({
    serverCount: z.number(),
    // New multi-dimensional fields (optional for backward compat with 0.1 reports)
    capabilityImpact: RiskLevelSchema.optional(),
    effectiveRisk: RiskLevelSchema.optional(),
    hardeningGrade: SafetyGradeSchema.optional(),
    publisherTrust: PublisherTrustSchema.optional(),
    installHygiene: SafetyGradeSchema.optional(),
    configHardening: SafetyGradeSchema.optional(),
    analysisConfidence: ConfidenceSchema.optional(),
    topMitigations: z.array(z.string()).optional(),
    // Present in both versions
    totalFindings: z.number(),
    topConcerns: z.array(z.string()),
    // Legacy (always present)
    overallGrade: SafetyGradeSchema,
    overallRisk: RiskLevelSchema,
    highestRisk: RiskLevelSchema,
  }),
  servers: z.array(ServerLabelSchema),
});

// ---------------------------------------------------------------------------
// MCP Config Input
// ---------------------------------------------------------------------------

export const McpServerConfigSchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string()).optional(),
    url: z.string().optional(),
    type: z.string().optional(),
    requestInit: z
      .object({
        headers: z.record(z.string()).optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

export const McpConfigFileSchema = z
  .object({
    mcpServers: z.record(McpServerConfigSchema).optional(),
    servers: z.record(McpServerConfigSchema).optional(),
  })
  .passthrough()
  .refine((data) => data.mcpServers || data.servers, {
    message: 'Config must have either "mcpServers" or "servers" key',
  });

