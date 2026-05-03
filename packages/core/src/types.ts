/**
 * Core types for mcp-label.
 *
 * These types define the permission ontology, findings, reports,
 * and all data structures used throughout the project.
 */

// ---------------------------------------------------------------------------
// Permission Ontology
// ---------------------------------------------------------------------------

export const PERMISSION_IDS = [
  'filesystem.read',
  'filesystem.read_possible',
  'filesystem.write',
  'filesystem.delete',
  'shell.execute',
  'code.execution',
  'network.fetch',
  'network.listen',
  'network.egress',
  'browser.control',
  'browser.read_session',
  'browser.session_persistence',
  'repo.read',
  'repo.write',
  'repo.admin',
  'database.query',
  'database.mutate',
  'cloud.read',
  'cloud.write',
  'cloud.admin',
  'email.read',
  'email.send',
  'calendar.read',
  'calendar.write',
  'secrets.env',
  'secrets.files',
  'payments.read',
  'payments.write',
  'payments.charge',
  'payments.charge_possible',
  'payments.receive',
  'payment_protocol.x402',
  'unknown',
] as const;

export type PermissionId = (typeof PERMISSION_IDS)[number];

// ---------------------------------------------------------------------------
// Severity & Confidence
// ---------------------------------------------------------------------------

export type FindingLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type SafetyGrade = 'A' | 'B' | 'C' | 'D' | 'F';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

// ---------------------------------------------------------------------------
// Multi-dimensional Scoring
// ---------------------------------------------------------------------------

export type CapabilityImpact = 'low' | 'medium' | 'high' | 'critical';
export type EffectiveRisk = 'low' | 'medium' | 'high' | 'critical';
export type PublisherTrust = 'unknown' | 'low' | 'medium' | 'high';
export type InstallHygieneGrade = 'A' | 'B' | 'C' | 'D' | 'F';
export type ConfigHardeningGrade = 'A' | 'B' | 'C' | 'D' | 'F';
export type AnalysisConfidence = 'low' | 'medium' | 'high';
export type FindingExpectation = 'expected' | 'unexpected' | 'unknown';

// ---------------------------------------------------------------------------
// Scoring Trace
// ---------------------------------------------------------------------------

export interface ScoreAdjustment {
  dimension: string;
  reason: string;
  evidence?: string;
}

export interface ScoringTrace {
  adjustments: ScoreAdjustment[];
  explanation: string;
}

// ---------------------------------------------------------------------------
// Trust & Hardening Signals
// ---------------------------------------------------------------------------

export interface TrustSignal {
  id: string;
  level: 'positive' | 'neutral' | 'negative';
  confidence: Confidence;
  evidence: string;
  explanation: string;
}

export interface HardeningSignal {
  id: string;
  status: 'present' | 'missing' | 'not_applicable' | 'unknown';
  evidence?: string;
  explanation: string;
  recommendation?: string;
}

// ---------------------------------------------------------------------------
// Findings (extended)
// ---------------------------------------------------------------------------

export interface PermissionFinding {
  id: string;
  permission: PermissionId;
  level: FindingLevel;
  confidence: Confidence;
  evidence: string;
  explanation: string;
  recommendation?: string;
  expectation?: FindingExpectation;
}

export interface InstallRisk {
  id: string;
  level: FindingLevel;
  confidence: Confidence;
  evidence: string;
  explanation: string;
  recommendation: string;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export interface PolicyRule {
  id: string;
  description: string;
  deny?: {
    permissions?: PermissionId[];
    evidenceIncludes?: string[];
  };
  require?: {
    install?: {
      dockerPinned?: boolean;
      packagePinned?: boolean;
    };
  };
  allow?: {
    domains?: string[];
  };
}

export interface PolicyFile {
  version: string;
  rules: PolicyRule[];
}

export interface PolicyResult {
  ruleId: string;
  description: string;
  passed: boolean;
  server: string;
  details: string;
}

// ---------------------------------------------------------------------------
// Safer Config Suggestions
// ---------------------------------------------------------------------------

export interface SaferConfigSuggestion {
  id: string;
  title: string;
  explanation: string;
  before?: string;
  after?: string;
  confidence: Confidence;
}

// ---------------------------------------------------------------------------
// Server Label
// ---------------------------------------------------------------------------

export interface ServerLabel {
  name: string;
  command?: string;
  args: string[];
  packageName?: string;
  dockerImage?: string;
  envVars: string[];

  // Multi-dimensional scoring (present in 0.2 reports)
  capabilityImpact?: CapabilityImpact;
  effectiveRisk?: EffectiveRisk;
  hardeningGrade?: SafetyGrade;
  publisherTrust?: PublisherTrust;
  installHygiene?: SafetyGrade;
  configHardening?: SafetyGrade;
  analysisConfidence?: AnalysisConfidence;
  knownServerProfile?: string;

  permissions: PermissionFinding[];
  installRisks: InstallRisk[];
  policyResults?: PolicyResult[];
  recommendations: string[];
  saferConfigSuggestions: SaferConfigSuggestion[];
  scoringTrace?: ScoringTrace;

  // Legacy (backward compatible)
  score: number;
  grade: SafetyGrade;
  risk: RiskLevel;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export interface McpLabelReport {
  schemaVersion: '0.1' | '0.2';
  generatedAt: string;
  source: {
    configPaths: string[];
    discovered: boolean;
    staticOnly: boolean;
  };
  summary: {
    serverCount: number;
    capabilityImpact?: CapabilityImpact;
    effectiveRisk?: EffectiveRisk;
    hardeningGrade?: SafetyGrade;
    publisherTrust?: PublisherTrust;
    installHygiene?: SafetyGrade;
    configHardening?: SafetyGrade;
    analysisConfidence?: AnalysisConfidence;
    totalFindings: number;
    topConcerns: string[];
    topMitigations?: string[];
    // Legacy (backward compatible)
    overallGrade: SafetyGrade;
    overallRisk: RiskLevel;
    highestRisk: RiskLevel;
  };
  servers: ServerLabel[];
}

// ---------------------------------------------------------------------------
// MCP Config (input)
// ---------------------------------------------------------------------------

export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
  requestInit?: {
    headers?: Record<string, string>;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface McpConfigFile {
  mcpServers: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Runtime Inspection (future)
// ---------------------------------------------------------------------------

export interface RuntimeTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface RuntimeResource {
  uri: string;
  name?: string;
  mimeType?: string;
}

export interface RuntimePrompt {
  name: string;
  description?: string;
}

export interface McpRuntimeSnapshot {
  schemaVersion: '0.1';
  generatedAt: string;
  server: string;
  tools: RuntimeTool[];
  resources: RuntimeResource[];
  prompts: RuntimePrompt[];
  capabilities: Record<string, unknown>;
  hashes: {
    toolsHash: string;
    resourcesHash: string;
    promptsHash: string;
  };
}

