import { z } from 'zod';

/**
 * Core types for mcp-label.
 *
 * These types define the permission ontology, findings, reports,
 * and all data structures used throughout the project.
 */
declare const PERMISSION_IDS: readonly ["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"];
type PermissionId = (typeof PERMISSION_IDS)[number];
type FindingLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';
type Confidence = 'low' | 'medium' | 'high';
type SafetyGrade = 'A' | 'B' | 'C' | 'D' | 'F';
type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
type CapabilityImpact = 'low' | 'medium' | 'high' | 'critical';
type EffectiveRisk = 'low' | 'medium' | 'high' | 'critical';
type PublisherTrust$1 = 'unknown' | 'low' | 'medium' | 'high';
type InstallHygieneGrade = 'A' | 'B' | 'C' | 'D' | 'F';
type ConfigHardeningGrade = 'A' | 'B' | 'C' | 'D' | 'F';
type AnalysisConfidence = 'low' | 'medium' | 'high';
type FindingExpectation = 'expected' | 'unexpected' | 'unknown';
interface ScoreAdjustment {
    dimension: string;
    reason: string;
    evidence?: string;
}
interface ScoringTrace {
    adjustments: ScoreAdjustment[];
    explanation: string;
}
interface TrustSignal {
    id: string;
    level: 'positive' | 'neutral' | 'negative';
    confidence: Confidence;
    evidence: string;
    explanation: string;
}
interface HardeningSignal {
    id: string;
    status: 'present' | 'missing' | 'not_applicable' | 'unknown';
    evidence?: string;
    explanation: string;
    recommendation?: string;
}
interface PermissionFinding {
    id: string;
    permission: PermissionId;
    level: FindingLevel;
    confidence: Confidence;
    evidence: string;
    explanation: string;
    recommendation?: string;
    expectation?: FindingExpectation;
}
interface InstallRisk {
    id: string;
    level: FindingLevel;
    confidence: Confidence;
    evidence: string;
    explanation: string;
    recommendation: string;
}
interface PolicyRule {
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
interface PolicyFile {
    version: string;
    rules: PolicyRule[];
}
interface PolicyResult {
    ruleId: string;
    description: string;
    passed: boolean;
    server: string;
    details: string;
}
interface SaferConfigSuggestion {
    id: string;
    title: string;
    explanation: string;
    before?: string;
    after?: string;
    confidence: Confidence;
}
interface ServerLabel {
    name: string;
    command?: string;
    args: string[];
    packageName?: string;
    dockerImage?: string;
    envVars: string[];
    capabilityImpact?: CapabilityImpact;
    effectiveRisk?: EffectiveRisk;
    hardeningGrade?: SafetyGrade;
    publisherTrust?: PublisherTrust$1;
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
    score: number;
    grade: SafetyGrade;
    risk: RiskLevel;
}
interface McpLabelReport {
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
        publisherTrust?: PublisherTrust$1;
        installHygiene?: SafetyGrade;
        configHardening?: SafetyGrade;
        analysisConfidence?: AnalysisConfidence;
        totalFindings: number;
        topConcerns: string[];
        topMitigations?: string[];
        overallGrade: SafetyGrade;
        overallRisk: RiskLevel;
        highestRisk: RiskLevel;
    };
    servers: ServerLabel[];
}
interface McpServerConfig {
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
interface McpConfigFile {
    mcpServers: Record<string, McpServerConfig>;
    [key: string]: unknown;
}
interface RuntimeTool {
    name: string;
    description?: string;
    inputSchema?: Record<string, unknown>;
}
interface RuntimeResource {
    uri: string;
    name?: string;
    mimeType?: string;
}
interface RuntimePrompt {
    name: string;
    description?: string;
}
interface McpRuntimeSnapshot {
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

/**
 * Zod schemas for mcp-label data structures.
 * Used for validation and JSON Schema generation.
 */

declare const PermissionIdSchema: z.ZodEnum<["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"]>;
declare const FindingLevelSchema: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
declare const ConfidenceSchema: z.ZodEnum<["low", "medium", "high"]>;
declare const SafetyGradeSchema: z.ZodEnum<["A", "B", "C", "D", "F"]>;
declare const RiskLevelSchema: z.ZodEnum<["low", "medium", "high", "critical"]>;
declare const PublisherTrustSchema: z.ZodEnum<["unknown", "low", "medium", "high"]>;
declare const FindingExpectationSchema: z.ZodEnum<["expected", "unexpected", "unknown"]>;
declare const PermissionFindingSchema: z.ZodObject<{
    id: z.ZodString;
    permission: z.ZodEnum<["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"]>;
    level: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
    confidence: z.ZodEnum<["low", "medium", "high"]>;
    evidence: z.ZodString;
    explanation: z.ZodString;
    recommendation: z.ZodOptional<z.ZodString>;
    expectation: z.ZodOptional<z.ZodEnum<["expected", "unexpected", "unknown"]>>;
}, "strip", z.ZodTypeAny, {
    id: string;
    permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
    level: "low" | "medium" | "high" | "critical" | "info";
    confidence: "low" | "medium" | "high";
    evidence: string;
    explanation: string;
    recommendation?: string | undefined;
    expectation?: "unknown" | "expected" | "unexpected" | undefined;
}, {
    id: string;
    permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
    level: "low" | "medium" | "high" | "critical" | "info";
    confidence: "low" | "medium" | "high";
    evidence: string;
    explanation: string;
    recommendation?: string | undefined;
    expectation?: "unknown" | "expected" | "unexpected" | undefined;
}>;
declare const InstallRiskSchema: z.ZodObject<{
    id: z.ZodString;
    level: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
    confidence: z.ZodEnum<["low", "medium", "high"]>;
    evidence: z.ZodString;
    explanation: z.ZodString;
    recommendation: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
    level: "low" | "medium" | "high" | "critical" | "info";
    confidence: "low" | "medium" | "high";
    evidence: string;
    explanation: string;
    recommendation: string;
}, {
    id: string;
    level: "low" | "medium" | "high" | "critical" | "info";
    confidence: "low" | "medium" | "high";
    evidence: string;
    explanation: string;
    recommendation: string;
}>;
declare const ScoreAdjustmentSchema: z.ZodObject<{
    dimension: z.ZodString;
    reason: z.ZodString;
    evidence: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    dimension: string;
    reason: string;
    evidence?: string | undefined;
}, {
    dimension: string;
    reason: string;
    evidence?: string | undefined;
}>;
declare const ScoringTraceSchema: z.ZodObject<{
    adjustments: z.ZodArray<z.ZodObject<{
        dimension: z.ZodString;
        reason: z.ZodString;
        evidence: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        dimension: string;
        reason: string;
        evidence?: string | undefined;
    }, {
        dimension: string;
        reason: string;
        evidence?: string | undefined;
    }>, "many">;
    explanation: z.ZodString;
}, "strip", z.ZodTypeAny, {
    explanation: string;
    adjustments: {
        dimension: string;
        reason: string;
        evidence?: string | undefined;
    }[];
}, {
    explanation: string;
    adjustments: {
        dimension: string;
        reason: string;
        evidence?: string | undefined;
    }[];
}>;
declare const PolicyRuleSchema: z.ZodObject<{
    id: z.ZodString;
    description: z.ZodString;
    deny: z.ZodOptional<z.ZodObject<{
        permissions: z.ZodOptional<z.ZodArray<z.ZodEnum<["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"]>, "many">>;
        evidenceIncludes: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
        evidenceIncludes?: string[] | undefined;
    }, {
        permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
        evidenceIncludes?: string[] | undefined;
    }>>;
    require: z.ZodOptional<z.ZodObject<{
        install: z.ZodOptional<z.ZodObject<{
            dockerPinned: z.ZodOptional<z.ZodBoolean>;
            packagePinned: z.ZodOptional<z.ZodBoolean>;
        }, "strip", z.ZodTypeAny, {
            dockerPinned?: boolean | undefined;
            packagePinned?: boolean | undefined;
        }, {
            dockerPinned?: boolean | undefined;
            packagePinned?: boolean | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        install?: {
            dockerPinned?: boolean | undefined;
            packagePinned?: boolean | undefined;
        } | undefined;
    }, {
        install?: {
            dockerPinned?: boolean | undefined;
            packagePinned?: boolean | undefined;
        } | undefined;
    }>>;
    allow: z.ZodOptional<z.ZodObject<{
        domains: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        domains?: string[] | undefined;
    }, {
        domains?: string[] | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    id: string;
    description: string;
    deny?: {
        permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
        evidenceIncludes?: string[] | undefined;
    } | undefined;
    require?: {
        install?: {
            dockerPinned?: boolean | undefined;
            packagePinned?: boolean | undefined;
        } | undefined;
    } | undefined;
    allow?: {
        domains?: string[] | undefined;
    } | undefined;
}, {
    id: string;
    description: string;
    deny?: {
        permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
        evidenceIncludes?: string[] | undefined;
    } | undefined;
    require?: {
        install?: {
            dockerPinned?: boolean | undefined;
            packagePinned?: boolean | undefined;
        } | undefined;
    } | undefined;
    allow?: {
        domains?: string[] | undefined;
    } | undefined;
}>;
declare const PolicyFileSchema: z.ZodObject<{
    version: z.ZodString;
    rules: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        description: z.ZodString;
        deny: z.ZodOptional<z.ZodObject<{
            permissions: z.ZodOptional<z.ZodArray<z.ZodEnum<["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"]>, "many">>;
            evidenceIncludes: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        }, "strip", z.ZodTypeAny, {
            permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
            evidenceIncludes?: string[] | undefined;
        }, {
            permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
            evidenceIncludes?: string[] | undefined;
        }>>;
        require: z.ZodOptional<z.ZodObject<{
            install: z.ZodOptional<z.ZodObject<{
                dockerPinned: z.ZodOptional<z.ZodBoolean>;
                packagePinned: z.ZodOptional<z.ZodBoolean>;
            }, "strip", z.ZodTypeAny, {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            }, {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            }>>;
        }, "strip", z.ZodTypeAny, {
            install?: {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            } | undefined;
        }, {
            install?: {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            } | undefined;
        }>>;
        allow: z.ZodOptional<z.ZodObject<{
            domains: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        }, "strip", z.ZodTypeAny, {
            domains?: string[] | undefined;
        }, {
            domains?: string[] | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        id: string;
        description: string;
        deny?: {
            permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
            evidenceIncludes?: string[] | undefined;
        } | undefined;
        require?: {
            install?: {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            } | undefined;
        } | undefined;
        allow?: {
            domains?: string[] | undefined;
        } | undefined;
    }, {
        id: string;
        description: string;
        deny?: {
            permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
            evidenceIncludes?: string[] | undefined;
        } | undefined;
        require?: {
            install?: {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            } | undefined;
        } | undefined;
        allow?: {
            domains?: string[] | undefined;
        } | undefined;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    version: string;
    rules: {
        id: string;
        description: string;
        deny?: {
            permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
            evidenceIncludes?: string[] | undefined;
        } | undefined;
        require?: {
            install?: {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            } | undefined;
        } | undefined;
        allow?: {
            domains?: string[] | undefined;
        } | undefined;
    }[];
}, {
    version: string;
    rules: {
        id: string;
        description: string;
        deny?: {
            permissions?: ("filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown")[] | undefined;
            evidenceIncludes?: string[] | undefined;
        } | undefined;
        require?: {
            install?: {
                dockerPinned?: boolean | undefined;
                packagePinned?: boolean | undefined;
            } | undefined;
        } | undefined;
        allow?: {
            domains?: string[] | undefined;
        } | undefined;
    }[];
}>;
declare const PolicyResultSchema: z.ZodObject<{
    ruleId: z.ZodString;
    description: z.ZodString;
    passed: z.ZodBoolean;
    server: z.ZodString;
    details: z.ZodString;
}, "strip", z.ZodTypeAny, {
    description: string;
    ruleId: string;
    passed: boolean;
    server: string;
    details: string;
}, {
    description: string;
    ruleId: string;
    passed: boolean;
    server: string;
    details: string;
}>;
declare const SaferConfigSuggestionSchema: z.ZodObject<{
    id: z.ZodString;
    title: z.ZodString;
    explanation: z.ZodString;
    before: z.ZodOptional<z.ZodString>;
    after: z.ZodOptional<z.ZodString>;
    confidence: z.ZodEnum<["low", "medium", "high"]>;
}, "strip", z.ZodTypeAny, {
    id: string;
    confidence: "low" | "medium" | "high";
    explanation: string;
    title: string;
    before?: string | undefined;
    after?: string | undefined;
}, {
    id: string;
    confidence: "low" | "medium" | "high";
    explanation: string;
    title: string;
    before?: string | undefined;
    after?: string | undefined;
}>;
declare const ServerLabelSchema: z.ZodObject<{
    name: z.ZodString;
    command: z.ZodOptional<z.ZodString>;
    args: z.ZodArray<z.ZodString, "many">;
    packageName: z.ZodOptional<z.ZodString>;
    dockerImage: z.ZodOptional<z.ZodString>;
    envVars: z.ZodArray<z.ZodString, "many">;
    capabilityImpact: z.ZodOptional<z.ZodEnum<["low", "medium", "high", "critical"]>>;
    effectiveRisk: z.ZodOptional<z.ZodEnum<["low", "medium", "high", "critical"]>>;
    hardeningGrade: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
    publisherTrust: z.ZodOptional<z.ZodEnum<["unknown", "low", "medium", "high"]>>;
    installHygiene: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
    configHardening: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
    analysisConfidence: z.ZodOptional<z.ZodEnum<["low", "medium", "high"]>>;
    knownServerProfile: z.ZodOptional<z.ZodString>;
    permissions: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        permission: z.ZodEnum<["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"]>;
        level: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
        confidence: z.ZodEnum<["low", "medium", "high"]>;
        evidence: z.ZodString;
        explanation: z.ZodString;
        recommendation: z.ZodOptional<z.ZodString>;
        expectation: z.ZodOptional<z.ZodEnum<["expected", "unexpected", "unknown"]>>;
    }, "strip", z.ZodTypeAny, {
        id: string;
        permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation?: string | undefined;
        expectation?: "unknown" | "expected" | "unexpected" | undefined;
    }, {
        id: string;
        permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation?: string | undefined;
        expectation?: "unknown" | "expected" | "unexpected" | undefined;
    }>, "many">;
    installRisks: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        level: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
        confidence: z.ZodEnum<["low", "medium", "high"]>;
        evidence: z.ZodString;
        explanation: z.ZodString;
        recommendation: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        id: string;
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation: string;
    }, {
        id: string;
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation: string;
    }>, "many">;
    policyResults: z.ZodOptional<z.ZodArray<z.ZodObject<{
        ruleId: z.ZodString;
        description: z.ZodString;
        passed: z.ZodBoolean;
        server: z.ZodString;
        details: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        description: string;
        ruleId: string;
        passed: boolean;
        server: string;
        details: string;
    }, {
        description: string;
        ruleId: string;
        passed: boolean;
        server: string;
        details: string;
    }>, "many">>;
    recommendations: z.ZodArray<z.ZodString, "many">;
    saferConfigSuggestions: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        title: z.ZodString;
        explanation: z.ZodString;
        before: z.ZodOptional<z.ZodString>;
        after: z.ZodOptional<z.ZodString>;
        confidence: z.ZodEnum<["low", "medium", "high"]>;
    }, "strip", z.ZodTypeAny, {
        id: string;
        confidence: "low" | "medium" | "high";
        explanation: string;
        title: string;
        before?: string | undefined;
        after?: string | undefined;
    }, {
        id: string;
        confidence: "low" | "medium" | "high";
        explanation: string;
        title: string;
        before?: string | undefined;
        after?: string | undefined;
    }>, "many">;
    scoringTrace: z.ZodOptional<z.ZodObject<{
        adjustments: z.ZodArray<z.ZodObject<{
            dimension: z.ZodString;
            reason: z.ZodString;
            evidence: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            dimension: string;
            reason: string;
            evidence?: string | undefined;
        }, {
            dimension: string;
            reason: string;
            evidence?: string | undefined;
        }>, "many">;
        explanation: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        explanation: string;
        adjustments: {
            dimension: string;
            reason: string;
            evidence?: string | undefined;
        }[];
    }, {
        explanation: string;
        adjustments: {
            dimension: string;
            reason: string;
            evidence?: string | undefined;
        }[];
    }>>;
    score: z.ZodNumber;
    grade: z.ZodEnum<["A", "B", "C", "D", "F"]>;
    risk: z.ZodEnum<["low", "medium", "high", "critical"]>;
}, "strip", z.ZodTypeAny, {
    name: string;
    permissions: {
        id: string;
        permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation?: string | undefined;
        expectation?: "unknown" | "expected" | "unexpected" | undefined;
    }[];
    installRisks: {
        id: string;
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation: string;
    }[];
    recommendations: string[];
    saferConfigSuggestions: {
        id: string;
        confidence: "low" | "medium" | "high";
        explanation: string;
        title: string;
        before?: string | undefined;
        after?: string | undefined;
    }[];
    args: string[];
    envVars: string[];
    score: number;
    grade: "A" | "B" | "C" | "D" | "F";
    risk: "low" | "medium" | "high" | "critical";
    packageName?: string | undefined;
    dockerImage?: string | undefined;
    command?: string | undefined;
    capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
    effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
    hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
    publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
    installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
    configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
    analysisConfidence?: "low" | "medium" | "high" | undefined;
    knownServerProfile?: string | undefined;
    policyResults?: {
        description: string;
        ruleId: string;
        passed: boolean;
        server: string;
        details: string;
    }[] | undefined;
    scoringTrace?: {
        explanation: string;
        adjustments: {
            dimension: string;
            reason: string;
            evidence?: string | undefined;
        }[];
    } | undefined;
}, {
    name: string;
    permissions: {
        id: string;
        permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation?: string | undefined;
        expectation?: "unknown" | "expected" | "unexpected" | undefined;
    }[];
    installRisks: {
        id: string;
        level: "low" | "medium" | "high" | "critical" | "info";
        confidence: "low" | "medium" | "high";
        evidence: string;
        explanation: string;
        recommendation: string;
    }[];
    recommendations: string[];
    saferConfigSuggestions: {
        id: string;
        confidence: "low" | "medium" | "high";
        explanation: string;
        title: string;
        before?: string | undefined;
        after?: string | undefined;
    }[];
    args: string[];
    envVars: string[];
    score: number;
    grade: "A" | "B" | "C" | "D" | "F";
    risk: "low" | "medium" | "high" | "critical";
    packageName?: string | undefined;
    dockerImage?: string | undefined;
    command?: string | undefined;
    capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
    effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
    hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
    publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
    installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
    configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
    analysisConfidence?: "low" | "medium" | "high" | undefined;
    knownServerProfile?: string | undefined;
    policyResults?: {
        description: string;
        ruleId: string;
        passed: boolean;
        server: string;
        details: string;
    }[] | undefined;
    scoringTrace?: {
        explanation: string;
        adjustments: {
            dimension: string;
            reason: string;
            evidence?: string | undefined;
        }[];
    } | undefined;
}>;
declare const McpLabelReportSchema: z.ZodObject<{
    schemaVersion: z.ZodUnion<[z.ZodLiteral<"0.1">, z.ZodLiteral<"0.2">]>;
    generatedAt: z.ZodString;
    source: z.ZodObject<{
        configPaths: z.ZodArray<z.ZodString, "many">;
        discovered: z.ZodBoolean;
        staticOnly: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        configPaths: string[];
        discovered: boolean;
        staticOnly: boolean;
    }, {
        configPaths: string[];
        discovered: boolean;
        staticOnly: boolean;
    }>;
    summary: z.ZodObject<{
        serverCount: z.ZodNumber;
        capabilityImpact: z.ZodOptional<z.ZodEnum<["low", "medium", "high", "critical"]>>;
        effectiveRisk: z.ZodOptional<z.ZodEnum<["low", "medium", "high", "critical"]>>;
        hardeningGrade: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
        publisherTrust: z.ZodOptional<z.ZodEnum<["unknown", "low", "medium", "high"]>>;
        installHygiene: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
        configHardening: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
        analysisConfidence: z.ZodOptional<z.ZodEnum<["low", "medium", "high"]>>;
        topMitigations: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        totalFindings: z.ZodNumber;
        topConcerns: z.ZodArray<z.ZodString, "many">;
        overallGrade: z.ZodEnum<["A", "B", "C", "D", "F"]>;
        overallRisk: z.ZodEnum<["low", "medium", "high", "critical"]>;
        highestRisk: z.ZodEnum<["low", "medium", "high", "critical"]>;
    }, "strip", z.ZodTypeAny, {
        serverCount: number;
        totalFindings: number;
        topConcerns: string[];
        overallGrade: "A" | "B" | "C" | "D" | "F";
        overallRisk: "low" | "medium" | "high" | "critical";
        highestRisk: "low" | "medium" | "high" | "critical";
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        topMitigations?: string[] | undefined;
    }, {
        serverCount: number;
        totalFindings: number;
        topConcerns: string[];
        overallGrade: "A" | "B" | "C" | "D" | "F";
        overallRisk: "low" | "medium" | "high" | "critical";
        highestRisk: "low" | "medium" | "high" | "critical";
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        topMitigations?: string[] | undefined;
    }>;
    servers: z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodArray<z.ZodString, "many">;
        packageName: z.ZodOptional<z.ZodString>;
        dockerImage: z.ZodOptional<z.ZodString>;
        envVars: z.ZodArray<z.ZodString, "many">;
        capabilityImpact: z.ZodOptional<z.ZodEnum<["low", "medium", "high", "critical"]>>;
        effectiveRisk: z.ZodOptional<z.ZodEnum<["low", "medium", "high", "critical"]>>;
        hardeningGrade: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
        publisherTrust: z.ZodOptional<z.ZodEnum<["unknown", "low", "medium", "high"]>>;
        installHygiene: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
        configHardening: z.ZodOptional<z.ZodEnum<["A", "B", "C", "D", "F"]>>;
        analysisConfidence: z.ZodOptional<z.ZodEnum<["low", "medium", "high"]>>;
        knownServerProfile: z.ZodOptional<z.ZodString>;
        permissions: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            permission: z.ZodEnum<["filesystem.read", "filesystem.read_possible", "filesystem.write", "filesystem.delete", "shell.execute", "code.execution", "network.fetch", "network.listen", "network.egress", "browser.control", "browser.read_session", "browser.session_persistence", "repo.read", "repo.write", "repo.admin", "database.query", "database.mutate", "cloud.read", "cloud.write", "cloud.admin", "email.read", "email.send", "calendar.read", "calendar.write", "secrets.env", "secrets.files", "payments.read", "payments.write", "payments.charge", "payments.charge_possible", "payments.receive", "payment_protocol.x402", "unknown"]>;
            level: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
            confidence: z.ZodEnum<["low", "medium", "high"]>;
            evidence: z.ZodString;
            explanation: z.ZodString;
            recommendation: z.ZodOptional<z.ZodString>;
            expectation: z.ZodOptional<z.ZodEnum<["expected", "unexpected", "unknown"]>>;
        }, "strip", z.ZodTypeAny, {
            id: string;
            permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation?: string | undefined;
            expectation?: "unknown" | "expected" | "unexpected" | undefined;
        }, {
            id: string;
            permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation?: string | undefined;
            expectation?: "unknown" | "expected" | "unexpected" | undefined;
        }>, "many">;
        installRisks: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            level: z.ZodEnum<["info", "low", "medium", "high", "critical"]>;
            confidence: z.ZodEnum<["low", "medium", "high"]>;
            evidence: z.ZodString;
            explanation: z.ZodString;
            recommendation: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            id: string;
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation: string;
        }, {
            id: string;
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation: string;
        }>, "many">;
        policyResults: z.ZodOptional<z.ZodArray<z.ZodObject<{
            ruleId: z.ZodString;
            description: z.ZodString;
            passed: z.ZodBoolean;
            server: z.ZodString;
            details: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            description: string;
            ruleId: string;
            passed: boolean;
            server: string;
            details: string;
        }, {
            description: string;
            ruleId: string;
            passed: boolean;
            server: string;
            details: string;
        }>, "many">>;
        recommendations: z.ZodArray<z.ZodString, "many">;
        saferConfigSuggestions: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            title: z.ZodString;
            explanation: z.ZodString;
            before: z.ZodOptional<z.ZodString>;
            after: z.ZodOptional<z.ZodString>;
            confidence: z.ZodEnum<["low", "medium", "high"]>;
        }, "strip", z.ZodTypeAny, {
            id: string;
            confidence: "low" | "medium" | "high";
            explanation: string;
            title: string;
            before?: string | undefined;
            after?: string | undefined;
        }, {
            id: string;
            confidence: "low" | "medium" | "high";
            explanation: string;
            title: string;
            before?: string | undefined;
            after?: string | undefined;
        }>, "many">;
        scoringTrace: z.ZodOptional<z.ZodObject<{
            adjustments: z.ZodArray<z.ZodObject<{
                dimension: z.ZodString;
                reason: z.ZodString;
                evidence: z.ZodOptional<z.ZodString>;
            }, "strip", z.ZodTypeAny, {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }, {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }>, "many">;
            explanation: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            explanation: string;
            adjustments: {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }[];
        }, {
            explanation: string;
            adjustments: {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }[];
        }>>;
        score: z.ZodNumber;
        grade: z.ZodEnum<["A", "B", "C", "D", "F"]>;
        risk: z.ZodEnum<["low", "medium", "high", "critical"]>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        permissions: {
            id: string;
            permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation?: string | undefined;
            expectation?: "unknown" | "expected" | "unexpected" | undefined;
        }[];
        installRisks: {
            id: string;
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation: string;
        }[];
        recommendations: string[];
        saferConfigSuggestions: {
            id: string;
            confidence: "low" | "medium" | "high";
            explanation: string;
            title: string;
            before?: string | undefined;
            after?: string | undefined;
        }[];
        args: string[];
        envVars: string[];
        score: number;
        grade: "A" | "B" | "C" | "D" | "F";
        risk: "low" | "medium" | "high" | "critical";
        packageName?: string | undefined;
        dockerImage?: string | undefined;
        command?: string | undefined;
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        knownServerProfile?: string | undefined;
        policyResults?: {
            description: string;
            ruleId: string;
            passed: boolean;
            server: string;
            details: string;
        }[] | undefined;
        scoringTrace?: {
            explanation: string;
            adjustments: {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }[];
        } | undefined;
    }, {
        name: string;
        permissions: {
            id: string;
            permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation?: string | undefined;
            expectation?: "unknown" | "expected" | "unexpected" | undefined;
        }[];
        installRisks: {
            id: string;
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation: string;
        }[];
        recommendations: string[];
        saferConfigSuggestions: {
            id: string;
            confidence: "low" | "medium" | "high";
            explanation: string;
            title: string;
            before?: string | undefined;
            after?: string | undefined;
        }[];
        args: string[];
        envVars: string[];
        score: number;
        grade: "A" | "B" | "C" | "D" | "F";
        risk: "low" | "medium" | "high" | "critical";
        packageName?: string | undefined;
        dockerImage?: string | undefined;
        command?: string | undefined;
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        knownServerProfile?: string | undefined;
        policyResults?: {
            description: string;
            ruleId: string;
            passed: boolean;
            server: string;
            details: string;
        }[] | undefined;
        scoringTrace?: {
            explanation: string;
            adjustments: {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }[];
        } | undefined;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    schemaVersion: "0.2" | "0.1";
    generatedAt: string;
    source: {
        configPaths: string[];
        discovered: boolean;
        staticOnly: boolean;
    };
    summary: {
        serverCount: number;
        totalFindings: number;
        topConcerns: string[];
        overallGrade: "A" | "B" | "C" | "D" | "F";
        overallRisk: "low" | "medium" | "high" | "critical";
        highestRisk: "low" | "medium" | "high" | "critical";
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        topMitigations?: string[] | undefined;
    };
    servers: {
        name: string;
        permissions: {
            id: string;
            permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation?: string | undefined;
            expectation?: "unknown" | "expected" | "unexpected" | undefined;
        }[];
        installRisks: {
            id: string;
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation: string;
        }[];
        recommendations: string[];
        saferConfigSuggestions: {
            id: string;
            confidence: "low" | "medium" | "high";
            explanation: string;
            title: string;
            before?: string | undefined;
            after?: string | undefined;
        }[];
        args: string[];
        envVars: string[];
        score: number;
        grade: "A" | "B" | "C" | "D" | "F";
        risk: "low" | "medium" | "high" | "critical";
        packageName?: string | undefined;
        dockerImage?: string | undefined;
        command?: string | undefined;
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        knownServerProfile?: string | undefined;
        policyResults?: {
            description: string;
            ruleId: string;
            passed: boolean;
            server: string;
            details: string;
        }[] | undefined;
        scoringTrace?: {
            explanation: string;
            adjustments: {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }[];
        } | undefined;
    }[];
}, {
    schemaVersion: "0.2" | "0.1";
    generatedAt: string;
    source: {
        configPaths: string[];
        discovered: boolean;
        staticOnly: boolean;
    };
    summary: {
        serverCount: number;
        totalFindings: number;
        topConcerns: string[];
        overallGrade: "A" | "B" | "C" | "D" | "F";
        overallRisk: "low" | "medium" | "high" | "critical";
        highestRisk: "low" | "medium" | "high" | "critical";
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        topMitigations?: string[] | undefined;
    };
    servers: {
        name: string;
        permissions: {
            id: string;
            permission: "filesystem.read" | "filesystem.read_possible" | "filesystem.write" | "filesystem.delete" | "shell.execute" | "code.execution" | "network.fetch" | "network.listen" | "network.egress" | "browser.control" | "browser.read_session" | "browser.session_persistence" | "repo.read" | "repo.write" | "repo.admin" | "database.query" | "database.mutate" | "cloud.read" | "cloud.write" | "cloud.admin" | "email.read" | "email.send" | "calendar.read" | "calendar.write" | "secrets.env" | "secrets.files" | "payments.read" | "payments.write" | "payments.charge" | "payments.charge_possible" | "payments.receive" | "payment_protocol.x402" | "unknown";
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation?: string | undefined;
            expectation?: "unknown" | "expected" | "unexpected" | undefined;
        }[];
        installRisks: {
            id: string;
            level: "low" | "medium" | "high" | "critical" | "info";
            confidence: "low" | "medium" | "high";
            evidence: string;
            explanation: string;
            recommendation: string;
        }[];
        recommendations: string[];
        saferConfigSuggestions: {
            id: string;
            confidence: "low" | "medium" | "high";
            explanation: string;
            title: string;
            before?: string | undefined;
            after?: string | undefined;
        }[];
        args: string[];
        envVars: string[];
        score: number;
        grade: "A" | "B" | "C" | "D" | "F";
        risk: "low" | "medium" | "high" | "critical";
        packageName?: string | undefined;
        dockerImage?: string | undefined;
        command?: string | undefined;
        capabilityImpact?: "low" | "medium" | "high" | "critical" | undefined;
        effectiveRisk?: "low" | "medium" | "high" | "critical" | undefined;
        hardeningGrade?: "A" | "B" | "C" | "D" | "F" | undefined;
        publisherTrust?: "unknown" | "low" | "medium" | "high" | undefined;
        installHygiene?: "A" | "B" | "C" | "D" | "F" | undefined;
        configHardening?: "A" | "B" | "C" | "D" | "F" | undefined;
        analysisConfidence?: "low" | "medium" | "high" | undefined;
        knownServerProfile?: string | undefined;
        policyResults?: {
            description: string;
            ruleId: string;
            passed: boolean;
            server: string;
            details: string;
        }[] | undefined;
        scoringTrace?: {
            explanation: string;
            adjustments: {
                dimension: string;
                reason: string;
                evidence?: string | undefined;
            }[];
        } | undefined;
    }[];
}>;
declare const McpServerConfigSchema: z.ZodObject<{
    command: z.ZodOptional<z.ZodString>;
    args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    url: z.ZodOptional<z.ZodString>;
    type: z.ZodOptional<z.ZodString>;
    requestInit: z.ZodOptional<z.ZodObject<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, z.ZodTypeAny, "passthrough">>>;
}, "passthrough", z.ZodTypeAny, z.objectOutputType<{
    command: z.ZodOptional<z.ZodString>;
    args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    url: z.ZodOptional<z.ZodString>;
    type: z.ZodOptional<z.ZodString>;
    requestInit: z.ZodOptional<z.ZodObject<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, z.ZodTypeAny, "passthrough">>>;
}, z.ZodTypeAny, "passthrough">, z.objectInputType<{
    command: z.ZodOptional<z.ZodString>;
    args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    url: z.ZodOptional<z.ZodString>;
    type: z.ZodOptional<z.ZodString>;
    requestInit: z.ZodOptional<z.ZodObject<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
    }, z.ZodTypeAny, "passthrough">>>;
}, z.ZodTypeAny, "passthrough">>;
declare const McpConfigFileSchema: z.ZodEffects<z.ZodObject<{
    mcpServers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
    servers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
}, "passthrough", z.ZodTypeAny, z.objectOutputType<{
    mcpServers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
    servers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
}, z.ZodTypeAny, "passthrough">, z.objectInputType<{
    mcpServers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
    servers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
}, z.ZodTypeAny, "passthrough">>, z.objectOutputType<{
    mcpServers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
    servers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
}, z.ZodTypeAny, "passthrough">, z.objectInputType<{
    mcpServers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
    servers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        command: z.ZodOptional<z.ZodString>;
        args: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        env: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        url: z.ZodOptional<z.ZodString>;
        type: z.ZodOptional<z.ZodString>;
        requestInit: z.ZodOptional<z.ZodObject<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
}, z.ZodTypeAny, "passthrough">>;

/**
 * MCP config file parsing and auto-discovery.
 */

/**
 * Parse an MCP config file from a path.
 * Supports both `mcpServers` (Claude/Cursor) and `servers` (GitHub Copilot/IntelliJ) keys.
 * Throws on invalid JSON or schema mismatch.
 */
declare function parseConfigFile(filePath: string): McpConfigFile;
/**
 * Redact secret values from an env record.
 * Returns only the env variable names.
 */
declare function redactEnvValues(env: Record<string, string> | undefined): string[];
/**
 * Returns a list of well-known MCP config paths for the current platform.
 */
declare function getDiscoveryPaths(): string[];
/**
 * Discover MCP config files from well-known locations.
 * Returns only paths that exist and parse successfully.
 */
declare function discoverConfigFiles(): {
    path: string;
    config: McpConfigFile;
}[];
/**
 * Merge multiple MCP configs into one.
 * Later configs override earlier ones for the same server name.
 */
declare function mergeConfigs(configs: McpConfigFile[]): McpConfigFile;

/**
 * Static analysis engine for MCP server configurations.
 *
 * Analyzes server name, command, args, env var names, Docker flags,
 * package names, paths, and service identifiers to infer permissions
 * and install risks.
 *
 * SAFETY: This module never executes configured commands.
 * SAFETY: This module never reads or logs secret values.
 */

declare function analyzeServer(name: string, config: McpServerConfig): {
    permissions: PermissionFinding[];
    installRisks: InstallRisk[];
    recommendations: string[];
    saferConfigSuggestions: SaferConfigSuggestion[];
    packageName?: string;
    dockerImage?: string;
};

/**
 * Known server profiles for mcp-label.
 *
 * These profiles encode publisher trust, expected capabilities,
 * and recommended hardening controls for well-known MCP servers.
 *
 * Expected capabilities are not treated as suspicious — they are
 * part of the server's intended function.
 */

type PublisherTrust = 'unknown' | 'low' | 'medium' | 'high';
interface KnownServerProfile {
    id: string;
    displayName: string;
    match: {
        packageNames?: string[];
        repos?: string[];
        dockerImages?: string[];
        commands?: string[];
    };
    publisher: {
        name: string;
        trust: PublisherTrust;
        evidence: string;
    };
    expectedCapabilities: PermissionId[];
    recommendedControls: string[];
}
declare const KNOWN_SERVER_PROFILES: KnownServerProfile[];
/**
 * Find a known server profile that matches the given config.
 * Returns null if no known profile matches.
 */
declare function findKnownProfile(name: string, config: McpServerConfig): KnownServerProfile | null;

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

declare function computeCapabilityImpact(permissions: PermissionFinding[]): CapabilityImpact;
declare function computeInstallHygiene(installRisks: InstallRisk[]): SafetyGrade;
declare function computeConfigHardening(permissions: PermissionFinding[], installRisks: InstallRisk[], saferSuggestions: SaferConfigSuggestion[], profile: KnownServerProfile | null): SafetyGrade;
declare function computeAnalysisConfidence(permissions: PermissionFinding[], profile: KnownServerProfile | null): AnalysisConfidence;
declare function computeEffectiveRisk(capabilityImpact: CapabilityImpact, publisherTrust: PublisherTrust$1, installHygiene: SafetyGrade, configHardening: SafetyGrade, permissions: PermissionFinding[], installRisks: InstallRisk[]): EffectiveRisk;
declare function computeHardeningGrade(installHygiene: SafetyGrade, configHardening: SafetyGrade): SafetyGrade;
declare function generateScoringTrace(capabilityImpact: CapabilityImpact, publisherTrust: PublisherTrust$1, installHygiene: SafetyGrade, configHardening: SafetyGrade, effectiveRisk: EffectiveRisk, analysisConfidence: AnalysisConfidence, permissions: PermissionFinding[], installRisks: InstallRisk[], profile: KnownServerProfile | null): ScoringTrace;
declare function computeScore(permissions: PermissionFinding[], installRisks: InstallRisk[]): number;
declare function scoreToGrade(score: number): SafetyGrade;
declare function computeRisk(score: number, permissions: PermissionFinding[], installRisks: InstallRisk[]): RiskLevel;
declare function computeOverallRisk(serverRisks: RiskLevel[]): RiskLevel;
declare function computeOverallGrade(serverScores: number[]): SafetyGrade;

/**
 * Policy-as-code engine for mcp-label.
 *
 * Evaluates MCP label reports against team-defined policies.
 */

/**
 * Parse a YAML or JSON policy file.
 */
declare function parsePolicyFile(filePath: string): PolicyFile;
/**
 * Evaluate a single server against a policy.
 */
declare function evaluatePolicy(server: ServerLabel, policy: PolicyFile): PolicyResult[];

/**
 * Terminal exporter for mcp-label reports.
 */

declare function exportTerminal(report: McpLabelReport, options?: {
    explain?: boolean;
}): string;

/**
 * Markdown exporter for mcp-label reports.
 */

declare function exportMarkdown(report: McpLabelReport): string;

/**
 * SVG exporter for mcp-label reports.
 *
 * Generates a standalone SVG card with no external fonts or remote assets.
 */

declare function exportSvg(report: McpLabelReport): string;

declare function exportJson(report: McpLabelReport): string;

/**
 * Utility functions for mcp-label.
 */
/**
 * Get the current ISO timestamp.
 */
declare function now(): string;
/**
 * Deduplicate an array of strings.
 */
declare function unique(arr: string[]): string[];

/**
 * Summarize and deduplicate concerns with counts.
 * Returns e.g. ["secrets.env x3", "payments.charge_possible", "network.egress"]
 */
declare function summarizeConcerns(permissions: PermissionFinding[], installRisks: InstallRisk[], max?: number): string[];

/**
 * Main entry point for @mcp-label/core.
 *
 * Provides the full scanning pipeline: parse config → analyze → score → report.
 */

interface ScanOptions {
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
declare function scan(config: McpConfigFile, options: ScanOptions): McpLabelReport;

export { type AnalysisConfidence, type CapabilityImpact, type Confidence, ConfidenceSchema, type ConfigHardeningGrade, type EffectiveRisk, type FindingExpectation, FindingExpectationSchema, type FindingLevel, FindingLevelSchema, type HardeningSignal, type InstallHygieneGrade, type InstallRisk, InstallRiskSchema, KNOWN_SERVER_PROFILES, type KnownServerProfile, type McpConfigFile, McpConfigFileSchema, type McpLabelReport, McpLabelReportSchema, type McpRuntimeSnapshot, type McpServerConfig, McpServerConfigSchema, PERMISSION_IDS, type PermissionFinding, PermissionFindingSchema, type PermissionId, PermissionIdSchema, type PolicyFile, PolicyFileSchema, type PolicyResult, PolicyResultSchema, type PolicyRule, PolicyRuleSchema, type PublisherTrust$1 as PublisherTrust, PublisherTrustSchema, type RiskLevel, RiskLevelSchema, type RuntimePrompt, type RuntimeResource, type RuntimeTool, type SaferConfigSuggestion, SaferConfigSuggestionSchema, type SafetyGrade, SafetyGradeSchema, type ScanOptions, type ScoreAdjustment, ScoreAdjustmentSchema, type ScoringTrace, ScoringTraceSchema, type ServerLabel, ServerLabelSchema, type TrustSignal, analyzeServer, computeAnalysisConfidence, computeCapabilityImpact, computeConfigHardening, computeEffectiveRisk, computeHardeningGrade, computeInstallHygiene, computeOverallGrade, computeOverallRisk, computeRisk, computeScore, discoverConfigFiles, evaluatePolicy, exportJson, exportMarkdown, exportSvg, exportTerminal, findKnownProfile, generateScoringTrace, getDiscoveryPaths, mergeConfigs, now, parseConfigFile, parsePolicyFile, redactEnvValues, scan, scoreToGrade, summarizeConcerns, unique };
