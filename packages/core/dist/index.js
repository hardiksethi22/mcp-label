// src/types.ts
var PERMISSION_IDS = [
  "filesystem.read",
  "filesystem.read_possible",
  "filesystem.write",
  "filesystem.delete",
  "shell.execute",
  "code.execution",
  "network.fetch",
  "network.listen",
  "network.egress",
  "browser.control",
  "browser.read_session",
  "browser.session_persistence",
  "repo.read",
  "repo.write",
  "repo.admin",
  "database.query",
  "database.mutate",
  "cloud.read",
  "cloud.write",
  "cloud.admin",
  "email.read",
  "email.send",
  "calendar.read",
  "calendar.write",
  "secrets.env",
  "secrets.files",
  "payments.read",
  "payments.write",
  "payments.charge",
  "payments.charge_possible",
  "payments.receive",
  "payment_protocol.x402",
  "unknown"
];

// src/schemas/index.ts
import { z } from "zod";
var PermissionIdSchema = z.enum(PERMISSION_IDS);
var FindingLevelSchema = z.enum(["info", "low", "medium", "high", "critical"]);
var ConfidenceSchema = z.enum(["low", "medium", "high"]);
var SafetyGradeSchema = z.enum(["A", "B", "C", "D", "F"]);
var RiskLevelSchema = z.enum(["low", "medium", "high", "critical"]);
var PublisherTrustSchema = z.enum(["unknown", "low", "medium", "high"]);
var FindingExpectationSchema = z.enum(["expected", "unexpected", "unknown"]);
var PermissionFindingSchema = z.object({
  id: z.string(),
  permission: PermissionIdSchema,
  level: FindingLevelSchema,
  confidence: ConfidenceSchema,
  evidence: z.string(),
  explanation: z.string(),
  recommendation: z.string().optional(),
  expectation: FindingExpectationSchema.optional()
});
var InstallRiskSchema = z.object({
  id: z.string(),
  level: FindingLevelSchema,
  confidence: ConfidenceSchema,
  evidence: z.string(),
  explanation: z.string(),
  recommendation: z.string()
});
var ScoreAdjustmentSchema = z.object({
  dimension: z.string(),
  reason: z.string(),
  evidence: z.string().optional()
});
var ScoringTraceSchema = z.object({
  adjustments: z.array(ScoreAdjustmentSchema),
  explanation: z.string()
});
var PolicyRuleSchema = z.object({
  id: z.string(),
  description: z.string(),
  deny: z.object({
    permissions: z.array(PermissionIdSchema).optional(),
    evidenceIncludes: z.array(z.string()).optional()
  }).optional(),
  require: z.object({
    install: z.object({
      dockerPinned: z.boolean().optional(),
      packagePinned: z.boolean().optional()
    }).optional()
  }).optional(),
  allow: z.object({
    domains: z.array(z.string()).optional()
  }).optional()
});
var PolicyFileSchema = z.object({
  version: z.string(),
  rules: z.array(PolicyRuleSchema)
});
var PolicyResultSchema = z.object({
  ruleId: z.string(),
  description: z.string(),
  passed: z.boolean(),
  server: z.string(),
  details: z.string()
});
var SaferConfigSuggestionSchema = z.object({
  id: z.string(),
  title: z.string(),
  explanation: z.string(),
  before: z.string().optional(),
  after: z.string().optional(),
  confidence: ConfidenceSchema
});
var ServerLabelSchema = z.object({
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
  risk: RiskLevelSchema
});
var McpLabelReportSchema = z.object({
  schemaVersion: z.union([z.literal("0.1"), z.literal("0.2")]),
  generatedAt: z.string(),
  source: z.object({
    configPaths: z.array(z.string()),
    discovered: z.boolean(),
    staticOnly: z.boolean()
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
    highestRisk: RiskLevelSchema
  }),
  servers: z.array(ServerLabelSchema)
});
var McpServerConfigSchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
  url: z.string().optional(),
  type: z.string().optional(),
  requestInit: z.object({
    headers: z.record(z.string()).optional()
  }).passthrough().optional()
}).passthrough();
var McpConfigFileSchema = z.object({
  mcpServers: z.record(McpServerConfigSchema).optional(),
  servers: z.record(McpServerConfigSchema).optional()
}).passthrough().refine((data) => data.mcpServers || data.servers, {
  message: 'Config must have either "mcpServers" or "servers" key'
});

// src/config/index.ts
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { homedir, platform } from "os";
function parseConfigFile(filePath) {
  const raw = readFileSync(filePath, "utf-8");
  const json = JSON.parse(raw);
  const parsed = McpConfigFileSchema.parse(json);
  const mcpServers = parsed.mcpServers ?? parsed.servers ?? {};
  return { ...parsed, mcpServers };
}
function redactEnvValues(env) {
  if (!env) return [];
  return Object.keys(env);
}
function getDiscoveryPaths() {
  const home = homedir();
  const os = platform();
  const paths = [];
  if (os === "darwin") {
    paths.push(
      join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
      join(home, ".cursor", "mcp.json"),
      join(process.cwd(), ".cursor", "mcp.json"),
      join(home, ".config", "github-copilot", "intellij", "mcp.json"),
      join(home, ".config", "github-copilot", "vscode", "mcp.json")
    );
  } else if (os === "win32") {
    const appData = process.env.APPDATA || join(home, "AppData", "Roaming");
    paths.push(
      join(appData, "Claude", "claude_desktop_config.json"),
      join(home, ".cursor", "mcp.json"),
      join(process.cwd(), ".cursor", "mcp.json"),
      join(home, ".config", "github-copilot", "intellij", "mcp.json"),
      join(home, ".config", "github-copilot", "vscode", "mcp.json")
    );
  } else {
    paths.push(
      join(home, ".config", "Claude", "claude_desktop_config.json"),
      join(home, ".cursor", "mcp.json"),
      join(process.cwd(), ".cursor", "mcp.json"),
      join(home, ".config", "github-copilot", "intellij", "mcp.json"),
      join(home, ".config", "github-copilot", "vscode", "mcp.json")
    );
  }
  return paths;
}
function discoverConfigFiles() {
  const results = [];
  for (const configPath of getDiscoveryPaths()) {
    if (!existsSync(configPath)) continue;
    try {
      const config = parseConfigFile(configPath);
      results.push({ path: configPath, config });
    } catch {
    }
  }
  return results;
}
function mergeConfigs(configs) {
  const merged = { mcpServers: {} };
  for (const config of configs) {
    Object.assign(merged.mcpServers, config.mcpServers);
  }
  return merged;
}

// src/analysis/index.ts
var SECRET_PATTERN = /(TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL|PAT|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH)/i;
var BROAD_PATHS = ["/", "~", "$HOME", "/Users", "/home", "/root", "/var", "/etc", "/tmp"];
var FILESYSTEM_SIGNALS = ["filesystem", "file", "directory", "folder", "fs-server", "local-files"];
var GITHUB_SERVER_SIGNALS = ["github-mcp", "gh-mcp", "github-mcp-server"];
var GITHUB_TOKEN_PATTERNS = [
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITHUB_PERSONAL_ACCESS_TOKEN",
  "GITHUB_PAT",
  "GH_PAT"
];
var GIT_URL_PATTERN = /git\+https?:\/\/github\.com\//i;
var BROWSER_SIGNALS = ["playwright", "puppeteer", "browser", "chromium", "selenium", "cdp"];
var PLAYWRIGHT_MCP_PACKAGE_SIGNALS = [
  "@playwright/mcp",
  "playwright-mcp",
  "microsoft/playwright-mcp",
  "github.com/microsoft/playwright-mcp"
];
var DATABASE_SIGNALS = [
  "postgres",
  "postgresql",
  "mysql",
  "mariadb",
  "mongodb",
  "mongo",
  "supabase",
  "neon",
  "planetscale",
  "sqlite",
  "clickhouse",
  "snowflake",
  "bigquery",
  "dynamodb",
  "cassandra"
];
var STATE_STORE_SIGNALS = ["redis"];
var CLOUD_SIGNALS = [
  "aws",
  "gcp",
  "google-cloud",
  "azure",
  "cloudflare",
  "vercel",
  "netlify",
  "kubernetes",
  "k8s",
  "terraform",
  "pulumi"
];
var EMAIL_SIGNALS = ["email", "gmail", "sendgrid", "mailgun", "ses", "smtp", "imap"];
var CALENDAR_SIGNALS = ["calendar", "gcal", "google-calendar"];
var PAYMENT_SIGNALS = ["stripe", "paypal", "braintree", "square", "payment", "paymcp"];
var X402_SIGNALS = ["x402", "paymcp-x402"];
var X402_ENV_PATTERNS = [
  "X402_PAY_TO_ADDRESS",
  "PAY_TO_ADDRESS",
  "PAYMENT_ADDRESS",
  "WALLET_ADDRESS"
];
var STRIPE_SECRET_PATTERNS = [
  "STRIPE_SECRET_KEY",
  "STRIPE_API_KEY"
];
var NETWORK_EGRESS_ENV_MAP = {
  "OPENAI_API_KEY": "OpenAI APIs (api.openai.com)",
  "STRIPE_SECRET_KEY": "Stripe APIs (api.stripe.com)",
  "STRIPE_API_KEY": "Stripe APIs (api.stripe.com)",
  "WALLEOT_API_KEY": "Walleot / external payment provider",
  "GITHUB_TOKEN": "GitHub APIs (api.github.com)",
  "GH_TOKEN": "GitHub APIs (api.github.com)",
  "GITHUB_PERSONAL_ACCESS_TOKEN": "GitHub APIs (api.github.com)",
  "SUPABASE_URL": "Supabase network access",
  "SUPABASE_KEY": "Supabase network access",
  "SUPABASE_ANON_KEY": "Supabase network access"
};
var SHELL_COMMANDS = ["bash", "sh", "zsh", "fish", "powershell", "pwsh", "cmd"];
function textPool(name, config) {
  const parts = [
    name,
    config.command || "",
    ...config.args || [],
    ...Object.keys(config.env || {}),
    config.url || "",
    config.type || "",
    ...Object.keys(config.requestInit?.headers || {})
  ];
  return parts.join(" ").toLowerCase();
}
function containsAny(text, signals) {
  const lower = text.toLowerCase();
  return signals.some((s) => lower.includes(s.toLowerCase()));
}
function isAbsolutePath(arg) {
  return arg.startsWith("/") || arg.startsWith("~") || arg.startsWith("$HOME");
}
function isBroadPath(arg) {
  const normalized = arg.replace(/\/+$/, "") || "/";
  return BROAD_PATHS.some((p) => normalized === p || normalized === p + "/");
}
function isUserHomePath(arg) {
  return /^(\/Users\/[^/]+|\/home\/[^/]+|~)$/.test(arg.replace(/\/+$/, ""));
}
function hasGitHubRuntimeSignal(name, config) {
  const envVars = Object.keys(config.env || {});
  const args = config.args || [];
  const command = config.command || "";
  const hasGitHubToken = envVars.some(
    (v) => GITHUB_TOKEN_PATTERNS.some((p) => v.toUpperCase() === p)
  );
  const argsWithoutGitUrls = args.filter((a) => !GIT_URL_PATTERN.test(a));
  const textWithoutGitUrls = [name, command, ...argsWithoutGitUrls].join(" ").toLowerCase();
  const hasServerSignal = GITHUB_SERVER_SIGNALS.some((s) => textWithoutGitUrls.includes(s));
  return hasGitHubToken || hasServerSignal;
}
function analyzeSecrets(name, config) {
  const findings = [];
  const envVars = redactEnvValues(config.env);
  for (const varName of envVars) {
    if (SECRET_PATTERN.test(varName)) {
      findings.push({
        id: `secrets-env-${varName.toLowerCase()}`,
        permission: "secrets.env",
        level: "high",
        confidence: "high",
        evidence: `Environment variable detected: ${varName}`,
        explanation: "The server receives a secret or credential through its environment.",
        recommendation: "Use the least-privileged credential possible and rotate it if exposed."
      });
    }
  }
  const headers = config.requestInit?.headers;
  if (headers) {
    for (const headerName of Object.keys(headers)) {
      if (SECRET_PATTERN.test(headerName) || /^authorization$/i.test(headerName)) {
        findings.push({
          id: `secrets-header-${headerName.toLowerCase().replace(/[^a-z0-9]/g, "_")}`,
          permission: "secrets.env",
          level: "high",
          confidence: "high",
          evidence: `HTTP header contains credential: ${headerName}`,
          explanation: "The server receives a secret or credential through an HTTP request header.",
          recommendation: "Use the least-privileged credential possible and rotate it if exposed."
        });
      }
    }
  }
  return findings;
}
function analyzeFilesystem(name, config) {
  const findings = [];
  const text = textPool(name, config);
  const args = config.args || [];
  if (!containsAny(text, FILESYSTEM_SIGNALS)) {
    const pathArgs = args.filter((a) => isAbsolutePath(a));
    if (pathArgs.length === 0) return findings;
  }
  findings.push({
    id: "filesystem-read",
    permission: "filesystem.read",
    level: "medium",
    confidence: "medium",
    evidence: containsAny(text, FILESYSTEM_SIGNALS) ? `Filesystem signal detected in server configuration` : `Absolute path argument detected`,
    explanation: "The server may read files from the local filesystem.",
    recommendation: "Restrict filesystem access to the smallest project folder needed."
  });
  const readOnlySignals = ["read-only", "readonly", "read_only", "viewer"];
  if (!containsAny(text, readOnlySignals)) {
    findings.push({
      id: "filesystem-write",
      permission: "filesystem.write",
      level: "high",
      confidence: "medium",
      evidence: "Filesystem MCP server detected without read-only signal",
      explanation: "The server may modify or create files on the local filesystem.",
      recommendation: "Use read-only mode if available, or restrict to a project folder."
    });
  }
  for (const arg of args) {
    if (isBroadPath(arg) || isUserHomePath(arg)) {
      const readFinding = findings.find((f) => f.id === "filesystem-read");
      if (readFinding) {
        readFinding.level = "high";
        readFinding.confidence = "high";
        readFinding.evidence = `Broad path argument: ${arg}`;
      }
    }
  }
  return findings;
}
function analyzeGitHub(name, config) {
  const findings = [];
  if (!hasGitHubRuntimeSignal(name, config)) return findings;
  findings.push({
    id: "repo-read",
    permission: "repo.read",
    level: "medium",
    confidence: "medium",
    evidence: "GitHub MCP server inferred from server name or GitHub token",
    explanation: "The server likely has read access to repository data."
  });
  findings.push({
    id: "repo-write",
    permission: "repo.write",
    level: "high",
    confidence: "medium",
    evidence: "Possible write access inferred; token scope determines actual capabilities",
    explanation: "The server may be able to write to repositories if the token has write scopes.",
    recommendation: "Use a fine-grained GitHub token and prefer read-only scopes unless write actions are required."
  });
  return findings;
}
function isPlaywrightMcp(name, config) {
  const args = config.args || [];
  const command = config.command || "";
  const allText = [command, ...args].join(" ").toLowerCase();
  return PLAYWRIGHT_MCP_PACKAGE_SIGNALS.some(
    (signal) => allText.includes(signal.toLowerCase())
  );
}
function hasFlag(args, flag) {
  return args.some((a) => a === flag);
}
function analyzePlaywrightMcp(name, config) {
  if (!isPlaywrightMcp(name, config)) return null;
  const findings = [];
  const args = config.args || [];
  findings.push({
    id: "playwright-browser-control",
    permission: "browser.control",
    level: "high",
    confidence: "high",
    evidence: "Known Playwright MCP package detected: @playwright/mcp",
    explanation: "Playwright MCP gives the model browser automation capabilities such as navigation, clicking, typing, form filling, screenshots, and tab interactions.",
    recommendation: "Use an isolated browser profile and avoid sensitive logged-in sessions."
  });
  const hasAllowedOrigins = args.some((a) => a === "--allowed-origins");
  const hasBlockedOrigins = args.some((a) => a === "--blocked-origins");
  const networkRec = hasAllowedOrigins || hasBlockedOrigins ? "Verify the configured origin allowlist/blocklist is sufficiently narrow." : "Use --allowed-origins or --blocked-origins to constrain browser network access.";
  findings.push({
    id: "playwright-network-fetch",
    permission: "network.fetch",
    level: "medium",
    confidence: "high",
    evidence: "Playwright browser automation can navigate to URLs and make browser network requests.",
    explanation: "The server can access network resources through browser navigation and page interactions.",
    recommendation: networkRec
  });
  findings.push({
    id: "playwright-run-code-unsafe",
    permission: "code.execution",
    level: "critical",
    confidence: "high",
    evidence: "Documented Playwright MCP tool: browser_run_code_unsafe",
    explanation: "Playwright MCP documents an unsafe tool (browser_run_code_unsafe) that can run Playwright code in the server process. This is a well-known, Microsoft-maintained package; the tool exists for advanced use cases but should be treated as RCE-equivalent unless disabled by policy or client-side tool allowlisting.",
    recommendation: "Require explicit approval for this tool, disable it via client tool allowlists, or avoid enabling it in sensitive environments."
  });
  if (!hasFlag(args, "--isolated")) {
    findings.push({
      id: "playwright-session-persistence",
      permission: "browser.session_persistence",
      level: "medium",
      confidence: "high",
      evidence: "No --isolated option found in Playwright MCP configuration.",
      explanation: "The browser profile may persist cookies, local storage, and login state between sessions unless isolated mode is used.",
      recommendation: "Add --isolated unless persistent login state is intentionally required."
    });
  }
  if (hasFlag(args, "--allow-unrestricted-file-access")) {
    findings.push({
      id: "playwright-unrestricted-file-access",
      permission: "filesystem.read",
      level: "high",
      confidence: "high",
      evidence: "--allow-unrestricted-file-access flag detected",
      explanation: "Unrestricted file access was explicitly enabled for browser navigation via file:// URLs.",
      recommendation: "Remove --allow-unrestricted-file-access unless it is required and tightly controlled."
    });
  } else {
    findings.push({
      id: "playwright-file-upload-paths",
      permission: "filesystem.read_possible",
      level: "medium",
      confidence: "medium",
      evidence: "Playwright MCP supports browser file upload/drop style interactions.",
      explanation: "Some browser file interactions can reference local file paths. This is not the same as unrestricted filesystem access.",
      recommendation: "Avoid exposing sensitive files through upload/drop tools and review any configured file access flags."
    });
  }
  return findings;
}
function analyzeBrowser(name, config) {
  const findings = [];
  const text = textPool(name, config);
  if (!containsAny(text, BROWSER_SIGNALS)) return findings;
  findings.push({
    id: "browser-control",
    permission: "browser.control",
    level: "high",
    confidence: "high",
    evidence: "Browser automation signal detected",
    explanation: "The server can control a browser instance.",
    recommendation: "Use an isolated browser profile and avoid sensitive logged-in sessions."
  });
  findings.push({
    id: "browser-network",
    permission: "network.fetch",
    level: "medium",
    confidence: "medium",
    evidence: "Browser automation implies network access",
    explanation: "The server can make network requests through the browser."
  });
  return findings;
}
function analyzeDatabase(name, config) {
  const findings = [];
  const text = textPool(name, config);
  const isStateStore = containsAny(text, STATE_STORE_SIGNALS);
  const isDatabase = containsAny(text, DATABASE_SIGNALS) && !isStateStore;
  if (!isDatabase && !isStateStore) return findings;
  if (isStateStore) {
    findings.push({
      id: "database-query",
      permission: "database.query",
      level: "medium",
      confidence: "medium",
      evidence: "State-store (Redis) signal detected",
      explanation: "Possible database or state-store read access inferred."
    });
    const readOnlySignals = ["read-only", "readonly", "read_only", "viewer", "query-only"];
    if (!containsAny(text, readOnlySignals)) {
      findings.push({
        id: "database-mutate",
        permission: "database.mutate",
        level: "medium",
        confidence: "medium",
        evidence: "State-store access without read-only signal",
        explanation: "Possible database or state-store write access inferred; no read-only signal was found.",
        recommendation: "Use read-only database credentials where possible."
      });
    }
  } else {
    findings.push({
      id: "database-query",
      permission: "database.query",
      level: "medium",
      confidence: "medium",
      evidence: "Database service signal detected",
      explanation: "The server can query a database."
    });
    const readOnlySignals = ["read-only", "readonly", "read_only", "viewer", "query-only"];
    if (!containsAny(text, readOnlySignals)) {
      findings.push({
        id: "database-mutate",
        permission: "database.mutate",
        level: "high",
        confidence: "low",
        evidence: "Database access without read-only signal",
        explanation: "Possible database write access inferred; no read-only signal was found.",
        recommendation: "Use read-only database credentials where possible."
      });
    }
  }
  return findings;
}
function analyzeCloud(name, config) {
  const findings = [];
  const text = textPool(name, config);
  if (!containsAny(text, CLOUD_SIGNALS)) return findings;
  findings.push({
    id: "cloud-read",
    permission: "cloud.read",
    level: "medium",
    confidence: "medium",
    evidence: "Cloud service signal detected",
    explanation: "The server may read cloud resources."
  });
  const adminSignals = ["admin", "full-access", "root", "superuser"];
  if (containsAny(text, adminSignals)) {
    findings.push({
      id: "cloud-admin",
      permission: "cloud.admin",
      level: "critical",
      confidence: "medium",
      evidence: "Cloud admin signal detected",
      explanation: "The server may have administrative access to cloud resources.",
      recommendation: "Use the least-privileged IAM role or policy."
    });
  } else {
    findings.push({
      id: "cloud-write",
      permission: "cloud.write",
      level: "high",
      confidence: "low",
      evidence: "Cloud access without read-only signal",
      explanation: "The server may be able to modify cloud resources.",
      recommendation: "Use read-only cloud credentials where possible."
    });
  }
  return findings;
}
function analyzeEmail(name, config) {
  const findings = [];
  const text = textPool(name, config);
  if (!containsAny(text, EMAIL_SIGNALS)) return findings;
  findings.push({
    id: "email-read",
    permission: "email.read",
    level: "medium",
    confidence: "medium",
    evidence: "Email service signal detected",
    explanation: "The server may read email messages."
  });
  const sendSignals = ["send", "compose", "smtp", "sendgrid", "mailgun", "ses"];
  if (containsAny(text, sendSignals)) {
    findings.push({
      id: "email-send",
      permission: "email.send",
      level: "high",
      confidence: "medium",
      evidence: "Email send capability inferred",
      explanation: "The server may send emails.",
      recommendation: "Restrict email sending capabilities and review email templates."
    });
  }
  return findings;
}
function analyzeCalendar(name, config) {
  const findings = [];
  const text = textPool(name, config);
  if (!containsAny(text, CALENDAR_SIGNALS)) return findings;
  findings.push({
    id: "calendar-read",
    permission: "calendar.read",
    level: "low",
    confidence: "medium",
    evidence: "Calendar service signal detected",
    explanation: "The server may read calendar events."
  });
  return findings;
}
function analyzePayments(name, config) {
  const findings = [];
  const text = textPool(name, config);
  const envVars = redactEnvValues(config.env);
  const hasPaymentSignal = containsAny(text, PAYMENT_SIGNALS);
  const hasStripeSecret = envVars.some(
    (v) => STRIPE_SECRET_PATTERNS.some((p) => v.toUpperCase() === p)
  );
  if (!hasPaymentSignal && !hasStripeSecret) return findings;
  if (hasStripeSecret) {
    findings.push({
      id: "payments-read",
      permission: "payments.read",
      level: "high",
      confidence: "high",
      evidence: "Stripe secret key detected in environment",
      explanation: "The server has access to payment data via Stripe credentials."
    });
    findings.push({
      id: "payments-charge-possible",
      permission: "payments.charge",
      level: "critical",
      confidence: "medium",
      evidence: "Stripe secret credentials detected",
      explanation: "Possible payment charge/write capability inferred from Stripe secret credentials. Actual operations depend on key restrictions and server code.",
      recommendation: "Use restricted API keys, enable webhook verification, and limit key permissions to the minimum required."
    });
  } else if (hasPaymentSignal) {
    findings.push({
      id: "payments-read",
      permission: "payments.read",
      level: "high",
      confidence: "medium",
      evidence: "Payment service signal inferred from server name or configuration",
      explanation: "The server may access payment data."
    });
  }
  return findings;
}
function analyzeX402(name, config) {
  const findings = [];
  const text = textPool(name, config);
  const envVars = redactEnvValues(config.env);
  const hasX402Signal = containsAny(text, X402_SIGNALS);
  const hasX402Env = envVars.some(
    (v) => X402_ENV_PATTERNS.some((p) => v.toUpperCase() === p)
  );
  if (!hasX402Signal && !hasX402Env) return findings;
  findings.push({
    id: "payment-protocol-x402",
    permission: "payment_protocol.x402",
    level: "medium",
    confidence: "high",
    evidence: hasX402Env ? `x402 payment protocol inferred from environment variables` : "x402 payment protocol inferred from server name or configuration",
    explanation: "The server appears to use the x402 payment protocol.",
    recommendation: "Review payment flow, wallet/address configuration, and user approval behavior."
  });
  if (hasX402Env) {
    findings.push({
      id: "payments-receive",
      permission: "payments.receive",
      level: "medium",
      confidence: "high",
      evidence: `Payment address environment variable detected`,
      explanation: "The server appears configured to receive or request payments using an x402-style payment address.",
      recommendation: "Verify the receiving address, payment limits, and whether the server can initiate payment-gated actions."
    });
  }
  return findings;
}
function analyzeNetworkEgress(name, config) {
  const findings = [];
  const envVars = redactEnvValues(config.env);
  const emittedServices = /* @__PURE__ */ new Set();
  for (const varName of envVars) {
    const upperVar = varName.toUpperCase();
    const service = NETWORK_EGRESS_ENV_MAP[upperVar];
    if (service && !emittedServices.has(service)) {
      emittedServices.add(service);
      findings.push({
        id: `network-egress-${varName.toLowerCase()}`,
        permission: "network.egress",
        level: "medium",
        confidence: "medium",
        evidence: `Environment variable detected: ${varName}`,
        explanation: `The server likely connects to ${service}.`,
        recommendation: "Confirm expected outbound domains and avoid sending sensitive data unnecessarily."
      });
    }
    if (X402_ENV_PATTERNS.some((p) => upperVar === p) && !emittedServices.has("x402-payment")) {
      emittedServices.add("x402-payment");
      findings.push({
        id: `network-egress-x402`,
        permission: "network.egress",
        level: "medium",
        confidence: "medium",
        evidence: `x402 payment environment variable detected: ${varName}`,
        explanation: "The server may connect to external payment endpoints via x402 protocol.",
        recommendation: "Confirm expected outbound payment domains."
      });
    }
    if (upperVar.startsWith("SUPABASE_") && !emittedServices.has("supabase")) {
      emittedServices.add("supabase");
      findings.push({
        id: `network-egress-supabase`,
        permission: "network.egress",
        level: "medium",
        confidence: "medium",
        evidence: `Environment variable detected: ${varName}`,
        explanation: "The server likely connects to Supabase.",
        recommendation: "Confirm expected outbound domains and avoid sending sensitive data unnecessarily."
      });
    }
  }
  return findings;
}
function analyzeShellExecution(name, config) {
  const findings = [];
  const command = config.command || "";
  const args = config.args || [];
  const argsStr = args.join(" ");
  if (SHELL_COMMANDS.includes(command.toLowerCase())) {
    findings.push({
      id: "shell-execute",
      permission: "shell.execute",
      level: "critical",
      confidence: "high",
      evidence: `Shell command detected: ${command}`,
      explanation: "The server uses a shell command, which can execute arbitrary code.",
      recommendation: "Avoid shell commands in MCP server configurations where possible."
    });
    return findings;
  }
  if (args.some((a) => a === "-c") && containsAny(argsStr, ["bash", "sh", "zsh"])) {
    findings.push({
      id: "shell-execute-args",
      permission: "shell.execute",
      level: "high",
      confidence: "high",
      evidence: `Shell execution in args: ${command} ${args.slice(0, 4).join(" ")}`,
      explanation: "Arguments include shell execution flags.",
      recommendation: "Replace shell commands with direct program execution."
    });
  }
  const text = textPool(name, config);
  const shellNameSignals = ["shell", "terminal", "exec", "command-runner"];
  if (containsAny(text, shellNameSignals)) {
    findings.push({
      id: "shell-execute-name",
      permission: "shell.execute",
      level: "high",
      confidence: "medium",
      evidence: `Shell/terminal signal in server name or package`,
      explanation: "The server appears to provide shell execution capabilities.",
      recommendation: "Review the server carefully and sandbox if possible."
    });
  }
  return findings;
}
function analyzeDockerRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  if (command.toLowerCase() !== "docker") return { risks };
  let image;
  for (let i = args.length - 1; i >= 0; i--) {
    const arg = args[i];
    if (arg && !arg.startsWith("-") && !arg.startsWith("/") && arg !== "run" && arg !== "-i" && arg !== "--rm" && arg !== "-e" && !args[i - 1]?.startsWith("-e") && (arg.includes("/") || arg.includes(":"))) {
      image = arg;
      break;
    }
  }
  if (!image) {
    for (const arg of args) {
      if (arg.match(/^[a-z][\w.-]*\/([\w.-]+\/)?[\w.-]+(:|$)/i)) {
        image = arg;
        break;
      }
    }
  }
  if (image) {
    if (image.endsWith(":latest")) {
      risks.push({
        id: "docker-latest",
        level: "medium",
        confidence: "high",
        evidence: image,
        explanation: "The Docker image uses the :latest tag, which can change over time.",
        recommendation: "Pin Docker images to explicit versions or immutable digests."
      });
    } else if (!image.includes(":") && !image.includes("@sha256:")) {
      risks.push({
        id: "docker-untagged",
        level: "medium",
        confidence: "high",
        evidence: image,
        explanation: "The Docker image has no explicit tag, defaulting to :latest.",
        recommendation: "Pin Docker images to explicit versions or immutable digests."
      });
    }
  }
  if (args.includes("--privileged")) {
    risks.push({
      id: "docker-privileged",
      level: "critical",
      confidence: "high",
      evidence: "--privileged flag detected",
      explanation: "The Docker container runs in privileged mode with full host access.",
      recommendation: "Remove --privileged and use specific capabilities instead."
    });
  }
  if (args.includes("--network") && args[args.indexOf("--network") + 1] === "host") {
    risks.push({
      id: "docker-host-network",
      level: "high",
      confidence: "high",
      evidence: "--network host",
      explanation: "The Docker container shares the host network stack.",
      recommendation: "Use bridge networking or a custom network instead."
    });
  }
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-v" || args[i] === "--volume") {
      const mount = args[i + 1] || "";
      const hostPath = mount.split(":")[0];
      if (hostPath && (isBroadPath(hostPath) || hostPath === ".")) {
        risks.push({
          id: "docker-broad-mount",
          level: "high",
          confidence: "high",
          evidence: `Volume mount: ${mount}`,
          explanation: "A broad host path is mounted into the container.",
          recommendation: "Mount only the specific directories needed."
        });
      }
    }
  }
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-e") {
      const envName = args[i + 1];
      if (envName && SECRET_PATTERN.test(envName)) {
        risks.push({
          id: `docker-secret-env-${envName.toLowerCase()}`,
          level: "high",
          confidence: "high",
          evidence: `Secret passed through Docker env: ${envName}`,
          explanation: "A secret is passed to the Docker container via environment variable.",
          recommendation: "Use Docker secrets or a secrets manager instead."
        });
      }
    }
  }
  return { risks, image };
}
function analyzeNpxRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  if (command.toLowerCase() !== "npx") return { risks };
  let packageName;
  for (const arg of args) {
    if (arg.startsWith("-")) continue;
    if (arg.startsWith("/") || arg.startsWith(".")) continue;
    packageName = arg;
    break;
  }
  if (packageName) {
    if (packageName.includes("@latest")) {
      risks.push({
        id: "npx-latest",
        level: "medium",
        confidence: "high",
        evidence: packageName,
        explanation: "The npx package uses @latest, which can change over time.",
        recommendation: `Pin the package to a specific version, for example ${packageName.replace(/@latest$/, "")}@<version>.`
      });
    } else if (!packageName.match(/@[\d^~]/)) {
      risks.push({
        id: "npx-unpinned",
        level: "medium",
        confidence: "high",
        evidence: packageName,
        explanation: "The npx package is not pinned to a specific version.",
        recommendation: `Pin the package to a specific version, for example ${packageName}@<version>.`
      });
    }
  }
  return { risks, packageName };
}
function analyzePnpmDlxRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  const isPnpm = command.toLowerCase() === "pnpm";
  const hasDlxOrExec = args.some((a) => a === "dlx" || a === "exec");
  if (!isPnpm || !hasDlxOrExec) return { risks };
  let packageName;
  let pastDlx = false;
  for (const arg of args) {
    if (arg === "dlx" || arg === "exec") {
      pastDlx = true;
      continue;
    }
    if (!pastDlx) continue;
    if (arg.startsWith("-")) continue;
    packageName = arg;
    break;
  }
  if (packageName) {
    if (packageName.includes("@latest")) {
      risks.push({
        id: "npx-latest",
        level: "medium",
        confidence: "high",
        evidence: packageName,
        explanation: "The pnpm dlx package uses @latest, which can change over time.",
        recommendation: `Pin the package to a specific version, for example ${packageName.replace(/@latest$/, "")}@<version>.`
      });
    } else if (!packageName.match(/@[\d^~]/)) {
      risks.push({
        id: "npx-unpinned",
        level: "medium",
        confidence: "high",
        evidence: packageName,
        explanation: "The pnpm dlx package is not pinned to a specific version.",
        recommendation: `Pin the package to a specific version, for example ${packageName}@<version>.`
      });
    }
  }
  return { risks, packageName };
}
function analyzeNpmExecRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  const isNpm = command.toLowerCase() === "npm";
  const hasExec = args.some((a) => a === "exec");
  if (!isNpm || !hasExec) return { risks };
  let packageName;
  let pastExec = false;
  for (const arg of args) {
    if (arg === "exec") {
      pastExec = true;
      continue;
    }
    if (!pastExec) continue;
    if (arg.startsWith("-")) continue;
    packageName = arg;
    break;
  }
  if (packageName) {
    if (packageName.includes("@latest")) {
      risks.push({
        id: "npx-latest",
        level: "medium",
        confidence: "high",
        evidence: packageName,
        explanation: "The npm exec package uses @latest, which can change over time.",
        recommendation: `Pin the package to a specific version, for example ${packageName.replace(/@latest$/, "")}@<version>.`
      });
    } else if (!packageName.match(/@[\d^~]/)) {
      risks.push({
        id: "npx-unpinned",
        level: "medium",
        confidence: "high",
        evidence: packageName,
        explanation: "The npm exec package is not pinned to a specific version.",
        recommendation: `Pin the package to a specific version, for example ${packageName}@<version>.`
      });
    }
  }
  return { risks, packageName };
}
function analyzeUvxRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  if (command.toLowerCase() !== "uvx") return { risks };
  const fromIdx = args.indexOf("--from");
  if (fromIdx !== -1 && fromIdx + 1 < args.length) {
    const fromValue = args[fromIdx + 1];
    if (GIT_URL_PATTERN.test(fromValue) || fromValue.startsWith("git+")) {
      risks.push(...analyzeRemoteGitUrl(fromValue));
      risks.push({
        id: "uvx-remote-source",
        level: "high",
        confidence: "high",
        evidence: fromValue,
        explanation: "The uvx package is installed from a remote Git repository.",
        recommendation: "Prefer a pinned release or package version."
      });
      return { risks };
    }
    const pkg = fromValue;
    if (!pkg.includes("==") && !pkg.includes(">=") && !pkg.match(/@[\d^~]/)) {
      risks.push({
        id: "uvx-unpinned",
        level: "medium",
        confidence: "high",
        evidence: pkg,
        explanation: "The uvx package is not pinned to a specific version.",
        recommendation: "Pin package versions (e.g., package==1.2.3)."
      });
    }
    return { risks };
  }
  let packageName;
  for (const arg of args) {
    if (arg.startsWith("-")) continue;
    packageName = arg;
    break;
  }
  if (packageName && !packageName.includes("==") && !packageName.includes(">=")) {
    risks.push({
      id: "uvx-unpinned",
      level: "medium",
      confidence: "high",
      evidence: packageName,
      explanation: "The uvx package is not pinned to a specific version.",
      recommendation: "Pin package versions (e.g., package==1.2.3)."
    });
  }
  return { risks };
}
function analyzeRemoteGitUrl(url) {
  const risks = [];
  risks.push({
    id: "remote-git-source",
    level: "medium",
    confidence: "high",
    evidence: url,
    explanation: "The server is installed from a remote Git repository.",
    recommendation: "Prefer a pinned release, package version, or commit SHA."
  });
  const atIdx = url.lastIndexOf("@");
  const hasAtPin = atIdx > url.lastIndexOf("/");
  if (!hasAtPin) {
    risks.push({
      id: "remote-git-unpinned",
      level: "high",
      confidence: "high",
      evidence: url,
      explanation: "The Git source is not pinned to a commit SHA or release tag.",
      recommendation: "Pin the Git dependency to a commit SHA or signed release tag."
    });
  } else {
    const ref = url.substring(atIdx + 1);
    const isSha = /^[0-9a-f]{7,40}$/i.test(ref);
    const isVersionTag = /^v?\d+\.\d+/.test(ref);
    if (!isSha && !isVersionTag) {
      risks.push({
        id: "remote-git-branch-ref",
        level: "medium",
        confidence: "high",
        evidence: url,
        explanation: `The Git source is pinned to a branch ref (${ref}), which can change over time.`,
        recommendation: "Prefer pinning to a commit SHA or signed release tag."
      });
    }
  }
  return risks;
}
function analyzeRemoteGitRisks(name, config) {
  const risks = [];
  const args = config.args || [];
  for (const arg of args) {
    if (GIT_URL_PATTERN.test(arg) || arg.startsWith("git+") && arg.includes("://")) {
      risks.push(...analyzeRemoteGitUrl(arg));
    }
  }
  return risks;
}
function analyzeUvWithRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  if (command.toLowerCase() !== "uv") return risks;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--with" && i + 1 < args.length) {
      const dep = args[i + 1];
      if (!dep.includes("==") && !dep.includes(">=") && !dep.includes("~=") && !dep.match(/@[\d^~]/)) {
        risks.push({
          id: "uv-with-unpinned",
          level: "medium",
          confidence: "high",
          evidence: `--with ${dep}`,
          explanation: "A runtime dependency is installed without a fixed version.",
          recommendation: `Pin runtime dependencies, for example: --with ${dep}==<version>`
        });
      }
    }
  }
  return risks;
}
function analyzeCurlPipeRisks(name, config) {
  const risks = [];
  const args = config.args || [];
  const argsStr = args.join(" ");
  if ((argsStr.includes("curl") || argsStr.includes("wget")) && (argsStr.includes("bash") || argsStr.includes("sh")) && argsStr.includes("|")) {
    risks.push({
      id: "curl-pipe-shell",
      level: "critical",
      confidence: "high",
      evidence: argsStr.substring(0, 100),
      explanation: "A remote script is piped directly into a shell for execution.",
      recommendation: "Download scripts first, inspect them, then execute."
    });
  }
  return risks;
}
function analyzeLocalScriptRisks(name, config) {
  const risks = [];
  const command = config.command || "";
  const args = config.args || [];
  if (command.match(/\.(sh|bash|py|js|ts)$/) || args.some((a) => a.match(/\.(sh|bash|py|js|ts)$/))) {
    const scriptFile = command.match(/\.(sh|bash|py|js|ts)$/) ? command : args.find((a) => a.match(/\.(sh|bash|py|js|ts)$/)) || "";
    risks.push({
      id: "local-script",
      level: "medium",
      confidence: "medium",
      evidence: scriptFile,
      explanation: "The MCP server runs a local script. Static config analysis cannot verify the script contents.",
      recommendation: "Review the script contents and dependencies before enabling the server."
    });
  }
  return risks;
}
function generateSaferSuggestions(name, config, permissions, installRisks) {
  const suggestions = [];
  for (const risk of installRisks) {
    if (risk.id === "docker-latest" || risk.id === "docker-untagged") {
      suggestions.push({
        id: "pin-docker-image",
        title: "Pin Docker image version",
        explanation: "Replace :latest or untagged images with an explicit version or immutable digest.",
        before: risk.evidence,
        after: `${risk.evidence.split(":")[0]}:<specific-version>`,
        confidence: "high"
      });
    }
  }
  for (const risk of installRisks) {
    if (risk.id === "npx-unpinned" || risk.id === "npx-latest") {
      suggestions.push({
        id: "pin-npx-package",
        title: "Pin package version",
        explanation: "Pin the npx package to a specific version for reproducible installs.",
        before: risk.evidence,
        after: `${risk.evidence.replace(/@latest$/, "")}@<specific-version>`,
        confidence: "high"
      });
    }
  }
  for (const finding of permissions) {
    if (finding.permission === "filesystem.read" && finding.evidence.includes("Broad path argument")) {
      const path = finding.evidence.replace("Broad path argument: ", "");
      suggestions.push({
        id: "restrict-filesystem-path",
        title: "Restrict filesystem path",
        explanation: "Restrict file access to the smallest project folder needed.",
        before: path,
        after: `${path}/projects/current-app`,
        confidence: "high"
      });
    }
  }
  for (const finding of permissions) {
    if (finding.permission === "repo.write") {
      suggestions.push({
        id: "use-fine-grained-token",
        title: "Use a fine-grained GitHub token",
        explanation: "Fine-grained personal access tokens allow scoping permissions to specific repositories and actions.",
        confidence: "medium"
      });
      break;
    }
  }
  for (const risk of installRisks) {
    if (risk.id === "docker-privileged") {
      suggestions.push({
        id: "remove-privileged",
        title: "Remove --privileged flag",
        explanation: "Run containers without privileged mode. Use specific --cap-add flags if needed.",
        before: "--privileged",
        after: "--cap-add=<SPECIFIC_CAPABILITY>",
        confidence: "high"
      });
    }
  }
  for (const risk of installRisks) {
    if (risk.id === "docker-host-network") {
      suggestions.push({
        id: "avoid-host-network",
        title: "Avoid host networking",
        explanation: "Use bridge networking or expose only the specific ports needed.",
        before: "--network host",
        after: "-p <host-port>:<container-port>",
        confidence: "high"
      });
    }
  }
  for (const risk of installRisks) {
    if (risk.id === "remote-git-unpinned" || risk.id === "remote-git-branch-ref") {
      suggestions.push({
        id: "pin-git-dependency",
        title: "Pin Git dependency to commit SHA or tag",
        explanation: "Pin remote Git dependencies to a commit SHA or signed release tag for reproducible installs.",
        before: risk.evidence,
        after: `${risk.evidence}@<commit-sha-or-tag>`,
        confidence: "high"
      });
      break;
    }
  }
  if (permissions.some((p) => p.id === "playwright-session-persistence")) {
    suggestions.push({
      id: "playwright-add-isolated",
      title: "Use isolated browser mode",
      explanation: "Add --isolated to prevent browser state (cookies, login sessions, local storage) from persisting between runs.",
      after: "npx @playwright/mcp@<version> --isolated",
      confidence: "high"
    });
  }
  if (permissions.some((p) => p.id === "playwright-network-fetch" && p.recommendation?.includes("--allowed-origins"))) {
    suggestions.push({
      id: "playwright-add-origin-controls",
      title: "Restrict browser origins",
      explanation: "Configure --allowed-origins or --blocked-origins to limit which sites the browser can navigate to.",
      after: "npx @playwright/mcp@<version> --allowed-origins https://example.com",
      confidence: "medium"
    });
  }
  if (permissions.some((p) => p.id === "playwright-unrestricted-file-access")) {
    suggestions.push({
      id: "playwright-remove-unrestricted-file-access",
      title: "Remove unrestricted file access",
      explanation: "The --allow-unrestricted-file-access flag grants broad file:// access. Remove it unless specifically required.",
      before: "--allow-unrestricted-file-access",
      after: "(remove this flag)",
      confidence: "high"
    });
  }
  return suggestions;
}
function analyzeHttpServer(name, config) {
  if (!config.url) return [];
  const findings = [];
  let url;
  try {
    url = new URL(config.url);
  } catch {
    findings.push({
      id: "http-invalid-url",
      permission: "network.fetch",
      level: "medium",
      confidence: "medium",
      evidence: `Invalid URL: ${config.url}`,
      explanation: "The server URL could not be parsed."
    });
    return findings;
  }
  findings.push({
    id: "http-remote-server",
    permission: "network.fetch",
    level: "medium",
    confidence: "high",
    evidence: `Remote MCP server at ${url.hostname}`,
    explanation: `The server connects to a remote HTTP endpoint. Data sent to this server leaves your machine.`,
    recommendation: "Verify you trust the remote endpoint and understand what data is sent to it."
  });
  if (url.protocol === "http:") {
    findings.push({
      id: "http-insecure",
      permission: "network.fetch",
      level: "high",
      confidence: "high",
      evidence: `Insecure HTTP URL: ${config.url}`,
      explanation: "The server uses unencrypted HTTP. Credentials and data can be intercepted.",
      recommendation: "Use HTTPS instead of HTTP."
    });
  }
  return findings;
}
function analyzeServer(name, config) {
  const playwrightFindings = analyzePlaywrightMcp(name, config);
  const permissions = [
    ...analyzeSecrets(name, config),
    ...analyzeHttpServer(name, config),
    ...analyzeFilesystem(name, config),
    ...analyzeGitHub(name, config),
    // Use Playwright MCP-specific findings if detected, otherwise generic browser analysis
    ...playwrightFindings ?? analyzeBrowser(name, config),
    ...analyzeDatabase(name, config),
    ...analyzeCloud(name, config),
    ...analyzeEmail(name, config),
    ...analyzeCalendar(name, config),
    ...analyzePayments(name, config),
    ...analyzeX402(name, config),
    ...analyzeNetworkEgress(name, config),
    ...analyzeShellExecution(name, config)
  ];
  const dockerResult = analyzeDockerRisks(name, config);
  const npxResult = analyzeNpxRisks(name, config);
  const pnpmResult = analyzePnpmDlxRisks(name, config);
  const npmResult = analyzeNpmExecRisks(name, config);
  const uvxResult = analyzeUvxRisks(name, config);
  const installRisks = [
    ...dockerResult.risks,
    ...npxResult.risks,
    ...pnpmResult.risks,
    ...npmResult.risks,
    ...uvxResult.risks,
    ...analyzeRemoteGitRisks(name, config),
    ...analyzeUvWithRisks(name, config),
    ...analyzeCurlPipeRisks(name, config),
    ...analyzeLocalScriptRisks(name, config)
  ];
  const recommendations = generateRecommendations(permissions, installRisks);
  const saferConfigSuggestions = generateSaferSuggestions(
    name,
    config,
    permissions,
    installRisks
  );
  return {
    permissions,
    installRisks,
    recommendations,
    saferConfigSuggestions,
    packageName: npxResult.packageName || pnpmResult.packageName || npmResult.packageName,
    dockerImage: dockerResult.image
  };
}
function generateRecommendations(permissions, installRisks) {
  const recs = /* @__PURE__ */ new Set();
  for (const finding of permissions) {
    if (finding.recommendation) {
      recs.add(finding.recommendation);
    }
  }
  for (const risk of installRisks) {
    if (risk.recommendation) {
      recs.add(risk.recommendation);
    }
  }
  return Array.from(recs);
}

// src/analysis/knownServers.ts
var KNOWN_SERVER_PROFILES = [
  {
    id: "known.playwright-mcp",
    displayName: "Microsoft Playwright MCP",
    match: {
      packageNames: ["@playwright/mcp", "playwright-mcp"],
      repos: ["github.com/microsoft/playwright-mcp", "microsoft/playwright-mcp"]
    },
    publisher: {
      name: "Microsoft",
      trust: "high",
      evidence: "Official Microsoft Playwright MCP package/repository match."
    },
    expectedCapabilities: [
      "browser.control",
      "network.fetch",
      "browser.session_persistence",
      "filesystem.read_possible",
      "code.execution"
    ],
    recommendedControls: [
      "Pin @playwright/mcp to a specific version.",
      "Use --isolated unless persistent login state is intentionally needed.",
      "Use --allowed-origins or --blocked-origins to limit browser egress.",
      "Avoid sensitive logged-in browser sessions.",
      "Require explicit approval for browser_run_code_unsafe or disable it via client tool allowlists."
    ]
  },
  {
    id: "known.mcp-filesystem",
    displayName: "MCP Filesystem Server",
    match: {
      packageNames: ["@modelcontextprotocol/server-filesystem"]
    },
    publisher: {
      name: "Anthropic (Model Context Protocol)",
      trust: "high",
      evidence: "Official Model Context Protocol reference server."
    },
    expectedCapabilities: [
      "filesystem.read",
      "filesystem.write"
    ],
    recommendedControls: [
      "Restrict filesystem access to the smallest project folder needed.",
      "Use read-only mode if available.",
      "Pin the package to a specific version."
    ]
  },
  {
    id: "known.github-mcp",
    displayName: "GitHub MCP Server",
    match: {
      packageNames: ["github-mcp-server", "@github/mcp-server"],
      dockerImages: ["ghcr.io/github/github-mcp-server"]
    },
    publisher: {
      name: "GitHub",
      trust: "high",
      evidence: "Official GitHub MCP server package/image match."
    },
    expectedCapabilities: [
      "repo.read",
      "repo.write",
      "secrets.env",
      "network.egress"
    ],
    recommendedControls: [
      "Use a fine-grained personal access token with minimal scopes.",
      "Prefer read-only scopes unless write actions are required.",
      "Pin the Docker image or package to a specific version."
    ]
  }
];
function findKnownProfile(name, config) {
  const args = config.args || [];
  const command = config.command || "";
  const allText = [command, ...args].join(" ").toLowerCase();
  for (const profile of KNOWN_SERVER_PROFILES) {
    if (profile.match.packageNames) {
      for (const pkg of profile.match.packageNames) {
        if (allText.includes(pkg.toLowerCase())) {
          return profile;
        }
      }
    }
    if (profile.match.repos) {
      for (const repo of profile.match.repos) {
        if (allText.includes(repo.toLowerCase())) {
          return profile;
        }
      }
    }
    if (profile.match.dockerImages) {
      for (const image of profile.match.dockerImages) {
        if (allText.includes(image.toLowerCase())) {
          return profile;
        }
      }
    }
  }
  return null;
}
function isExpectedCapability(profile, permission) {
  if (!profile) return false;
  return profile.expectedCapabilities.includes(permission);
}

// src/scoring/index.ts
var FINDING_DEDUCTIONS = {
  info: 0,
  low: -5,
  medium: -12,
  high: -25,
  critical: -40
};
var INSTALL_RISK_DEDUCTIONS = {
  "npx-unpinned": -10,
  "npx-latest": -10,
  "uvx-unpinned": -10,
  "uvx-remote-source": -15,
  "docker-latest": -10,
  "docker-untagged": -10,
  "docker-privileged": -30,
  "docker-host-network": -15,
  "docker-broad-mount": -25,
  "curl-pipe-shell": -40,
  "local-script": -10,
  "remote-git-source": -10,
  "remote-git-unpinned": -20,
  "remote-git-branch-ref": -10,
  "uv-with-unpinned": -8
};
var CRITICAL_CAPABILITIES = [
  "shell.execute",
  "code.execution",
  "payments.charge",
  "cloud.admin"
];
var HIGH_CAPABILITIES = [
  "browser.control",
  "filesystem.write",
  "filesystem.delete",
  "repo.write",
  "repo.admin",
  "database.mutate",
  "cloud.write",
  "email.send",
  "payments.write",
  "payments.charge_possible"
];
var MEDIUM_CAPABILITIES = [
  "filesystem.read",
  "network.fetch",
  "network.egress",
  "repo.read",
  "database.query",
  "cloud.read",
  "email.read",
  "payments.read",
  "secrets.env",
  "browser.session_persistence",
  "filesystem.read_possible",
  "payment_protocol.x402",
  "payments.receive"
];
function computeCapabilityImpact(permissions) {
  const ids = permissions.map((p) => p.permission);
  if (ids.some((id) => CRITICAL_CAPABILITIES.includes(id))) return "critical";
  if (ids.some((id) => HIGH_CAPABILITIES.includes(id))) return "high";
  if (ids.some((id) => MEDIUM_CAPABILITIES.includes(id))) return "medium";
  return "low";
}
function computeInstallHygiene(installRisks) {
  const ids = installRisks.map((r) => r.id);
  const levels = installRisks.map((r) => r.level);
  if (ids.includes("curl-pipe-shell") || ids.includes("docker-privileged")) return "F";
  if (ids.includes("remote-git-unpinned") || ids.includes("uvx-remote-source")) return "D";
  if (ids.includes("npx-latest") || ids.includes("npx-unpinned") || ids.includes("uvx-unpinned") || ids.includes("docker-latest") || ids.includes("docker-untagged") || ids.includes("uv-with-unpinned")) return "C";
  if (installRisks.length > 0) return "B";
  return "A";
}
function computeConfigHardening(permissions, installRisks, saferSuggestions, profile) {
  let score = 100;
  const hasShell = permissions.some((p) => p.permission === "shell.execute");
  const hasSecret = permissions.some((p) => p.permission === "secrets.env");
  const hasBroadFs = permissions.some(
    (p) => p.permission === "filesystem.write" || p.permission === "filesystem.read" && p.evidence.includes("Broad path")
  );
  const hasRemoteUnpinned = installRisks.some((r) => r.id === "remote-git-unpinned");
  if (hasShell && hasRemoteUnpinned) return "F";
  if (hasBroadFs && hasSecret && hasShell) return "F";
  if (installRisks.some((r) => r.id === "curl-pipe-shell")) return "F";
  const missingControls = saferSuggestions.length;
  score -= missingControls * 8;
  if (installRisks.some((r) => r.id === "npx-latest" || r.id === "npx-unpinned")) score -= 10;
  if (hasBroadFs) score -= 15;
  if (hasSecret && permissions.some((p) => p.permission === "repo.write" || p.permission === "filesystem.write" || p.permission === "database.mutate" || p.permission === "cloud.write")) {
    score -= 15;
  }
  if (permissions.some((p) => p.id === "playwright-session-persistence")) score -= 8;
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}
function computeAnalysisConfidence(permissions, profile) {
  if (profile) {
    const highConfidenceCount = permissions.filter((p) => p.confidence === "high").length;
    if (highConfidenceCount >= permissions.length * 0.6) return "high";
    return "medium";
  }
  const highCount = permissions.filter((p) => p.confidence === "high").length;
  const medCount = permissions.filter((p) => p.confidence === "medium").length;
  const total = permissions.length || 1;
  if (highCount / total >= 0.5) return "medium";
  if (medCount / total >= 0.5) return "medium";
  return "low";
}
function computeEffectiveRisk(capabilityImpact, publisherTrust, installHygiene, configHardening, permissions, installRisks) {
  const hasShell = permissions.some((p) => p.permission === "shell.execute");
  const hasCurlPipe = installRisks.some((r) => r.id === "curl-pipe-shell");
  const hasDockerPriv = installRisks.some((r) => r.id === "docker-privileged");
  if (hasCurlPipe || hasDockerPriv || hasShell && installRisks.some((r) => r.id === "remote-git-unpinned")) {
    return "critical";
  }
  if (capabilityImpact === "critical") {
    if (publisherTrust === "high") return "high";
    return "critical";
  }
  if (capabilityImpact === "high") {
    if (publisherTrust === "high" && (configHardening === "A" || configHardening === "B")) return "medium";
    if (publisherTrust === "high") return "high";
    if (publisherTrust === "unknown" || publisherTrust === "low") return "high";
    return "high";
  }
  if (capabilityImpact === "medium") {
    if (configHardening === "A" || configHardening === "B") return "low";
    return "medium";
  }
  return "low";
}
function computeHardeningGrade(installHygiene, configHardening) {
  const gradeOrder = { "A": 4, "B": 3, "C": 2, "D": 1, "F": 0 };
  const avg = (gradeOrder[installHygiene] + gradeOrder[configHardening]) / 2;
  if (avg >= 3.5) return "A";
  if (avg >= 2.5) return "B";
  if (avg >= 1.5) return "C";
  if (avg >= 0.5) return "D";
  return "F";
}
function generateScoringTrace(capabilityImpact, publisherTrust, installHygiene, configHardening, effectiveRisk, analysisConfidence, permissions, installRisks, profile) {
  const adjustments = [];
  const critCaps = permissions.filter((p) => CRITICAL_CAPABILITIES.includes(p.permission));
  const highCaps = permissions.filter((p) => HIGH_CAPABILITIES.includes(p.permission));
  if (critCaps.length > 0) {
    adjustments.push({
      dimension: "capabilityImpact",
      reason: `Critical capabilities detected: ${critCaps.map((c) => c.permission).join(", ")}`,
      evidence: critCaps.map((c) => c.evidence).join("; ")
    });
  } else if (highCaps.length > 0) {
    adjustments.push({
      dimension: "capabilityImpact",
      reason: `High-impact capabilities detected: ${highCaps.map((c) => c.permission).join(", ")}`
    });
  }
  if (profile) {
    adjustments.push({
      dimension: "publisherTrust",
      reason: `Known server profile matched: ${profile.displayName} (${profile.publisher.name})`,
      evidence: profile.publisher.evidence
    });
  } else {
    adjustments.push({
      dimension: "publisherTrust",
      reason: "No known server profile matched. Publisher trust is unknown."
    });
  }
  if (installRisks.length > 0) {
    adjustments.push({
      dimension: "installHygiene",
      reason: `Install risks found: ${installRisks.map((r) => r.id).join(", ")}`
    });
  }
  const expectedCount = permissions.filter((p) => p.expectation === "expected").length;
  const unexpectedCount = permissions.filter((p) => p.expectation === "unexpected").length;
  if (unexpectedCount > 0) {
    adjustments.push({
      dimension: "configHardening",
      reason: `${unexpectedCount} unexpected capability/capabilities detected`
    });
  }
  const parts = [];
  parts.push(`Capability impact is **${capabilityImpact}** because ${capabilityImpact === "low" ? "no high-impact capabilities were detected" : `the server has ${capabilityImpact}-impact capabilities (${permissions.map((p) => p.permission).filter((v, i, a) => a.indexOf(v) === i).slice(0, 3).join(", ")})`}.`);
  parts.push(`Publisher trust is **${publisherTrust}**${profile ? ` because the package matches a known ${profile.publisher.name} profile` : " because no known publisher profile was matched"}.`);
  parts.push(`Install hygiene is **${installHygiene}**${installRisks.length > 0 ? ` because ${installRisks[0].explanation.toLowerCase()}` : " because no install risks were found"}.`);
  parts.push(`Config hardening is **${configHardening}**.`);
  parts.push(`Effective risk is **${effectiveRisk}**.`);
  return {
    adjustments,
    explanation: parts.join(" ")
  };
}
function computeScore(permissions, installRisks) {
  let score = 100;
  for (const finding of permissions) {
    score += FINDING_DEDUCTIONS[finding.level] ?? 0;
  }
  for (const risk of installRisks) {
    const specificDeduction = INSTALL_RISK_DEDUCTIONS[risk.id];
    if (specificDeduction !== void 0) {
      score += specificDeduction;
    } else {
      score += FINDING_DEDUCTIONS[risk.level] ?? 0;
    }
  }
  const hasSecret = permissions.some((p) => p.permission === "secrets.env");
  const hasWrite = permissions.some(
    (p) => p.permission === "repo.write" || p.permission === "filesystem.write" || p.permission === "database.mutate" || p.permission === "cloud.write" || p.permission === "cloud.admin"
  );
  if (hasSecret && hasWrite) score -= 15;
  const hasPaymentCharge = permissions.some(
    (p) => p.permission === "payments.charge" || p.permission === "payments.charge_possible"
  );
  if (hasSecret && hasPaymentCharge) score -= 10;
  const hasLocalScript = installRisks.some((r) => r.id === "local-script");
  if (hasLocalScript && hasSecret && hasPaymentCharge) score -= 10;
  const hasRemoteGitUnpinned = installRisks.some((r) => r.id === "remote-git-unpinned");
  if (hasRemoteGitUnpinned && hasSecret) score -= 10;
  const hasShell = permissions.some((p) => p.permission === "shell.execute");
  if (hasShell) score -= 20;
  const hasCodeExecution = permissions.some((p) => p.permission === "code.execution");
  const hasBrowserControl = permissions.some((p) => p.permission === "browser.control");
  if (hasCodeExecution && hasBrowserControl) score -= 5;
  return Math.max(0, Math.min(100, score));
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
function computeRisk(score, permissions, installRisks) {
  const allFindings = [...permissions, ...installRisks];
  const hasCritical = allFindings.some((f) => f.level === "critical");
  const hasHigh = allFindings.some((f) => f.level === "high");
  if (hasCritical || score < 40) return "critical";
  if (hasHigh || score < 70) return "high";
  if (score < 85) return "medium";
  return "low";
}
function computeOverallRisk(serverRisks) {
  const order = ["critical", "high", "medium", "low"];
  for (const level of order) {
    if (serverRisks.includes(level)) return level;
  }
  return "low";
}
function computeOverallGrade(serverScores) {
  if (serverScores.length === 0) return "A";
  const avg = serverScores.reduce((a, b) => a + b, 0) / serverScores.length;
  return scoreToGrade(avg);
}

// src/policy/index.ts
import { readFileSync as readFileSync2 } from "fs";
import YAML from "yaml";
function parsePolicyFile(filePath) {
  const raw = readFileSync2(filePath, "utf-8");
  let parsed;
  if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
    parsed = YAML.parse(raw);
  } else {
    parsed = JSON.parse(raw);
  }
  return PolicyFileSchema.parse(parsed);
}
function evaluatePolicy(server, policy) {
  const results = [];
  for (const rule of policy.rules) {
    const result = evaluateRule(server, rule);
    results.push(result);
  }
  return results;
}
function evaluateRule(server, rule) {
  if (rule.deny?.permissions) {
    for (const deniedPerm of rule.deny.permissions) {
      const matchingFindings = server.permissions.filter(
        (f) => f.permission === deniedPerm
      );
      if (matchingFindings.length > 0) {
        if (rule.deny.evidenceIncludes && rule.deny.evidenceIncludes.length > 0) {
          const evidenceMatch = matchingFindings.some(
            (f) => rule.deny.evidenceIncludes.some(
              (pattern) => f.evidence.includes(pattern)
            )
          );
          if (evidenceMatch) {
            return {
              ruleId: rule.id,
              description: rule.description,
              passed: false,
              server: server.name,
              details: `Denied permission ${deniedPerm} with matching evidence found.`
            };
          }
        } else {
          return {
            ruleId: rule.id,
            description: rule.description,
            passed: false,
            server: server.name,
            details: `Denied permission ${deniedPerm} detected.`
          };
        }
      }
    }
  }
  if (rule.require?.install) {
    if (rule.require.install.dockerPinned) {
      const hasUnpinnedDocker = server.installRisks.some(
        (r) => r.id === "docker-latest" || r.id === "docker-untagged"
      );
      if (hasUnpinnedDocker) {
        return {
          ruleId: rule.id,
          description: rule.description,
          passed: false,
          server: server.name,
          details: "Docker image is not pinned to an explicit version or digest."
        };
      }
    }
    if (rule.require.install.packagePinned) {
      const hasUnpinnedPkg = server.installRisks.some(
        (r) => r.id === "npx-unpinned" || r.id === "npx-latest" || r.id === "uvx-unpinned"
      );
      if (hasUnpinnedPkg) {
        return {
          ruleId: rule.id,
          description: rule.description,
          passed: false,
          server: server.name,
          details: "Package is not pinned to a specific version."
        };
      }
    }
  }
  return {
    ruleId: rule.id,
    description: rule.description,
    passed: true,
    server: server.name,
    details: "Rule passed."
  };
}

// src/exporters/terminal.ts
var BOLD = "\x1B[1m";
var RED = "\x1B[31m";
var YELLOW = "\x1B[33m";
var GREEN = "\x1B[32m";
var CYAN = "\x1B[36m";
var DIM = "\x1B[2m";
var RESET = "\x1B[0m";
function levelColor(level) {
  switch (level) {
    case "critical":
      return RED;
    case "high":
      return RED;
    case "medium":
      return YELLOW;
    case "low":
      return GREEN;
    default:
      return DIM;
  }
}
function trustColor(trust) {
  switch (trust) {
    case "high":
      return GREEN;
    case "medium":
      return YELLOW;
    case "low":
      return RED;
    case "unknown":
      return DIM;
    default:
      return DIM;
  }
}
function padRight(str, len) {
  return str.padEnd(len);
}
function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
function exportTerminal(report, options) {
  const lines = [];
  lines.push(`${BOLD}MCP Safety Label${RESET}`);
  lines.push(
    `Config: ${report.source.configPaths.join(", ") || "auto-discovered"}`
  );
  lines.push(`Servers: ${report.summary.serverCount}`);
  lines.push("");
  const s = report.summary;
  if (s.capabilityImpact) {
    lines.push(`  Capability impact:  ${levelColor(s.capabilityImpact)}${capitalize(s.capabilityImpact)}${RESET}`);
    lines.push(`  Effective risk:     ${levelColor(s.effectiveRisk)}${capitalize(s.effectiveRisk)}${RESET}`);
    lines.push(`  Hardening grade:    ${BOLD}${s.hardeningGrade}${RESET}`);
    lines.push(`  Publisher trust:    ${trustColor(s.publisherTrust)}${capitalize(s.publisherTrust)}${RESET}`);
    lines.push(`  Install hygiene:    ${BOLD}${s.installHygiene}${RESET}`);
    lines.push(`  Config hardening:   ${BOLD}${s.configHardening}${RESET}`);
    lines.push(`  Static confidence:  ${capitalize(s.analysisConfidence)}`);
  } else {
    lines.push(`  Overall: ${BOLD}${s.overallGrade}${RESET} / ${levelColor(s.overallRisk)}${s.overallRisk.toUpperCase()}${RESET}`);
  }
  lines.push(`  Static analysis only: ${report.source.staticOnly ? "yes" : "no"}`);
  lines.push("");
  for (const server of report.servers) {
    lines.push(`${BOLD}${CYAN}${server.name}${RESET}${server.knownServerProfile ? ` ${DIM}(${server.knownServerProfile})${RESET}` : ""}`);
    if (server.capabilityImpact) {
      lines.push(`  Capability: ${levelColor(server.capabilityImpact)}${capitalize(server.capabilityImpact)}${RESET}  Risk: ${levelColor(server.effectiveRisk)}${capitalize(server.effectiveRisk)}${RESET}  Hardening: ${BOLD}${server.hardeningGrade}${RESET}  Trust: ${trustColor(server.publisherTrust)}${capitalize(server.publisherTrust)}${RESET}`);
    } else {
      lines.push(`  Grade: ${BOLD}${server.grade}${RESET}  Risk: ${levelColor(server.risk)}${server.risk.toUpperCase()}${RESET}`);
    }
    lines.push("");
    if (server.permissions.length > 0) {
      const expected = server.permissions.filter((p) => p.expectation === "expected");
      const other = server.permissions.filter((p) => p.expectation !== "expected");
      if (expected.length > 0) {
        lines.push(`  ${BOLD}Expected capabilities:${RESET}`);
        for (const perm of expected) {
          const lvl = padRight(perm.level.toUpperCase(), 10);
          const id = padRight(perm.permission, 28);
          lines.push(
            `    ${levelColor(perm.level)}${lvl}${RESET}${id}${DIM}(expected)${RESET} ${perm.evidence}`
          );
        }
        lines.push("");
      }
      if (other.length > 0) {
        lines.push(`  ${BOLD}Permissions:${RESET}`);
        for (const perm of other) {
          const lvl = padRight(perm.level.toUpperCase(), 10);
          const id = padRight(perm.permission, 28);
          lines.push(
            `    ${levelColor(perm.level)}${lvl}${RESET}${id}${perm.evidence}`
          );
        }
        lines.push("");
      }
    }
    if (server.installRisks.length > 0) {
      lines.push(`  ${BOLD}Install risks:${RESET}`);
      for (const risk of server.installRisks) {
        const lvl = padRight(risk.level.toUpperCase(), 10);
        const id = padRight(risk.id, 26);
        lines.push(
          `    ${levelColor(risk.level)}${lvl}${RESET}${id}${risk.explanation}`
        );
      }
      lines.push("");
    }
    if (server.recommendations.length > 0) {
      lines.push(`  ${BOLD}Recommendations:${RESET}`);
      for (const rec of server.recommendations) {
        lines.push(`    - ${rec}`);
      }
      lines.push("");
    }
    if (options?.explain && server.scoringTrace) {
      lines.push(`  ${BOLD}Why this result?${RESET}`);
      lines.push(`    ${server.scoringTrace.explanation.replace(/\*\*/g, "")}`);
      lines.push("");
    }
  }
  lines.push(
    `${DIM}mcp-label is a heuristic analyzer. It does not prove safety. High impact \u2260 malicious. Use it as a review aid.${RESET}`
  );
  return lines.join("\n");
}

// src/utils/index.ts
function now() {
  return (/* @__PURE__ */ new Date()).toISOString();
}
function unique(arr) {
  return [...new Set(arr)];
}
function summarizeConcerns(permissions, installRisks, max = 4) {
  const levelOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const items = [
    ...permissions.map((p) => ({ id: p.permission, level: p.level })),
    ...installRisks.map((r) => ({ id: r.id, level: r.level }))
  ];
  const counts = /* @__PURE__ */ new Map();
  for (const item of items) {
    const existing = counts.get(item.id);
    if (existing) {
      existing.count++;
      if ((levelOrder[item.level] ?? 5) < (levelOrder[existing.level] ?? 5)) {
        existing.level = item.level;
      }
    } else {
      counts.set(item.id, { count: 1, level: item.level });
    }
  }
  const sorted = [...counts.entries()].sort((a, b) => {
    const levelDiff = (levelOrder[a[1].level] ?? 5) - (levelOrder[b[1].level] ?? 5);
    if (levelDiff !== 0) return levelDiff;
    return b[1].count - a[1].count;
  });
  return sorted.slice(0, max).map(
    ([id, { count }]) => count > 1 ? `${id} x${count}` : id
  );
}

// src/exporters/markdown.ts
function exportMarkdown(report) {
  const lines = [];
  lines.push("# MCP Safety Label");
  lines.push("");
  if (report.summary.capabilityImpact) {
    lines.push(`Capability impact: **${capitalize2(report.summary.capabilityImpact)}**`);
    lines.push(`Effective risk: **${capitalize2(report.summary.effectiveRisk)}**`);
    lines.push(`Hardening grade: **${report.summary.hardeningGrade}**`);
    lines.push(`Publisher trust: **${capitalize2(report.summary.publisherTrust)}**`);
    lines.push(`Install hygiene: **${report.summary.installHygiene}**`);
    lines.push(`Config hardening: **${report.summary.configHardening}**`);
    lines.push(`Static confidence: **${capitalize2(report.summary.analysisConfidence)}**`);
  } else {
    lines.push(`Overall grade: **${report.summary.overallGrade}**`);
    lines.push(`Overall risk: **${capitalize2(report.summary.overallRisk)}**`);
  }
  lines.push(`Static analysis only: **${report.source.staticOnly ? "Yes" : "No"}**`);
  lines.push("");
  if (report.servers[0]?.capabilityImpact) {
    lines.push("| Server | Impact | Risk | Hardening | Trust | Main concerns |");
    lines.push("|---|:---:|:---:|:---:|:---:|---|");
    for (const server of report.servers) {
      const concerns = summarizeConcerns(server.permissions, server.installRisks, 4);
      lines.push(
        `| ${server.name} | ${capitalize2(server.capabilityImpact)} | ${capitalize2(server.effectiveRisk)} | ${server.hardeningGrade} | ${capitalize2(server.publisherTrust)} | ${concerns.join(", ") || "none"} |`
      );
    }
  } else {
    lines.push("| Server | Grade | Risk | Main concerns |");
    lines.push("|---|:---:|:---:|---|");
    for (const server of report.servers) {
      const concerns = summarizeConcerns(server.permissions, server.installRisks, 4);
      lines.push(
        `| ${server.name} | ${server.grade} | ${capitalize2(server.risk)} | ${concerns.join(", ") || "none"} |`
      );
    }
  }
  lines.push("");
  for (const server of report.servers) {
    lines.push(`## ${server.name}`);
    lines.push("");
    if (server.knownServerProfile && server.publisherTrust) {
      lines.push(`> Known server: publisher trust is **${capitalize2(server.publisherTrust)}**.`);
      lines.push("");
    }
    const expected = server.permissions.filter((p) => p.expectation === "expected");
    const unexpected = server.permissions.filter((p) => p.expectation === "unexpected");
    const unknown = server.permissions.filter((p) => p.expectation === "unknown");
    if (expected.length > 0) {
      lines.push("### Expected Capabilities");
      lines.push("");
      for (const perm of expected) {
        lines.push(
          `- **${capitalize2(perm.level)}:** \`${perm.permission}\` \u2014 ${perm.explanation}`
        );
      }
      lines.push("");
    }
    if (unexpected.length > 0) {
      lines.push("### Unexpected or Review-Needed Capabilities");
      lines.push("");
      for (const perm of unexpected) {
        lines.push(
          `- **${capitalize2(perm.level)}:** \`${perm.permission}\` \u2014 ${perm.evidence}`
        );
      }
      lines.push("");
    }
    if (unknown.length > 0) {
      lines.push("### Permissions");
      lines.push("");
      for (const perm of unknown) {
        lines.push(
          `- **${capitalize2(perm.level)}:** \`${perm.permission}\` \u2014 ${perm.evidence}`
        );
      }
      lines.push("");
    }
    if (server.installRisks.length > 0) {
      lines.push("### Install Risks");
      lines.push("");
      for (const risk of server.installRisks) {
        lines.push(
          `- **${capitalize2(risk.level)}:** \`${risk.id}\` \u2014 ${risk.explanation}`
        );
      }
      lines.push("");
    }
    if (server.recommendations.length > 0) {
      lines.push("### Recommendations");
      lines.push("");
      for (const rec of server.recommendations) {
        lines.push(`- ${rec}`);
      }
      lines.push("");
    }
    if (server.policyResults && server.policyResults.length > 0) {
      const failed = server.policyResults.filter((r) => !r.passed);
      if (failed.length > 0) {
        lines.push("### Policy Violations");
        lines.push("");
        for (const r of failed) {
          lines.push(`- \u274C **${r.ruleId}:** ${r.details}`);
        }
        lines.push("");
      }
    }
    if (server.scoringTrace) {
      lines.push("### Why this result?");
      lines.push("");
      lines.push(server.scoringTrace.explanation);
      lines.push("");
    }
  }
  lines.push("---");
  lines.push("");
  lines.push(
    "*Generated by [mcp-label](https://github.com/mcp-label/mcp-label). High capability impact does not mean a server is malicious. This is a heuristic analysis, not a proof of safety.*"
  );
  return lines.join("\n");
}
function capitalize2(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// src/exporters/svg.ts
function riskColor(risk) {
  switch (risk) {
    case "critical":
      return "#dc2626";
    case "high":
      return "#ea580c";
    case "medium":
      return "#ca8a04";
    case "low":
      return "#16a34a";
    default:
      return "#6b7280";
  }
}
function gradeColor(grade) {
  switch (grade) {
    case "A":
      return "#16a34a";
    case "B":
      return "#65a30d";
    case "C":
      return "#ca8a04";
    case "D":
      return "#ea580c";
    case "F":
      return "#dc2626";
    default:
      return "#6b7280";
  }
}
function trustColor2(trust) {
  switch (trust) {
    case "high":
      return "#16a34a";
    case "medium":
      return "#ca8a04";
    case "low":
      return "#ea580c";
    case "unknown":
    default:
      return "#6b7280";
  }
}
function escapeXml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
function capitalize3(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function exportSvg(report) {
  const width = 420;
  let topConcerns = report.summary.topConcerns.slice(0, 3);
  if (topConcerns.length === 0 && report.servers.length > 0) {
    const allPerms = report.servers.flatMap((s) => s.permissions);
    const allRisks = report.servers.flatMap((s) => s.installRisks);
    topConcerns = summarizeConcerns(allPerms, allRisks, 3);
  }
  const impact = report.summary.capabilityImpact || report.summary.overallRisk;
  const risk = report.summary.effectiveRisk || report.summary.overallRisk;
  const hardening = report.summary.hardeningGrade || report.summary.overallGrade;
  const trust = report.summary.publisherTrust || "unknown";
  const hygiene = report.summary.installHygiene || report.summary.overallGrade;
  const date = new Date(report.generatedAt).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
  const baseHeight = 220;
  const concernHeight = topConcerns.length * 22;
  const height = baseHeight + concernHeight;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <defs>
    <style>
      .title { font: bold 16px system-ui, -apple-system, sans-serif; fill: #1f2937; }
      .label { font: 12px system-ui, -apple-system, sans-serif; fill: #6b7280; }
      .value { font: bold 13px system-ui, -apple-system, sans-serif; }
      .grade { font: bold 28px system-ui, -apple-system, sans-serif; }
      .concern { font: 12px monospace; fill: #374151; }
      .footer { font: 10px system-ui, -apple-system, sans-serif; fill: #9ca3af; }
    </style>
  </defs>
  <rect width="${width}" height="${height}" rx="8" fill="#ffffff" stroke="#e5e7eb" stroke-width="1"/>
  
  <!-- Header -->
  <text x="20" y="30" class="title">MCP Safety Label</text>
  
  <!-- Hardening grade circle -->
  <circle cx="48" cy="72" r="26" fill="${gradeColor(hardening)}" opacity="0.1"/>
  <text x="48" y="82" class="grade" fill="${gradeColor(hardening)}" text-anchor="middle">${escapeXml(hardening)}</text>
  
  <!-- Dimensions -->
  <text x="90" y="56" class="label">Capability</text>
  <text x="90" y="72" class="value" fill="${riskColor(impact)}">${escapeXml(capitalize3(impact))}</text>
  
  <text x="170" y="56" class="label">Risk</text>
  <text x="170" y="72" class="value" fill="${riskColor(risk)}">${escapeXml(capitalize3(risk))}</text>
  
  <text x="240" y="56" class="label">Trust</text>
  <text x="240" y="72" class="value" fill="${trustColor2(trust)}">${escapeXml(capitalize3(trust))}</text>
  
  <text x="320" y="56" class="label">Hygiene</text>
  <text x="320" y="72" class="value" fill="${gradeColor(hygiene)}">${escapeXml(hygiene)}</text>

  <!-- Stats row -->
  <text x="90" y="98" class="label">Servers: ${report.summary.serverCount}</text>
  <text x="170" y="98" class="label">Findings: ${report.summary.totalFindings}</text>
  
  <!-- Divider -->
  <line x1="20" y1="115" x2="${width - 20}" y2="115" stroke="#e5e7eb" stroke-width="1"/>
  
  <!-- Top concerns -->
  <text x="20" y="135" class="label">Top Concerns</text>
  ${topConcerns.map(
    (c, i) => `<text x="20" y="${155 + i * 22}" class="concern">${escapeXml(c)}</text>`
  ).join("\n  ")}
  
  <!-- Mitigations -->
  ${(report.summary.topMitigations?.length ?? 0) > 0 ? `
  <line x1="20" y1="${155 + topConcerns.length * 22 + 5}" x2="${width - 20}" y2="${155 + topConcerns.length * 22 + 5}" stroke="#e5e7eb" stroke-width="1"/>
  <text x="20" y="${155 + topConcerns.length * 22 + 22}" class="label">Top Mitigations</text>
  ${report.summary.topMitigations?.slice(0, 2).map((m, i) => `<text x="20" y="${155 + topConcerns.length * 22 + 40 + i * 18}" class="concern">${escapeXml(m)}</text>`).join("\n  ")}` : ""}
  
  <!-- Footer -->
  <text x="20" y="${height - 10}" class="footer">Generated ${escapeXml(date)} \xB7 mcp-label \xB7 static analysis only</text>
</svg>`;
  return svg;
}

// src/exporters/index.ts
function exportJson(report) {
  return JSON.stringify(report, null, 2);
}

// src/index.ts
function scan(config, options) {
  const servers = [];
  for (const [name, serverConfig] of Object.entries(config.mcpServers)) {
    const {
      permissions,
      installRisks,
      recommendations,
      saferConfigSuggestions,
      packageName,
      dockerImage
    } = analyzeServer(name, serverConfig);
    const profile = options.noKnownProfiles ? null : findKnownProfile(name, serverConfig);
    for (const perm of permissions) {
      if (profile) {
        perm.expectation = isExpectedCapability(profile, perm.permission) ? "expected" : "unexpected";
      } else {
        perm.expectation = "unknown";
      }
    }
    const score = computeScore(permissions, installRisks);
    const grade = scoreToGrade(score);
    const risk = computeRisk(score, permissions, installRisks);
    const capabilityImpact = computeCapabilityImpact(permissions);
    const publisherTrust = profile?.publisher.trust ?? "unknown";
    const installHygiene = computeInstallHygiene(installRisks);
    const configHardening = computeConfigHardening(permissions, installRisks, saferConfigSuggestions, profile);
    const analysisConfidence = computeAnalysisConfidence(permissions, profile);
    const hardeningGrade = computeHardeningGrade(installHygiene, configHardening);
    const effectiveTrust = options.strict ? "unknown" : publisherTrust;
    const effectiveRisk = computeEffectiveRisk(
      capabilityImpact,
      effectiveTrust,
      installHygiene,
      configHardening,
      permissions,
      installRisks
    );
    const scoringTrace = generateScoringTrace(
      capabilityImpact,
      publisherTrust,
      installHygiene,
      configHardening,
      effectiveRisk,
      analysisConfidence,
      permissions,
      installRisks,
      profile
    );
    const serverLabel = {
      name,
      command: serverConfig.command,
      args: serverConfig.args || [],
      packageName,
      dockerImage,
      envVars: [
        ...redactEnvValues(serverConfig.env),
        ...Object.keys(serverConfig.requestInit?.headers || {}).map((h) => `[header] ${h}`)
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
      risk
    };
    if (options.policy) {
      serverLabel.policyResults = evaluatePolicy(serverLabel, options.policy);
    }
    servers.push(serverLabel);
  }
  const allRisks = servers.map((s) => s.risk);
  const allScores = servers.map((s) => s.score);
  const overallRisk = computeOverallRisk(allRisks);
  const overallGrade = computeOverallGrade(allScores);
  const totalFindings = servers.reduce(
    (sum, s) => sum + s.permissions.length + s.installRisks.length,
    0
  );
  const allPermissions = servers.flatMap((s) => s.permissions);
  const allInstallRisks = servers.flatMap((s) => s.installRisks);
  const topConcerns = summarizeConcerns(allPermissions, allInstallRisks, 5);
  const topMitigations = servers.flatMap((s) => s.saferConfigSuggestions.map((sug) => sug.title)).filter((v, i, a) => a.indexOf(v) === i).slice(0, 5);
  const impactOrder = ["critical", "high", "medium", "low"];
  const trustOrder = ["unknown", "low", "medium", "high"];
  const gradeOrder = ["F", "D", "C", "B", "A"];
  const confOrder = ["low", "medium", "high"];
  const worstImpact = impactOrder.find((l) => servers.some((s) => s.capabilityImpact === l)) ?? "low";
  const worstEffRisk = impactOrder.find((l) => servers.some((s) => s.effectiveRisk === l)) ?? "low";
  const worstTrust = trustOrder.find((l) => servers.some((s) => s.publisherTrust === l)) ?? "unknown";
  const worstInstHyg = gradeOrder.find((g) => servers.some((s) => s.installHygiene === g)) ?? "A";
  const worstConfHard = gradeOrder.find((g) => servers.some((s) => s.configHardening === g)) ?? "A";
  const worstHardGrade = gradeOrder.find((g) => servers.some((s) => s.hardeningGrade === g)) ?? "A";
  const lowestConf = confOrder.find((c) => servers.some((s) => s.analysisConfidence === c)) ?? "low";
  const report = {
    schemaVersion: "0.2",
    generatedAt: now(),
    source: {
      configPaths: options.configPaths,
      discovered: options.discovered,
      staticOnly: true
    },
    summary: {
      serverCount: servers.length,
      capabilityImpact: worstImpact,
      effectiveRisk: worstEffRisk,
      hardeningGrade: worstHardGrade,
      publisherTrust: worstTrust,
      installHygiene: worstInstHyg,
      configHardening: worstConfHard,
      analysisConfidence: lowestConf,
      totalFindings,
      topConcerns,
      topMitigations,
      // Legacy
      overallGrade,
      overallRisk,
      highestRisk: computeOverallRisk(allRisks)
    },
    servers
  };
  return report;
}
export {
  ConfidenceSchema,
  FindingExpectationSchema,
  FindingLevelSchema,
  InstallRiskSchema,
  KNOWN_SERVER_PROFILES,
  McpConfigFileSchema,
  McpLabelReportSchema,
  McpServerConfigSchema,
  PERMISSION_IDS,
  PermissionFindingSchema,
  PermissionIdSchema,
  PolicyFileSchema,
  PolicyResultSchema,
  PolicyRuleSchema,
  PublisherTrustSchema,
  RiskLevelSchema,
  SaferConfigSuggestionSchema,
  SafetyGradeSchema,
  ScoreAdjustmentSchema,
  ScoringTraceSchema,
  ServerLabelSchema,
  analyzeServer,
  computeAnalysisConfidence,
  computeCapabilityImpact,
  computeConfigHardening,
  computeEffectiveRisk,
  computeHardeningGrade,
  computeInstallHygiene,
  computeOverallGrade,
  computeOverallRisk,
  computeRisk,
  computeScore,
  discoverConfigFiles,
  evaluatePolicy,
  exportJson,
  exportMarkdown,
  exportSvg,
  exportTerminal,
  findKnownProfile,
  generateScoringTrace,
  getDiscoveryPaths,
  mergeConfigs,
  now,
  parseConfigFile,
  parsePolicyFile,
  redactEnvValues,
  scan,
  scoreToGrade,
  summarizeConcerns,
  unique
};
