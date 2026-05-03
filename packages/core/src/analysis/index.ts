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

import type {
  McpServerConfig,
  PermissionFinding,
  InstallRisk,
  SaferConfigSuggestion,
} from '../types.js';
import { redactEnvValues } from '../config/index.js';

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

const SECRET_PATTERN =
  /(TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL|PAT|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH)/i;

const BROAD_PATHS = ['/', '~', '$HOME', '/Users', '/home', '/root', '/var', '/etc', '/tmp'];

const FILESYSTEM_SIGNALS = ['filesystem', 'file', 'directory', 'folder', 'fs-server', 'local-files'];

const GITHUB_SERVER_SIGNALS = ['github-mcp', 'gh-mcp', 'github-mcp-server'];

const GITHUB_TOKEN_PATTERNS = [
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'GITHUB_PERSONAL_ACCESS_TOKEN',
  'GITHUB_PAT',
  'GH_PAT',
];

const GIT_URL_PATTERN = /git\+https?:\/\/github\.com\//i;

const BROWSER_SIGNALS = ['playwright', 'puppeteer', 'browser', 'chromium', 'selenium', 'cdp'];

// Known Playwright MCP package signals (package-based, not server-name-based)
const PLAYWRIGHT_MCP_PACKAGE_SIGNALS = [
  '@playwright/mcp',
  'playwright-mcp',
  'microsoft/playwright-mcp',
  'github.com/microsoft/playwright-mcp',
];

// Runner commands that can invoke packages dynamically
const DYNAMIC_RUNNER_COMMANDS = ['npx', 'pnpm', 'npm'];


const DATABASE_SIGNALS = [
  'postgres',
  'postgresql',
  'mysql',
  'mariadb',
  'mongodb',
  'mongo',
  'supabase',
  'neon',
  'planetscale',
  'sqlite',
  'clickhouse',
  'snowflake',
  'bigquery',
  'dynamodb',
  'cassandra',
];

const STATE_STORE_SIGNALS = ['redis'];

const CLOUD_SIGNALS = [
  'aws',
  'gcp',
  'google-cloud',
  'azure',
  'cloudflare',
  'vercel',
  'netlify',
  'kubernetes',
  'k8s',
  'terraform',
  'pulumi',
];

const EMAIL_SIGNALS = ['email', 'gmail', 'sendgrid', 'mailgun', 'ses', 'smtp', 'imap'];

const CALENDAR_SIGNALS = ['calendar', 'gcal', 'google-calendar'];

const PAYMENT_SIGNALS = ['stripe', 'paypal', 'braintree', 'square', 'payment', 'paymcp'];

const X402_SIGNALS = ['x402', 'paymcp-x402'];

const X402_ENV_PATTERNS = [
  'X402_PAY_TO_ADDRESS',
  'PAY_TO_ADDRESS',
  'PAYMENT_ADDRESS',
  'WALLET_ADDRESS',
];

const STRIPE_SECRET_PATTERNS = [
  'STRIPE_SECRET_KEY',
  'STRIPE_API_KEY',
];

const NETWORK_EGRESS_ENV_MAP: Record<string, string> = {
  'OPENAI_API_KEY': 'OpenAI APIs (api.openai.com)',
  'STRIPE_SECRET_KEY': 'Stripe APIs (api.stripe.com)',
  'STRIPE_API_KEY': 'Stripe APIs (api.stripe.com)',
  'WALLEOT_API_KEY': 'Walleot / external payment provider',
  'GITHUB_TOKEN': 'GitHub APIs (api.github.com)',
  'GH_TOKEN': 'GitHub APIs (api.github.com)',
  'GITHUB_PERSONAL_ACCESS_TOKEN': 'GitHub APIs (api.github.com)',
  'SUPABASE_URL': 'Supabase network access',
  'SUPABASE_KEY': 'Supabase network access',
  'SUPABASE_ANON_KEY': 'Supabase network access',
};

const SHELL_COMMANDS = ['bash', 'sh', 'zsh', 'fish', 'powershell', 'pwsh', 'cmd'];

const DB_CREDENTIAL_PATTERNS =
  /(DATABASE_URL|DB_PASSWORD|DB_HOST|MONGO_URI|REDIS_URL|PG_PASSWORD|MYSQL_PASSWORD)/i;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function textPool(name: string, config: McpServerConfig): string {
  const parts = [
    name,
    config.command || '',
    ...(config.args || []),
    ...Object.keys(config.env || {}),
    config.url || '',
    config.type || '',
    ...Object.keys(config.requestInit?.headers || {}),
  ];
  return parts.join(' ').toLowerCase();
}

function containsAny(text: string, signals: string[]): boolean {
  const lower = text.toLowerCase();
  return signals.some((s) => lower.includes(s.toLowerCase()));
}

function isAbsolutePath(arg: string): boolean {
  return arg.startsWith('/') || arg.startsWith('~') || arg.startsWith('$HOME');
}

function isBroadPath(arg: string): boolean {
  const normalized = arg.replace(/\/+$/, '') || '/';
  return BROAD_PATHS.some((p) => normalized === p || normalized === p + '/');
}

function isUserHomePath(arg: string): boolean {
  return /^(\/Users\/[^/]+|\/home\/[^/]+|~)$/.test(arg.replace(/\/+$/, ''));
}

/**
 * Check if the server actually has GitHub runtime capability
 * (not just a git install source).
 */
function hasGitHubRuntimeSignal(name: string, config: McpServerConfig): boolean {
  const envVars = Object.keys(config.env || {});
  const args = config.args || [];
  const command = config.command || '';

  // Check for GitHub token env vars
  const hasGitHubToken = envVars.some((v) =>
    GITHUB_TOKEN_PATTERNS.some((p) => v.toUpperCase() === p),
  );

  // Check server name or package name signals (but NOT git install URLs)
  const argsWithoutGitUrls = args.filter((a) => !GIT_URL_PATTERN.test(a));
  const textWithoutGitUrls = [name, command, ...argsWithoutGitUrls].join(' ').toLowerCase();
  const hasServerSignal = GITHUB_SERVER_SIGNALS.some((s) => textWithoutGitUrls.includes(s));

  // Must have either a GitHub token or a server name signal
  return hasGitHubToken || hasServerSignal;
}

// ---------------------------------------------------------------------------
// Permission Analyzers
// ---------------------------------------------------------------------------

export function analyzeSecrets(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const envVars = redactEnvValues(config.env);

  for (const varName of envVars) {
    if (SECRET_PATTERN.test(varName)) {
      findings.push({
        id: `secrets-env-${varName.toLowerCase()}`,
        permission: 'secrets.env',
        level: 'high',
        confidence: 'high',
        evidence: `Environment variable detected: ${varName}`,
        explanation: 'The server receives a secret or credential through its environment.',
        recommendation:
          'Use the least-privileged credential possible and rotate it if exposed.',
      });
    }
  }

  // Detect secrets in HTTP request headers (e.g. Authorization, X-*-PAT, X-*-TOKEN)
  const headers = config.requestInit?.headers;
  if (headers) {
    for (const headerName of Object.keys(headers)) {
      if (SECRET_PATTERN.test(headerName) || /^authorization$/i.test(headerName)) {
        findings.push({
          id: `secrets-header-${headerName.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
          permission: 'secrets.env',
          level: 'high',
          confidence: 'high',
          evidence: `HTTP header contains credential: ${headerName}`,
          explanation: 'The server receives a secret or credential through an HTTP request header.',
          recommendation:
            'Use the least-privileged credential possible and rotate it if exposed.',
        });
      }
    }
  }

  return findings;
}

export function analyzeFilesystem(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);
  const args = config.args || [];

  if (!containsAny(text, FILESYSTEM_SIGNALS)) {
    const pathArgs = args.filter((a) => isAbsolutePath(a));
    if (pathArgs.length === 0) return findings;
  }

  findings.push({
    id: 'filesystem-read',
    permission: 'filesystem.read',
    level: 'medium',
    confidence: 'medium',
    evidence: containsAny(text, FILESYSTEM_SIGNALS)
      ? `Filesystem signal detected in server configuration`
      : `Absolute path argument detected`,
    explanation: 'The server may read files from the local filesystem.',
    recommendation: 'Restrict filesystem access to the smallest project folder needed.',
  });

  const readOnlySignals = ['read-only', 'readonly', 'read_only', 'viewer'];
  if (!containsAny(text, readOnlySignals)) {
    findings.push({
      id: 'filesystem-write',
      permission: 'filesystem.write',
      level: 'high',
      confidence: 'medium',
      evidence: 'Filesystem MCP server detected without read-only signal',
      explanation: 'The server may modify or create files on the local filesystem.',
      recommendation: 'Use read-only mode if available, or restrict to a project folder.',
    });
  }

  for (const arg of args) {
    if (isBroadPath(arg) || isUserHomePath(arg)) {
      const readFinding = findings.find((f) => f.id === 'filesystem-read');
      if (readFinding) {
        readFinding.level = 'high';
        readFinding.confidence = 'high';
        readFinding.evidence = `Broad path argument: ${arg}`;
      }
    }
  }

  return findings;
}

export function analyzeGitHub(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];

  // Only emit repo.read/write when there is actual GitHub runtime capability
  if (!hasGitHubRuntimeSignal(name, config)) return findings;

  findings.push({
    id: 'repo-read',
    permission: 'repo.read',
    level: 'medium',
    confidence: 'medium',
    evidence: 'GitHub MCP server inferred from server name or GitHub token',
    explanation: 'The server likely has read access to repository data.',
  });

  findings.push({
    id: 'repo-write',
    permission: 'repo.write',
    level: 'high',
    confidence: 'medium',
    evidence: 'Possible write access inferred; token scope determines actual capabilities',
    explanation:
      'The server may be able to write to repositories if the token has write scopes.',
    recommendation:
      'Use a fine-grained GitHub token and prefer read-only scopes unless write actions are required.',
  });

  return findings;
}

// ---------------------------------------------------------------------------
// Known Server Detection
// ---------------------------------------------------------------------------

/**
 * Check if the server is the official Playwright MCP package,
 * based on package name in args (not server name).
 */
export function isPlaywrightMcp(name: string, config: McpServerConfig): boolean {
  const args = config.args || [];
  const command = config.command || '';
  const allText = [command, ...args].join(' ').toLowerCase();

  return PLAYWRIGHT_MCP_PACKAGE_SIGNALS.some((signal) =>
    allText.includes(signal.toLowerCase()),
  );
}

/**
 * Check if a specific CLI flag is present in args.
 */
function hasFlag(args: string[], flag: string): boolean {
  return args.some((a) => a === flag);
}

/**
 * Analyze known Playwright MCP server for specific capabilities.
 * Returns null if the server is not Playwright MCP.
 */
export function analyzePlaywrightMcp(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] | null {
  if (!isPlaywrightMcp(name, config)) return null;

  const findings: PermissionFinding[] = [];
  const args = config.args || [];

  // browser.control — always present when Playwright MCP is detected
  findings.push({
    id: 'playwright-browser-control',
    permission: 'browser.control',
    level: 'high',
    confidence: 'high',
    evidence: 'Known Playwright MCP package detected: @playwright/mcp',
    explanation:
      'Playwright MCP gives the model browser automation capabilities such as navigation, clicking, typing, form filling, screenshots, and tab interactions.',
    recommendation:
      'Use an isolated browser profile and avoid sensitive logged-in sessions.',
  });

  // network.fetch — always present
  const hasAllowedOrigins = args.some((a) => a === '--allowed-origins');
  const hasBlockedOrigins = args.some((a) => a === '--blocked-origins');
  const networkRec = hasAllowedOrigins || hasBlockedOrigins
    ? 'Verify the configured origin allowlist/blocklist is sufficiently narrow.'
    : 'Use --allowed-origins or --blocked-origins to constrain browser network access.';
  findings.push({
    id: 'playwright-network-fetch',
    permission: 'network.fetch',
    level: 'medium',
    confidence: 'high',
    evidence:
      'Playwright browser automation can navigate to URLs and make browser network requests.',
    explanation:
      'The server can access network resources through browser navigation and page interactions.',
    recommendation: networkRec,
  });

  // code.execution — documented unsafe tool (browser_run_code_unsafe)
  findings.push({
    id: 'playwright-run-code-unsafe',
    permission: 'code.execution',
    level: 'critical',
    confidence: 'high',
    evidence: 'Documented Playwright MCP tool: browser_run_code_unsafe',
    explanation:
      'Playwright MCP documents an unsafe tool (browser_run_code_unsafe) that can run Playwright code in the server process. This is a well-known, Microsoft-maintained package; the tool exists for advanced use cases but should be treated as RCE-equivalent unless disabled by policy or client-side tool allowlisting.',
    recommendation:
      'Require explicit approval for this tool, disable it via client tool allowlists, or avoid enabling it in sensitive environments.',
  });

  // browser.session_persistence — only when --isolated is absent
  if (!hasFlag(args, '--isolated')) {
    findings.push({
      id: 'playwright-session-persistence',
      permission: 'browser.session_persistence',
      level: 'medium',
      confidence: 'high',
      evidence: 'No --isolated option found in Playwright MCP configuration.',
      explanation:
        'The browser profile may persist cookies, local storage, and login state between sessions unless isolated mode is used.',
      recommendation:
        'Add --isolated unless persistent login state is intentionally required.',
    });
  }

  // filesystem — file upload/drop interactions
  // Escalated to filesystem.read + high when --allow-unrestricted-file-access is present
  if (hasFlag(args, '--allow-unrestricted-file-access')) {
    findings.push({
      id: 'playwright-unrestricted-file-access',
      permission: 'filesystem.read',
      level: 'high',
      confidence: 'high',
      evidence: '--allow-unrestricted-file-access flag detected',
      explanation:
        'Unrestricted file access was explicitly enabled for browser navigation via file:// URLs.',
      recommendation:
        'Remove --allow-unrestricted-file-access unless it is required and tightly controlled.',
    });
  } else {
    findings.push({
      id: 'playwright-file-upload-paths',
      permission: 'filesystem.read_possible',
      level: 'medium',
      confidence: 'medium',
      evidence:
        'Playwright MCP supports browser file upload/drop style interactions.',
      explanation:
        'Some browser file interactions can reference local file paths. This is not the same as unrestricted filesystem access.',
      recommendation:
        'Avoid exposing sensitive files through upload/drop tools and review any configured file access flags.',
    });
  }

  // network unrestricted by config — informational config note when neither origin control is present
  // This is NOT a separate network.fetch finding; the network.fetch finding above already covers it.
  // Instead we just add a recommendation via the existing network.fetch finding.
  // (No additional finding emitted — the recommendation is already in the network.fetch finding above)

  return findings;
}

export function analyzeBrowser(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);

  if (!containsAny(text, BROWSER_SIGNALS)) return findings;

  findings.push({
    id: 'browser-control',
    permission: 'browser.control',
    level: 'high',
    confidence: 'high',
    evidence: 'Browser automation signal detected',
    explanation: 'The server can control a browser instance.',
    recommendation: 'Use an isolated browser profile and avoid sensitive logged-in sessions.',
  });

  findings.push({
    id: 'browser-network',
    permission: 'network.fetch',
    level: 'medium',
    confidence: 'medium',
    evidence: 'Browser automation implies network access',
    explanation: 'The server can make network requests through the browser.',
  });

  return findings;
}

export function analyzeDatabase(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);

  // Check for state-store (Redis) separately
  const isStateStore = containsAny(text, STATE_STORE_SIGNALS);
  const isDatabase = containsAny(text, DATABASE_SIGNALS) && !isStateStore;

  if (!isDatabase && !isStateStore) return findings;

  if (isStateStore) {
    // Redis / state-store: use more precise classification
    findings.push({
      id: 'database-query',
      permission: 'database.query',
      level: 'medium',
      confidence: 'medium',
      evidence: 'State-store (Redis) signal detected',
      explanation: 'Possible database or state-store read access inferred.',
    });

    const readOnlySignals = ['read-only', 'readonly', 'read_only', 'viewer', 'query-only'];
    if (!containsAny(text, readOnlySignals)) {
      findings.push({
        id: 'database-mutate',
        permission: 'database.mutate',
        level: 'medium',
        confidence: 'medium',
        evidence: 'State-store access without read-only signal',
        explanation: 'Possible database or state-store write access inferred; no read-only signal was found.',
        recommendation: 'Use read-only database credentials where possible.',
      });
    }
  } else {
    // Regular database
    findings.push({
      id: 'database-query',
      permission: 'database.query',
      level: 'medium',
      confidence: 'medium',
      evidence: 'Database service signal detected',
      explanation: 'The server can query a database.',
    });

    const readOnlySignals = ['read-only', 'readonly', 'read_only', 'viewer', 'query-only'];
    if (!containsAny(text, readOnlySignals)) {
      findings.push({
        id: 'database-mutate',
        permission: 'database.mutate',
        level: 'high',
        confidence: 'low',
        evidence: 'Database access without read-only signal',
        explanation: 'Possible database write access inferred; no read-only signal was found.',
        recommendation: 'Use read-only database credentials where possible.',
      });
    }
  }

  return findings;
}

export function analyzeCloud(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);

  if (!containsAny(text, CLOUD_SIGNALS)) return findings;

  findings.push({
    id: 'cloud-read',
    permission: 'cloud.read',
    level: 'medium',
    confidence: 'medium',
    evidence: 'Cloud service signal detected',
    explanation: 'The server may read cloud resources.',
  });

  const adminSignals = ['admin', 'full-access', 'root', 'superuser'];
  if (containsAny(text, adminSignals)) {
    findings.push({
      id: 'cloud-admin',
      permission: 'cloud.admin',
      level: 'critical',
      confidence: 'medium',
      evidence: 'Cloud admin signal detected',
      explanation: 'The server may have administrative access to cloud resources.',
      recommendation: 'Use the least-privileged IAM role or policy.',
    });
  } else {
    findings.push({
      id: 'cloud-write',
      permission: 'cloud.write',
      level: 'high',
      confidence: 'low',
      evidence: 'Cloud access without read-only signal',
      explanation: 'The server may be able to modify cloud resources.',
      recommendation: 'Use read-only cloud credentials where possible.',
    });
  }

  return findings;
}

export function analyzeEmail(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);

  if (!containsAny(text, EMAIL_SIGNALS)) return findings;

  findings.push({
    id: 'email-read',
    permission: 'email.read',
    level: 'medium',
    confidence: 'medium',
    evidence: 'Email service signal detected',
    explanation: 'The server may read email messages.',
  });

  const sendSignals = ['send', 'compose', 'smtp', 'sendgrid', 'mailgun', 'ses'];
  if (containsAny(text, sendSignals)) {
    findings.push({
      id: 'email-send',
      permission: 'email.send',
      level: 'high',
      confidence: 'medium',
      evidence: 'Email send capability inferred',
      explanation: 'The server may send emails.',
      recommendation: 'Restrict email sending capabilities and review email templates.',
    });
  }

  return findings;
}

export function analyzeCalendar(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);

  if (!containsAny(text, CALENDAR_SIGNALS)) return findings;

  findings.push({
    id: 'calendar-read',
    permission: 'calendar.read',
    level: 'low',
    confidence: 'medium',
    evidence: 'Calendar service signal detected',
    explanation: 'The server may read calendar events.',
  });

  return findings;
}

export function analyzePayments(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);
  const envVars = redactEnvValues(config.env);

  const hasPaymentSignal = containsAny(text, PAYMENT_SIGNALS);
  const hasStripeSecret = envVars.some((v) =>
    STRIPE_SECRET_PATTERNS.some((p) => v.toUpperCase() === p),
  );

  if (!hasPaymentSignal && !hasStripeSecret) return findings;

  // Stripe secret key detection
  if (hasStripeSecret) {
    findings.push({
      id: 'payments-read',
      permission: 'payments.read',
      level: 'high',
      confidence: 'high',
      evidence: 'Stripe secret key detected in environment',
      explanation: 'The server has access to payment data via Stripe credentials.',
    });

    findings.push({
      id: 'payments-charge-possible',
      permission: 'payments.charge',
      level: 'critical',
      confidence: 'medium',
      evidence: 'Stripe secret credentials detected',
      explanation: 'Possible payment charge/write capability inferred from Stripe secret credentials. Actual operations depend on key restrictions and server code.',
      recommendation: 'Use restricted API keys, enable webhook verification, and limit key permissions to the minimum required.',
    });
  } else if (hasPaymentSignal) {
    findings.push({
      id: 'payments-read',
      permission: 'payments.read',
      level: 'high',
      confidence: 'medium',
      evidence: 'Payment service signal inferred from server name or configuration',
      explanation: 'The server may access payment data.',
    });
  }

  return findings;
}

export function analyzeX402(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const text = textPool(name, config);
  const envVars = redactEnvValues(config.env);

  const hasX402Signal = containsAny(text, X402_SIGNALS);
  const hasX402Env = envVars.some((v) =>
    X402_ENV_PATTERNS.some((p) => v.toUpperCase() === p),
  );

  if (!hasX402Signal && !hasX402Env) return findings;

  findings.push({
    id: 'payment-protocol-x402',
    permission: 'payment_protocol.x402',
    level: 'medium',
    confidence: 'high',
    evidence: hasX402Env
      ? `x402 payment protocol inferred from environment variables`
      : 'x402 payment protocol inferred from server name or configuration',
    explanation: 'The server appears to use the x402 payment protocol.',
    recommendation: 'Review payment flow, wallet/address configuration, and user approval behavior.',
  });

  if (hasX402Env) {
    findings.push({
      id: 'payments-receive',
      permission: 'payments.receive',
      level: 'medium',
      confidence: 'high',
      evidence: `Payment address environment variable detected`,
      explanation: 'The server appears configured to receive or request payments using an x402-style payment address.',
      recommendation: 'Verify the receiving address, payment limits, and whether the server can initiate payment-gated actions.',
    });
  }

  return findings;
}

export function analyzeNetworkEgress(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const envVars = redactEnvValues(config.env);
  const emittedServices = new Set<string>();

  for (const varName of envVars) {
    const upperVar = varName.toUpperCase();

    // Check direct matches
    const service = NETWORK_EGRESS_ENV_MAP[upperVar];
    if (service && !emittedServices.has(service)) {
      emittedServices.add(service);
      findings.push({
        id: `network-egress-${varName.toLowerCase()}`,
        permission: 'network.egress',
        level: 'medium',
        confidence: 'medium',
        evidence: `Environment variable detected: ${varName}`,
        explanation: `The server likely connects to ${service}.`,
        recommendation: 'Confirm expected outbound domains and avoid sending sensitive data unnecessarily.',
      });
    }

    // Check for x402/payment protocol network egress
    if (X402_ENV_PATTERNS.some((p) => upperVar === p) && !emittedServices.has('x402-payment')) {
      emittedServices.add('x402-payment');
      findings.push({
        id: `network-egress-x402`,
        permission: 'network.egress',
        level: 'medium',
        confidence: 'medium',
        evidence: `x402 payment environment variable detected: ${varName}`,
        explanation: 'The server may connect to external payment endpoints via x402 protocol.',
        recommendation: 'Confirm expected outbound payment domains.',
      });
    }

    // Check prefixes for Supabase, etc.
    if (upperVar.startsWith('SUPABASE_') && !emittedServices.has('supabase')) {
      emittedServices.add('supabase');
      findings.push({
        id: `network-egress-supabase`,
        permission: 'network.egress',
        level: 'medium',
        confidence: 'medium',
        evidence: `Environment variable detected: ${varName}`,
        explanation: 'The server likely connects to Supabase.',
        recommendation: 'Confirm expected outbound domains and avoid sending sensitive data unnecessarily.',
      });
    }
  }

  return findings;
}

export function analyzeShellExecution(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  const command = config.command || '';
  const args = config.args || [];
  const argsStr = args.join(' ');

  if (SHELL_COMMANDS.includes(command.toLowerCase())) {
    findings.push({
      id: 'shell-execute',
      permission: 'shell.execute',
      level: 'critical',
      confidence: 'high',
      evidence: `Shell command detected: ${command}`,
      explanation: 'The server uses a shell command, which can execute arbitrary code.',
      recommendation: 'Avoid shell commands in MCP server configurations where possible.',
    });
    return findings;
  }

  if (args.some((a) => a === '-c') && containsAny(argsStr, ['bash', 'sh', 'zsh'])) {
    findings.push({
      id: 'shell-execute-args',
      permission: 'shell.execute',
      level: 'high',
      confidence: 'high',
      evidence: `Shell execution in args: ${command} ${args.slice(0, 4).join(' ')}`,
      explanation: 'Arguments include shell execution flags.',
      recommendation: 'Replace shell commands with direct program execution.',
    });
  }

  const text = textPool(name, config);
  const shellNameSignals = ['shell', 'terminal', 'exec', 'command-runner'];
  if (containsAny(text, shellNameSignals)) {
    findings.push({
      id: 'shell-execute-name',
      permission: 'shell.execute',
      level: 'high',
      confidence: 'medium',
      evidence: `Shell/terminal signal in server name or package`,
      explanation: 'The server appears to provide shell execution capabilities.',
      recommendation: 'Review the server carefully and sandbox if possible.',
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Install Risk Analyzers
// ---------------------------------------------------------------------------

export function analyzeDockerRisks(
  name: string,
  config: McpServerConfig,
): { risks: InstallRisk[]; image?: string } {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  if (command.toLowerCase() !== 'docker') return { risks };

  // Extract image name (last arg that looks like an image)
  let image: string | undefined;
  for (let i = args.length - 1; i >= 0; i--) {
    const arg = args[i];
    if (
      arg &&
      !arg.startsWith('-') &&
      !arg.startsWith('/') &&
      arg !== 'run' &&
      arg !== '-i' &&
      arg !== '--rm' &&
      arg !== '-e' &&
      !args[i - 1]?.startsWith('-e') &&
      (arg.includes('/') || arg.includes(':'))
    ) {
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
    if (image.endsWith(':latest')) {
      risks.push({
        id: 'docker-latest',
        level: 'medium',
        confidence: 'high',
        evidence: image,
        explanation: 'The Docker image uses the :latest tag, which can change over time.',
        recommendation: 'Pin Docker images to explicit versions or immutable digests.',
      });
    } else if (!image.includes(':') && !image.includes('@sha256:')) {
      risks.push({
        id: 'docker-untagged',
        level: 'medium',
        confidence: 'high',
        evidence: image,
        explanation: 'The Docker image has no explicit tag, defaulting to :latest.',
        recommendation: 'Pin Docker images to explicit versions or immutable digests.',
      });
    }
  }

  if (args.includes('--privileged')) {
    risks.push({
      id: 'docker-privileged',
      level: 'critical',
      confidence: 'high',
      evidence: '--privileged flag detected',
      explanation:
        'The Docker container runs in privileged mode with full host access.',
      recommendation: 'Remove --privileged and use specific capabilities instead.',
    });
  }

  if (args.includes('--network') && args[args.indexOf('--network') + 1] === 'host') {
    risks.push({
      id: 'docker-host-network',
      level: 'high',
      confidence: 'high',
      evidence: '--network host',
      explanation: 'The Docker container shares the host network stack.',
      recommendation: 'Use bridge networking or a custom network instead.',
    });
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-v' || args[i] === '--volume') {
      const mount = args[i + 1] || '';
      const hostPath = mount.split(':')[0];
      if (hostPath && (isBroadPath(hostPath) || hostPath === '.')) {
        risks.push({
          id: 'docker-broad-mount',
          level: 'high',
          confidence: 'high',
          evidence: `Volume mount: ${mount}`,
          explanation: 'A broad host path is mounted into the container.',
          recommendation: 'Mount only the specific directories needed.',
        });
      }
    }
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-e') {
      const envName = args[i + 1];
      if (envName && SECRET_PATTERN.test(envName)) {
        risks.push({
          id: `docker-secret-env-${envName.toLowerCase()}`,
          level: 'high',
          confidence: 'high',
          evidence: `Secret passed through Docker env: ${envName}`,
          explanation: 'A secret is passed to the Docker container via environment variable.',
          recommendation: 'Use Docker secrets or a secrets manager instead.',
        });
      }
    }
  }

  return { risks, image };
}

export function analyzeNpxRisks(
  name: string,
  config: McpServerConfig,
): { risks: InstallRisk[]; packageName?: string } {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  if (command.toLowerCase() !== 'npx') return { risks };

  let packageName: string | undefined;
  for (const arg of args) {
    if (arg.startsWith('-')) continue;
    if (arg.startsWith('/') || arg.startsWith('.')) continue;
    packageName = arg;
    break;
  }

  if (packageName) {
    if (packageName.includes('@latest')) {
      risks.push({
        id: 'npx-latest',
        level: 'medium',
        confidence: 'high',
        evidence: packageName,
        explanation: 'The npx package uses @latest, which can change over time.',
        recommendation: `Pin the package to a specific version, for example ${packageName.replace(/@latest$/, '')}@<version>.`,
      });
    } else if (!packageName.match(/@[\d^~]/)) {
      risks.push({
        id: 'npx-unpinned',
        level: 'medium',
        confidence: 'high',
        evidence: packageName,
        explanation: 'The npx package is not pinned to a specific version.',
        recommendation: `Pin the package to a specific version, for example ${packageName}@<version>.`,
      });
    }
  }

  return { risks, packageName };
}

export function analyzePnpmDlxRisks(
  name: string,
  config: McpServerConfig,
): { risks: InstallRisk[]; packageName?: string } {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  // Detect "pnpm dlx" or "pnpm exec"
  const isPnpm = command.toLowerCase() === 'pnpm';
  const hasDlxOrExec = args.some((a) => a === 'dlx' || a === 'exec');
  if (!isPnpm || !hasDlxOrExec) return { risks };

  let packageName: string | undefined;
  let pastDlx = false;
  for (const arg of args) {
    if (arg === 'dlx' || arg === 'exec') { pastDlx = true; continue; }
    if (!pastDlx) continue;
    if (arg.startsWith('-')) continue;
    packageName = arg;
    break;
  }

  if (packageName) {
    if (packageName.includes('@latest')) {
      risks.push({
        id: 'npx-latest',
        level: 'medium',
        confidence: 'high',
        evidence: packageName,
        explanation: 'The pnpm dlx package uses @latest, which can change over time.',
        recommendation: `Pin the package to a specific version, for example ${packageName.replace(/@latest$/, '')}@<version>.`,
      });
    } else if (!packageName.match(/@[\d^~]/)) {
      risks.push({
        id: 'npx-unpinned',
        level: 'medium',
        confidence: 'high',
        evidence: packageName,
        explanation: 'The pnpm dlx package is not pinned to a specific version.',
        recommendation: `Pin the package to a specific version, for example ${packageName}@<version>.`,
      });
    }
  }

  return { risks, packageName };
}

export function analyzeNpmExecRisks(
  name: string,
  config: McpServerConfig,
): { risks: InstallRisk[]; packageName?: string } {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  // Detect "npm exec"
  const isNpm = command.toLowerCase() === 'npm';
  const hasExec = args.some((a) => a === 'exec');
  if (!isNpm || !hasExec) return { risks };

  let packageName: string | undefined;
  let pastExec = false;
  for (const arg of args) {
    if (arg === 'exec') { pastExec = true; continue; }
    if (!pastExec) continue;
    if (arg.startsWith('-')) continue;
    packageName = arg;
    break;
  }

  if (packageName) {
    if (packageName.includes('@latest')) {
      risks.push({
        id: 'npx-latest',
        level: 'medium',
        confidence: 'high',
        evidence: packageName,
        explanation: 'The npm exec package uses @latest, which can change over time.',
        recommendation: `Pin the package to a specific version, for example ${packageName.replace(/@latest$/, '')}@<version>.`,
      });
    } else if (!packageName.match(/@[\d^~]/)) {
      risks.push({
        id: 'npx-unpinned',
        level: 'medium',
        confidence: 'high',
        evidence: packageName,
        explanation: 'The npm exec package is not pinned to a specific version.',
        recommendation: `Pin the package to a specific version, for example ${packageName}@<version>.`,
      });
    }
  }

  return { risks, packageName };
}

export function analyzeUvxRisks(
  name: string,
  config: McpServerConfig,
): { risks: InstallRisk[] } {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  if (command.toLowerCase() !== 'uvx') return { risks };

  // Check for --from git+https://... pattern
  const fromIdx = args.indexOf('--from');
  if (fromIdx !== -1 && fromIdx + 1 < args.length) {
    const fromValue = args[fromIdx + 1];
    if (GIT_URL_PATTERN.test(fromValue) || fromValue.startsWith('git+')) {
      // This is a remote Git source via uvx
      risks.push(...analyzeRemoteGitUrl(fromValue));
      risks.push({
        id: 'uvx-remote-source',
        level: 'high',
        confidence: 'high',
        evidence: fromValue,
        explanation: 'The uvx package is installed from a remote Git repository.',
        recommendation: 'Prefer a pinned release or package version.',
      });
      return { risks };
    }

    // --from with a package name
    const pkg = fromValue;
    if (!pkg.includes('==') && !pkg.includes('>=') && !pkg.match(/@[\d^~]/)) {
      risks.push({
        id: 'uvx-unpinned',
        level: 'medium',
        confidence: 'high',
        evidence: pkg,
        explanation: 'The uvx package is not pinned to a specific version.',
        recommendation: 'Pin package versions (e.g., package==1.2.3).',
      });
    }
    return { risks };
  }

  // No --from: first non-flag arg is the package
  let packageName: string | undefined;
  for (const arg of args) {
    if (arg.startsWith('-')) continue;
    packageName = arg;
    break;
  }

  if (packageName && !packageName.includes('==') && !packageName.includes('>=')) {
    risks.push({
      id: 'uvx-unpinned',
      level: 'medium',
      confidence: 'high',
      evidence: packageName,
      explanation: 'The uvx package is not pinned to a specific version.',
      recommendation: 'Pin package versions (e.g., package==1.2.3).',
    });
  }

  return { risks };
}

/**
 * Analyze a remote Git URL for install risks.
 */
function analyzeRemoteGitUrl(url: string): InstallRisk[] {
  const risks: InstallRisk[] = [];

  risks.push({
    id: 'remote-git-source',
    level: 'medium',
    confidence: 'high',
    evidence: url,
    explanation: 'The server is installed from a remote Git repository.',
    recommendation: 'Prefer a pinned release, package version, or commit SHA.',
  });

  // Check pinning: @sha, @tag, @branch
  const atIdx = url.lastIndexOf('@');
  const hasAtPin = atIdx > url.lastIndexOf('/');

  if (!hasAtPin) {
    risks.push({
      id: 'remote-git-unpinned',
      level: 'high',
      confidence: 'high',
      evidence: url,
      explanation: 'The Git source is not pinned to a commit SHA or release tag.',
      recommendation: 'Pin the Git dependency to a commit SHA or signed release tag.',
    });
  } else {
    const ref = url.substring(atIdx + 1);
    // Check if it's a commit SHA (40 hex chars or short form 7+)
    const isSha = /^[0-9a-f]{7,40}$/i.test(ref);
    // Check if it looks like a version tag
    const isVersionTag = /^v?\d+\.\d+/.test(ref);

    if (!isSha && !isVersionTag) {
      // Branch ref - weaker pin
      risks.push({
        id: 'remote-git-branch-ref',
        level: 'medium',
        confidence: 'high',
        evidence: url,
        explanation: `The Git source is pinned to a branch ref (${ref}), which can change over time.`,
        recommendation: 'Prefer pinning to a commit SHA or signed release tag.',
      });
    }
  }

  return risks;
}

/**
 * Analyze remote Git URLs in args (outside of uvx --from).
 */
export function analyzeRemoteGitRisks(
  name: string,
  config: McpServerConfig,
): InstallRisk[] {
  const risks: InstallRisk[] = [];
  const args = config.args || [];

  for (const arg of args) {
    if (GIT_URL_PATTERN.test(arg) || (arg.startsWith('git+') && arg.includes('://'))) {
      risks.push(...analyzeRemoteGitUrl(arg));
    }
  }

  return risks;
}

/**
 * Detect unpinned `uv --with` dependencies.
 */
export function analyzeUvWithRisks(
  name: string,
  config: McpServerConfig,
): InstallRisk[] {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  if (command.toLowerCase() !== 'uv') return risks;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--with' && i + 1 < args.length) {
      const dep = args[i + 1];
      // Check if pinned
      if (!dep.includes('==') && !dep.includes('>=') && !dep.includes('~=') && !dep.match(/@[\d^~]/)) {
        risks.push({
          id: 'uv-with-unpinned',
          level: 'medium',
          confidence: 'high',
          evidence: `--with ${dep}`,
          explanation: 'A runtime dependency is installed without a fixed version.',
          recommendation: `Pin runtime dependencies, for example: --with ${dep}==<version>`,
        });
      }
    }
  }

  return risks;
}

export function analyzeCurlPipeRisks(
  name: string,
  config: McpServerConfig,
): InstallRisk[] {
  const risks: InstallRisk[] = [];
  const args = config.args || [];
  const argsStr = args.join(' ');

  if (
    (argsStr.includes('curl') || argsStr.includes('wget')) &&
    (argsStr.includes('bash') || argsStr.includes('sh')) &&
    argsStr.includes('|')
  ) {
    risks.push({
      id: 'curl-pipe-shell',
      level: 'critical',
      confidence: 'high',
      evidence: argsStr.substring(0, 100),
      explanation: 'A remote script is piped directly into a shell for execution.',
      recommendation: 'Download scripts first, inspect them, then execute.',
    });
  }

  return risks;
}

export function analyzeLocalScriptRisks(
  name: string,
  config: McpServerConfig,
): InstallRisk[] {
  const risks: InstallRisk[] = [];
  const command = config.command || '';
  const args = config.args || [];

  if (command.match(/\.(sh|bash|py|js|ts)$/) || args.some((a) => a.match(/\.(sh|bash|py|js|ts)$/))) {
    const scriptFile = command.match(/\.(sh|bash|py|js|ts)$/) ? command : args.find((a) => a.match(/\.(sh|bash|py|js|ts)$/)) || '';
    risks.push({
      id: 'local-script',
      level: 'medium',
      confidence: 'medium',
      evidence: scriptFile,
      explanation: 'The MCP server runs a local script. Static config analysis cannot verify the script contents.',
      recommendation: 'Review the script contents and dependencies before enabling the server.',
    });
  }

  return risks;
}

// ---------------------------------------------------------------------------
// Safer Config Suggestions
// ---------------------------------------------------------------------------

export function generateSaferSuggestions(
  name: string,
  config: McpServerConfig,
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
): SaferConfigSuggestion[] {
  const suggestions: SaferConfigSuggestion[] = [];

  for (const risk of installRisks) {
    if (risk.id === 'docker-latest' || risk.id === 'docker-untagged') {
      suggestions.push({
        id: 'pin-docker-image',
        title: 'Pin Docker image version',
        explanation:
          'Replace :latest or untagged images with an explicit version or immutable digest.',
        before: risk.evidence,
        after: `${risk.evidence.split(':')[0]}:<specific-version>`,
        confidence: 'high',
      });
    }
  }

  for (const risk of installRisks) {
    if (risk.id === 'npx-unpinned' || risk.id === 'npx-latest') {
      suggestions.push({
        id: 'pin-npx-package',
        title: 'Pin package version',
        explanation: 'Pin the npx package to a specific version for reproducible installs.',
        before: risk.evidence,
        after: `${risk.evidence.replace(/@latest$/, '')}@<specific-version>`,
        confidence: 'high',
      });
    }
  }

  for (const finding of permissions) {
    if (
      finding.permission === 'filesystem.read' &&
      finding.evidence.includes('Broad path argument')
    ) {
      const path = finding.evidence.replace('Broad path argument: ', '');
      suggestions.push({
        id: 'restrict-filesystem-path',
        title: 'Restrict filesystem path',
        explanation: 'Restrict file access to the smallest project folder needed.',
        before: path,
        after: `${path}/projects/current-app`,
        confidence: 'high',
      });
    }
  }

  for (const finding of permissions) {
    if (finding.permission === 'repo.write') {
      suggestions.push({
        id: 'use-fine-grained-token',
        title: 'Use a fine-grained GitHub token',
        explanation:
          'Fine-grained personal access tokens allow scoping permissions to specific repositories and actions.',
        confidence: 'medium',
      });
      break;
    }
  }

  for (const risk of installRisks) {
    if (risk.id === 'docker-privileged') {
      suggestions.push({
        id: 'remove-privileged',
        title: 'Remove --privileged flag',
        explanation: 'Run containers without privileged mode. Use specific --cap-add flags if needed.',
        before: '--privileged',
        after: '--cap-add=<SPECIFIC_CAPABILITY>',
        confidence: 'high',
      });
    }
  }

  for (const risk of installRisks) {
    if (risk.id === 'docker-host-network') {
      suggestions.push({
        id: 'avoid-host-network',
        title: 'Avoid host networking',
        explanation: 'Use bridge networking or expose only the specific ports needed.',
        before: '--network host',
        after: '-p <host-port>:<container-port>',
        confidence: 'high',
      });
    }
  }

  for (const risk of installRisks) {
    if (risk.id === 'remote-git-unpinned' || risk.id === 'remote-git-branch-ref') {
      suggestions.push({
        id: 'pin-git-dependency',
        title: 'Pin Git dependency to commit SHA or tag',
        explanation: 'Pin remote Git dependencies to a commit SHA or signed release tag for reproducible installs.',
        before: risk.evidence,
        after: `${risk.evidence}@<commit-sha-or-tag>`,
        confidence: 'high',
      });
      break;
    }
  }

  // Playwright MCP-specific suggestions
  if (permissions.some((p) => p.id === 'playwright-session-persistence')) {
    suggestions.push({
      id: 'playwright-add-isolated',
      title: 'Use isolated browser mode',
      explanation:
        'Add --isolated to prevent browser state (cookies, login sessions, local storage) from persisting between runs.',
      after: 'npx @playwright/mcp@<version> --isolated',
      confidence: 'high',
    });
  }

  if (permissions.some((p) => p.id === 'playwright-network-fetch' && p.recommendation?.includes('--allowed-origins'))) {
    suggestions.push({
      id: 'playwright-add-origin-controls',
      title: 'Restrict browser origins',
      explanation:
        'Configure --allowed-origins or --blocked-origins to limit which sites the browser can navigate to.',
      after: 'npx @playwright/mcp@<version> --allowed-origins https://example.com',
      confidence: 'medium',
    });
  }

  if (permissions.some((p) => p.id === 'playwright-unrestricted-file-access')) {
    suggestions.push({
      id: 'playwright-remove-unrestricted-file-access',
      title: 'Remove unrestricted file access',
      explanation:
        'The --allow-unrestricted-file-access flag grants broad file:// access. Remove it unless specifically required.',
      before: '--allow-unrestricted-file-access',
      after: '(remove this flag)',
      confidence: 'high',
    });
  }

  return suggestions;
}

// ---------------------------------------------------------------------------
// Main Analysis
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// HTTP/SSE Server Analysis
// ---------------------------------------------------------------------------

/**
 * Analyze HTTP-based MCP servers (type: http, sse, streamable-http).
 * These connect to a remote URL rather than running a local command.
 */
export function analyzeHttpServer(
  name: string,
  config: McpServerConfig,
): PermissionFinding[] {
  if (!config.url) return [];

  const findings: PermissionFinding[] = [];
  let url: URL;
  try {
    url = new URL(config.url);
  } catch {
    findings.push({
      id: 'http-invalid-url',
      permission: 'network.fetch',
      level: 'medium',
      confidence: 'medium',
      evidence: `Invalid URL: ${config.url}`,
      explanation: 'The server URL could not be parsed.',
    });
    return findings;
  }

  findings.push({
    id: 'http-remote-server',
    permission: 'network.fetch',
    level: 'medium',
    confidence: 'high',
    evidence: `Remote MCP server at ${url.hostname}`,
    explanation: `The server connects to a remote HTTP endpoint. Data sent to this server leaves your machine.`,
    recommendation: 'Verify you trust the remote endpoint and understand what data is sent to it.',
  });

  if (url.protocol === 'http:') {
    findings.push({
      id: 'http-insecure',
      permission: 'network.fetch',
      level: 'high',
      confidence: 'high',
      evidence: `Insecure HTTP URL: ${config.url}`,
      explanation: 'The server uses unencrypted HTTP. Credentials and data can be intercepted.',
      recommendation: 'Use HTTPS instead of HTTP.',
    });
  }

  return findings;
}

export function analyzeServer(
  name: string,
  config: McpServerConfig,
): {
  permissions: PermissionFinding[];
  installRisks: InstallRisk[];
  recommendations: string[];
  saferConfigSuggestions: SaferConfigSuggestion[];
  packageName?: string;
  dockerImage?: string;
} {
  // Gather all permission findings
  // Check for known servers first (Playwright MCP), then fall back to generic analyzers
  const playwrightFindings = analyzePlaywrightMcp(name, config);
  const permissions: PermissionFinding[] = [
    ...analyzeSecrets(name, config),
    ...analyzeHttpServer(name, config),
    ...analyzeFilesystem(name, config),
    ...analyzeGitHub(name, config),
    // Use Playwright MCP-specific findings if detected, otherwise generic browser analysis
    ...(playwrightFindings ?? analyzeBrowser(name, config)),
    ...analyzeDatabase(name, config),
    ...analyzeCloud(name, config),
    ...analyzeEmail(name, config),
    ...analyzeCalendar(name, config),
    ...analyzePayments(name, config),
    ...analyzeX402(name, config),
    ...analyzeNetworkEgress(name, config),
    ...analyzeShellExecution(name, config),
  ];

  // Gather all install risks
  const dockerResult = analyzeDockerRisks(name, config);
  const npxResult = analyzeNpxRisks(name, config);
  const pnpmResult = analyzePnpmDlxRisks(name, config);
  const npmResult = analyzeNpmExecRisks(name, config);
  const uvxResult = analyzeUvxRisks(name, config);

  const installRisks: InstallRisk[] = [
    ...dockerResult.risks,
    ...npxResult.risks,
    ...pnpmResult.risks,
    ...npmResult.risks,
    ...uvxResult.risks,
    ...analyzeRemoteGitRisks(name, config),
    ...analyzeUvWithRisks(name, config),
    ...analyzeCurlPipeRisks(name, config),
    ...analyzeLocalScriptRisks(name, config),
  ];

  // Generate recommendations from findings
  const recommendations = generateRecommendations(permissions, installRisks);

  // Generate safer config suggestions
  const saferConfigSuggestions = generateSaferSuggestions(
    name,
    config,
    permissions,
    installRisks,
  );

  return {
    permissions,
    installRisks,
    recommendations,
    saferConfigSuggestions,
    packageName: npxResult.packageName || pnpmResult.packageName || npmResult.packageName,
    dockerImage: dockerResult.image,
  };
}

function generateRecommendations(
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
): string[] {
  const recs = new Set<string>();

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


