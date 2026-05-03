/**
 * `mcp-label scan` command.
 */

import { Command } from 'commander';
import { existsSync, writeFileSync } from 'node:fs';
import {
  parseConfigFile,
  discoverConfigFiles,
  mergeConfigs,
  scan,
  parsePolicyFile,
  exportTerminal,
  exportMarkdown,
  exportSvg,
  exportJson,
} from '@mcp-label/core';
import type { McpConfigFile, RiskLevel } from '@mcp-label/core';

export const scanCommand = new Command('scan')
  .description('Scan MCP server configurations and generate a safety label report.')
  .option('--config <path>', 'Path to MCP config file')
  .option('--output <path>', 'Write JSON report to file')
  .option('--json', 'Print JSON report to stdout')
  .option('--markdown', 'Print Markdown report to stdout')
  .option('--svg', 'Print SVG report to stdout')
  .option('--no-discover', 'Do not auto-discover config files')
  .option('--fail-on <level>', 'Exit non-zero if risk is at or above: low|medium|high|critical')
  .option('--policy <path>', 'Evaluate against a policy file')
  .option('--strict', 'Use stricter inference (disables publisher trust mitigations)')
  .option('--explain', 'Show scoring trace and rationale')
  .option('--no-known-profiles', 'Disable known-server profile trust/expectation adjustments')
  .action(async (opts) => {
    let configPaths: string[] = [];
    let configs: McpConfigFile[] = [];
    let discovered = false;

    // Load config
    if (opts.config) {
      if (!existsSync(opts.config)) {
        console.error(`Error: Config file not found: ${opts.config}`);
        process.exit(1);
      }
      try {
        const config = parseConfigFile(opts.config);
        configs.push(config);
        configPaths.push(opts.config);
      } catch (err: any) {
        console.error(`Error: Failed to parse config: ${err.message}`);
        process.exit(1);
      }
    } else if (opts.discover !== false) {
      // Auto-discover
      const found = discoverConfigFiles();
      if (found.length === 0) {
        console.error(
          'No MCP config files found. Use --config to specify a path, or place a config at a known location.',
        );
        console.error('Known locations:');
        console.error('  ~/.cursor/mcp.json');
        console.error('  ./.cursor/mcp.json');
        console.error(
          '  ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)',
        );
        process.exit(1);
      }
      discovered = true;
      for (const { path, config } of found) {
        configPaths.push(path);
        configs.push(config);
      }
    }

    if (configs.length === 0) {
      console.error('No configs to scan.');
      process.exit(1);
    }

    const merged = mergeConfigs(configs);

    // Load policy
    let policy;
    if (opts.policy) {
      try {
        policy = parsePolicyFile(opts.policy);
      } catch (err: any) {
        console.error(`Error: Failed to parse policy: ${err.message}`);
        process.exit(1);
      }
    }

    // Scan
    const report = scan(merged, {
      configPaths,
      discovered,
      policy,
      strict: opts.strict,
      explain: opts.explain,
      noKnownProfiles: opts.knownProfiles === false,
    });

    // Output
    if (opts.json) {
      console.log(exportJson(report));
    } else if (opts.markdown) {
      console.log(exportMarkdown(report));
    } else if (opts.svg) {
      console.log(exportSvg(report));
    } else {
      console.log(exportTerminal(report, { explain: opts.explain }));
    }

    // Write file
    if (opts.output) {
      writeFileSync(opts.output, exportJson(report), 'utf-8');
      console.error(`Report written to ${opts.output}`);
    }

    // Fail on risk level
    if (opts.failOn) {
      const levels: RiskLevel[] = ['low', 'medium', 'high', 'critical'];
      const threshold = levels.indexOf(opts.failOn as RiskLevel);
      const actual = levels.indexOf(report.summary.overallRisk);
      if (threshold >= 0 && actual >= threshold) {
        process.exit(2);
      }
    }
  });

