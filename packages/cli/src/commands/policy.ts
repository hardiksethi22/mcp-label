/**
 * `mcp-label policy check` command.
 */

import { Command } from 'commander';
import { existsSync, readFileSync } from 'node:fs';
import {
  parseConfigFile,
  parsePolicyFile,
  scan,
  McpLabelReportSchema,
  evaluatePolicy,
} from '@mcp-label/core';
import type { McpLabelReport } from '@mcp-label/core';

const checkCommand = new Command('check')
  .description('Check a config or report against a policy file.')
  .option('--config <path>', 'Path to MCP config file')
  .option('--report <path>', 'Path to existing JSON report')
  .requiredOption('--policy <path>', 'Path to policy file')
  .option('--fail-on <mode>', 'Fail on: deny (any deny match)')
  .action((opts) => {
    if (!opts.config && !opts.report) {
      console.error('Error: Provide --config or --report.');
      process.exit(1);
    }

    let report: McpLabelReport;
    let policy;

    try {
      policy = parsePolicyFile(opts.policy);
    } catch (err: any) {
      console.error(`Error: Failed to parse policy: ${err.message}`);
      process.exit(1);
    }

    if (opts.report) {
      try {
        const raw = readFileSync(opts.report, 'utf-8');
        report = McpLabelReportSchema.parse(JSON.parse(raw));
      } catch (err: any) {
        console.error(`Error: Failed to read report: ${err.message}`);
        process.exit(1);
      }
    } else {
      try {
        const config = parseConfigFile(opts.config);
        report = scan(config, {
          configPaths: [opts.config],
          discovered: false,
          policy,
        });
      } catch (err: any) {
        console.error(`Error: Failed to scan config: ${err.message}`);
        process.exit(1);
      }
    }

    // If report was loaded, evaluate policy against each server
    let allResults = report!.servers.flatMap(
      (s) => s.policyResults || evaluatePolicy(s, policy!),
    );

    const failed = allResults.filter((r) => !r.passed);
    const passed = allResults.filter((r) => r.passed);

    console.log(`Policy: ${opts.policy}`);
    console.log(`Rules evaluated: ${allResults.length}`);
    console.log(`Passed: ${passed.length}`);
    console.log(`Failed: ${failed.length}`);
    console.log('');

    for (const result of failed) {
      console.log(`❌ ${result.ruleId} (${result.server}): ${result.details}`);
    }

    for (const result of passed) {
      console.log(`✅ ${result.ruleId} (${result.server}): ${result.details}`);
    }

    if (opts.failOn === 'deny' && failed.length > 0) {
      process.exit(2);
    }
  });

export const policyCommand = new Command('policy')
  .description('Policy commands for mcp-label.')
  .addCommand(checkCommand);

