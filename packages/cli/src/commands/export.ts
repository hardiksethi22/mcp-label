/**
 * `mcp-label export` command.
 */

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';
import {
  McpLabelReportSchema,
  exportTerminal,
  exportMarkdown,
  exportSvg,
  exportJson,
} from '@mcp-label/core';

export const exportCommand = new Command('export')
  .description('Export an existing JSON report to another format.')
  .requiredOption('--input <path>', 'Path to JSON report')
  .requiredOption('--format <format>', 'Output format: json|markdown|svg|terminal')
  .option('--output <path>', 'Write output to file')
  .action((opts) => {
    let report;
    try {
      const raw = readFileSync(opts.input, 'utf-8');
      report = McpLabelReportSchema.parse(JSON.parse(raw));
    } catch (err: any) {
      console.error(`Error: Failed to read report: ${err.message}`);
      process.exit(1);
    }

    let output: string;
    switch (opts.format) {
      case 'json':
        output = exportJson(report);
        break;
      case 'markdown':
        output = exportMarkdown(report);
        break;
      case 'svg':
        output = exportSvg(report);
        break;
      case 'terminal':
        output = exportTerminal(report);
        break;
      default:
        console.error(`Unknown format: ${opts.format}. Use json, markdown, svg, or terminal.`);
        process.exit(1);
    }

    if (opts.output) {
      writeFileSync(opts.output, output, 'utf-8');
      console.error(`Exported to ${opts.output}`);
    } else {
      console.log(output);
    }
  });

