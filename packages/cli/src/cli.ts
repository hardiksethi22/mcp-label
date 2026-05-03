/**
 * mcp-label CLI entry point.
 */

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { exportCommand } from './commands/export.js';
import { policyCommand } from './commands/policy.js';
import { hardenCommand } from './commands/harden.js';
import { initCommand } from './commands/init.js';
import { diffCommand } from './commands/diff.js';

const program = new Command();

program
  .name('mcp-label')
  .description('A privacy, safety, and permissions label for MCP servers.')
  .version('0.1.3');

program.addCommand(scanCommand);
program.addCommand(exportCommand);
program.addCommand(policyCommand);
program.addCommand(hardenCommand);
program.addCommand(initCommand);
program.addCommand(diffCommand);

program.parse();

