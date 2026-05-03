/**
 * `mcp-label harden` command.
 */

import { Command } from 'commander';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { parseConfigFile, analyzeServer } from '@mcp-label/core';
import { computeScore } from '@mcp-label/core';

export const hardenCommand = new Command('harden')
  .description('Generate safer config suggestions for an MCP server.')
  .requiredOption('--config <path>', 'Path to MCP config file')
  .option('--server <name>', 'Server name to harden (all if omitted)')
  .option('--output <path>', 'Write safer config to file')
  .option('--write', 'Overwrite the original config file')
  .action((opts) => {
    if (!existsSync(opts.config)) {
      console.error(`Error: Config file not found: ${opts.config}`);
      process.exit(1);
    }

    const config = parseConfigFile(opts.config);
    const servers = opts.server
      ? [[opts.server, config.mcpServers[opts.server]] as const]
      : Object.entries(config.mcpServers);

    for (const [name, serverConfig] of servers) {
      if (!serverConfig) {
        console.error(`Server not found: ${name}`);
        continue;
      }

      const result = analyzeServer(name, serverConfig);

      if (result.saferConfigSuggestions.length === 0) {
        console.log(`${name}: No suggestions. Configuration looks reasonable.`);
        continue;
      }

      console.log(`\nSafer config suggestions for ${name}\n`);
      let i = 1;
      for (const suggestion of result.saferConfigSuggestions) {
        console.log(`${i}. ${suggestion.title}`);
        console.log(`   ${suggestion.explanation}`);
        if (suggestion.before) {
          console.log(`   Before: ${suggestion.before}`);
        }
        if (suggestion.after) {
          console.log(`   After:  ${suggestion.after}`);
        }
        console.log('');
        i++;
      }
    }
  });

