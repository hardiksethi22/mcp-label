/**
 * `mcp-label diff` command.
 *
 * Compares two JSON reports or snapshots and shows what changed.
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { McpLabelReportSchema } from '@mcp-label/core';
import type { McpLabelReport } from '@mcp-label/core';

export const diffCommand = new Command('diff')
  .description('Compare two mcp-label reports or snapshots.')
  .argument('<old>', 'Path to old report')
  .argument('<new>', 'Path to new report')
  .action((oldPath: string, newPath: string) => {
    let oldReport: McpLabelReport;
    let newReport: McpLabelReport;

    try {
      oldReport = McpLabelReportSchema.parse(JSON.parse(readFileSync(oldPath, 'utf-8')));
      newReport = McpLabelReportSchema.parse(JSON.parse(readFileSync(newPath, 'utf-8')));
    } catch (err: any) {
      console.error(`Error: Failed to parse reports: ${err.message}`);
      process.exit(1);
    }

    console.log('MCP Label Diff');
    console.log(`Old: ${oldPath} (grade: ${oldReport.summary.overallGrade}, risk: ${oldReport.summary.overallRisk})`);
    console.log(`New: ${newPath} (grade: ${newReport.summary.overallGrade}, risk: ${newReport.summary.overallRisk})`);
    console.log('');

    // Grade change
    if (oldReport.summary.overallGrade !== newReport.summary.overallGrade) {
      console.log(`Grade changed: ${oldReport.summary.overallGrade} → ${newReport.summary.overallGrade}`);
    }

    // Risk change
    if (oldReport.summary.overallRisk !== newReport.summary.overallRisk) {
      console.log(`Risk changed: ${oldReport.summary.overallRisk} → ${newReport.summary.overallRisk}`);
    }

    // Server changes
    const oldNames = new Set(oldReport.servers.map((s) => s.name));
    const newNames = new Set(newReport.servers.map((s) => s.name));

    for (const name of newNames) {
      if (!oldNames.has(name)) {
        console.log(`+ New server: ${name}`);
      }
    }
    for (const name of oldNames) {
      if (!newNames.has(name)) {
        console.log(`- Removed server: ${name}`);
      }
    }

    // Permission changes per server
    for (const newServer of newReport.servers) {
      const oldServer = oldReport.servers.find((s) => s.name === newServer.name);
      if (!oldServer) continue;

      const oldPerms = new Set(oldServer.permissions.map((p) => p.permission));
      const newPerms = new Set(newServer.permissions.map((p) => p.permission));

      for (const perm of newPerms) {
        if (!oldPerms.has(perm)) {
          console.log(`+ ${newServer.name}: new permission ${perm}`);
        }
      }
      for (const perm of oldPerms) {
        if (!newPerms.has(perm)) {
          console.log(`- ${newServer.name}: removed permission ${perm}`);
        }
      }

      if (oldServer.grade !== newServer.grade) {
        console.log(`  ${newServer.name}: grade ${oldServer.grade} → ${newServer.grade}`);
      }
      if (oldServer.risk !== newServer.risk) {
        console.log(`  ${newServer.name}: risk ${oldServer.risk} → ${newServer.risk}`);
      }
    }
  });

