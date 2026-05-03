export { exportTerminal } from './terminal.js';
export { exportMarkdown } from './markdown.js';
export { exportSvg } from './svg.js';

/**
 * JSON exporter is trivial — just JSON.stringify the report.
 */
import type { McpLabelReport } from '../types.js';

export function exportJson(report: McpLabelReport): string {
  return JSON.stringify(report, null, 2);
}

