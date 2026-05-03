/**
 * Utility functions for mcp-label.
 */

/**
 * Get the current ISO timestamp.
 */
export function now(): string {
  return new Date().toISOString();
}

/**
 * Deduplicate an array of strings.
 */
export function unique(arr: string[]): string[] {
  return [...new Set(arr)];
}

import type { PermissionFinding, InstallRisk, FindingLevel } from '../types.js';

/**
 * Summarize and deduplicate concerns with counts.
 * Returns e.g. ["secrets.env x3", "payments.charge_possible", "network.egress"]
 */
export function summarizeConcerns(
  permissions: PermissionFinding[],
  installRisks: InstallRisk[],
  max = 4,
): string[] {
  const levelOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // Collect all concern IDs with their highest level
  const items: { id: string; level: FindingLevel }[] = [
    ...permissions.map((p) => ({ id: p.permission, level: p.level })),
    ...installRisks.map((r) => ({ id: r.id, level: r.level })),
  ];

  // Count occurrences and track highest severity
  const counts = new Map<string, { count: number; level: FindingLevel }>();
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

  // Sort by severity first, then count
  const sorted = [...counts.entries()].sort((a, b) => {
    const levelDiff = (levelOrder[a[1].level] ?? 5) - (levelOrder[b[1].level] ?? 5);
    if (levelDiff !== 0) return levelDiff;
    return b[1].count - a[1].count;
  });

  return sorted.slice(0, max).map(([id, { count }]) =>
    count > 1 ? `${id} x${count}` : id,
  );
}
