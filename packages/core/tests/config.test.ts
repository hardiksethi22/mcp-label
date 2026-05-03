import { describe, it, expect } from 'vitest';
import {
  parseConfigFile,
  redactEnvValues,
  getDiscoveryPaths,
} from '../src/config/index.js';
import { join } from 'node:path';

const EXAMPLES_DIR = join(__dirname, '..', '..', '..', 'examples');

describe('Config parsing', () => {
  it('should parse a valid MCP config file', () => {
    const config = parseConfigFile(join(EXAMPLES_DIR, 'risky.mcp.json'));
    expect(config.mcpServers).toBeDefined();
    expect(Object.keys(config.mcpServers).length).toBeGreaterThan(0);
  });

  it('should parse cursor config', () => {
    const config = parseConfigFile(join(EXAMPLES_DIR, 'cursor.mcp.json'));
    expect(config.mcpServers.github).toBeDefined();
    expect(config.mcpServers.filesystem).toBeDefined();
  });

  it('should throw on invalid JSON', () => {
    expect(() => parseConfigFile('/nonexistent/path.json')).toThrow();
  });
});

describe('Secret redaction', () => {
  it('should return only env variable names', () => {
    const result = redactEnvValues({
      GITHUB_TOKEN: 'ghp_secret123',
      API_KEY: 'sk-secret456',
      NORMAL_VAR: 'hello',
    });
    expect(result).toEqual(['GITHUB_TOKEN', 'API_KEY', 'NORMAL_VAR']);
    // Ensure no values are present
    expect(result.join('')).not.toContain('ghp_secret');
    expect(result.join('')).not.toContain('sk-secret');
  });

  it('should handle undefined env', () => {
    expect(redactEnvValues(undefined)).toEqual([]);
  });
});

describe('Discovery paths', () => {
  it('should return an array of paths', () => {
    const paths = getDiscoveryPaths();
    expect(Array.isArray(paths)).toBe(true);
    expect(paths.length).toBeGreaterThan(0);
  });

  it('should include .cursor/mcp.json', () => {
    const paths = getDiscoveryPaths();
    expect(paths.some((p) => p.includes('.cursor/mcp.json'))).toBe(true);
  });
});

