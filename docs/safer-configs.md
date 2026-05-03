# Safer Config Suggestions

The `mcp-label harden` command generates actionable suggestions for improving MCP server configurations.

## Example

```bash
mcp-label harden --config ./.cursor/mcp.json --server github
```

## Suggestions Include

- **Pin Docker images**: Replace `:latest` with explicit versions or digests
- **Pin packages**: Add version specifiers to npx packages
- **Restrict filesystem paths**: Narrow broad paths to project directories
- **Use fine-grained tokens**: Use scoped credentials instead of broad access tokens
- **Remove privileged mode**: Drop Docker `--privileged` flag
- **Avoid host networking**: Use bridge networking instead

## Output Format

Each suggestion includes:
- Title
- Explanation
- Before value (what the config currently has)
- After value (what it should look like)
- Confidence level

## Safety

The `harden` command does not modify files unless `--write` is explicitly passed.

