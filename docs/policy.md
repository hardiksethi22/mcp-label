# Policy-as-Code

`mcp-label` supports YAML-based team policies for enforcing MCP server standards.

## Policy File Format

```yaml
version: "0.1"
rules:
  - id: rule-id
    description: Human-readable description.
    deny:
      permissions:
        - shell.execute
      evidenceIncludes:
        - "/"
    require:
      install:
        dockerPinned: true
        packagePinned: true
    allow:
      domains:
        - api.github.com
```

## Rule Types

### Deny Rules

Deny rules fail if a server has a matching permission (optionally with matching evidence).

### Require Rules

Require rules fail if a server does not meet the stated requirement (e.g., Docker images not pinned).

### Allow Rules

Allow rules define approved values (e.g., allowed network domains). Currently used for documentation; enforcement is planned.

## Usage

```bash
mcp-label policy check --config ./.cursor/mcp.json --policy ./policy.yaml
mcp-label policy check --report ./mcp-label.json --policy ./policy.yaml
```

## CI Integration

```bash
mcp-label policy check --config ./.cursor/mcp.json --policy ./policy.yaml --fail-on deny
```

Exit code 2 is returned if any deny rule fails.

