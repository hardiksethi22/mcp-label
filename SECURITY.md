# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security issues privately by emailing the maintainers or opening a private security advisory through GitHub.

**Do not open public issues** containing:

- Real secrets or credentials
- Private MCP configuration files
- Exploitable implementation details

We will acknowledge reports within 72 hours and aim to release fixes promptly.

## Scope

`mcp-label` is a static analysis tool. It does not execute MCP servers by default. However, the `inspect` command may start MCP servers, and security issues related to:

- Secret leakage in reports or logs
- Unsafe default behavior
- Command injection through config parsing

are all in scope.

