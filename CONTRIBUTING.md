# Contributing to mcp-label

Thank you for your interest in contributing to `mcp-label`! This project aims to make MCP server permissions transparent, auditable, and enforceable.

## Getting Started

1. Fork and clone the repository
2. Install dependencies:
   ```bash
   pnpm install
   ```
3. Build:
   ```bash
   pnpm build
   ```
4. Run tests:
   ```bash
   pnpm test
   ```

## Development Workflow

### Running the CLI locally

```bash
pnpm --filter @mcp-label/cli dev scan --config examples/risky.mcp.json
```

### Adding a New Rule

Rules live in `packages/rules/src/`. A good rule includes:

- Clear evidence (what triggered the finding)
- Clear explanation (what it means)
- Clear recommendation (what the user should do)
- Tests (in `packages/rules/tests/`)
- No secret values in fixtures

### Code Quality

Before submitting a PR:

```bash
pnpm build
pnpm test
pnpm lint
```

## Good First Issues

- Add a new permission detection rule
- Improve Markdown export formatting
- Add a new example MCP config
- Improve Docker image parsing
- Add tests for a permission category
- Improve safer config suggestions
- Add documentation for a client-specific MCP config format

## Pull Request Guidelines

1. Keep PRs focused on a single change
2. Include tests for new functionality
3. Update relevant documentation
4. Ensure CI passes
5. Never include real secrets in fixtures or tests

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

