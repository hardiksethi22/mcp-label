# Publishing mcp-label to npm

## Prerequisites

1. **npm account**: Create one at https://www.npmjs.com/signup
2. **npm login**: Run `npm login` and authenticate
3. **Organization** (required before first publish): Create the `@mcp-label` org at https://www.npmjs.com/org/create — choose the free plan. Without this, `pnpm publish` will fail with `E404 Scope not found`.
4. **Permissions**: Ensure your npm user has publish access to `@mcp-label` org packages

## Pre-publish Checklist

```bash
# 1. Ensure clean working tree
git status

# 2. Run full build
pnpm build

# 3. Run all tests
pnpm test

# 4. Run type checking
pnpm typecheck

# 5. Verify package contents (dry run)
cd packages/core && npm pack --dry-run && cd ../..
cd packages/cli && npm pack --dry-run && cd ../..
```

## Publish Steps

### Step 1: Version bump

Decide on version. Current published versions: `@mcp-label/core@0.1.3`, `@mcp-label/cli@0.1.3`, `@mcp-label/rules@0.1.3`.

```bash
# For a patch bump (e.g. 0.1.2):
pnpm -r exec npm version 0.1.2 --no-git-tag-version

# For a minor bump (e.g. 0.2.0):
pnpm -r exec npm version 0.2.0 --no-git-tag-version

# Also bump the root package:
npm version <new-version> --no-git-tag-version
```

### Step 2: Update workspace dependency references

In `packages/cli/package.json`, ensure `@mcp-label/core` dependency uses the right version:

```json
"dependencies": {
  "@mcp-label/core": "workspace:*"
}
```

For npm publish, pnpm will convert `workspace:*` to the actual version automatically when using `pnpm publish`.

### Step 3: Build for production

```bash
pnpm build
```

### Step 4: Publish packages (in order)

```bash
# Publish core first (other packages depend on it)
cd packages/core
pnpm publish --access public --no-git-checks
cd ../..

# Then publish CLI
cd packages/cli
pnpm publish --access public --no-git-checks
cd ../..

# Optional: publish other packages
cd packages/rules
pnpm publish --access public --no-git-checks
cd ../..
```

Or use pnpm's recursive publish:

```bash
pnpm -r publish --access public --no-git-checks
```

### Step 5: Tag the release

```bash
git tag v<version>
git push origin v<version>
```

### Step 6: Create GitHub Release

```bash
gh release create v<version> --title "v<version> — <title>" --generate-notes
```

## Automated Publishing (CI/CD)

For automated releases, add a GitHub Action:

```yaml
# .github/workflows/publish.yml
name: Publish to npm
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
      - run: pnpm install
      - run: pnpm build
      - run: pnpm test
      - run: pnpm -r publish --access public --no-git-checks
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Set `NPM_TOKEN` as a repository secret in GitHub.

## Verify Publication

```bash
# Check packages are published
npm view @mcp-label/core
npm view @mcp-label/cli

# Test install
npx @mcp-label/cli scan --config path/to/config.json
```
