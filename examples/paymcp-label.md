# MCP Safety Label

Overall grade: **F**
Overall risk: **Critical**
Static analysis only: **Yes**

| Server | Grade | Risk | Main concerns |
|---|:---:|:---:|---|
| paymcp-demo | F | Critical | payments.charge, secrets.env x3, remote-git-unpinned x2, payments.read |
| paymcp-stripe-server | F | Critical | payments.charge, secrets.env x2, payments.read, database.query |
| paymcp-x402 | F | Critical | secrets.env, payments.read, network.egress x2, payment_protocol.x402 |
| paymcp-subscription-demo | F | Critical | payments.charge, secrets.env x2, payments.read, uv-with-unpinned x4 |

## paymcp-demo

### Permissions

- **High:** `secrets.env` — Environment variable detected: OPENAI_API_KEY
- **High:** `secrets.env` — Environment variable detected: STRIPE_SECRET_KEY
- **High:** `secrets.env` — Environment variable detected: WALLEOT_API_KEY
- **High:** `payments.read` — Stripe secret key detected in environment
- **Critical:** `payments.charge` — Stripe secret credentials detected
- **Medium:** `network.egress` — Environment variable detected: OPENAI_API_KEY
- **Medium:** `network.egress` — Environment variable detected: STRIPE_SECRET_KEY
- **Medium:** `network.egress` — Environment variable detected: WALLEOT_API_KEY

### Install Risks

- **Medium:** `remote-git-source` — The server is installed from a remote Git repository.
- **High:** `remote-git-unpinned` — The Git source is not pinned to a commit SHA or release tag.
- **High:** `uvx-remote-source` — The uvx package is installed from a remote Git repository.
- **Medium:** `remote-git-source` — The server is installed from a remote Git repository.
- **High:** `remote-git-unpinned` — The Git source is not pinned to a commit SHA or release tag.

### Recommendations

- Use the least-privileged credential possible and rotate it if exposed.
- Use restricted API keys, enable webhook verification, and limit key permissions to the minimum required.
- Confirm expected outbound domains and avoid sending sensitive data unnecessarily.
- Prefer a pinned release, package version, or commit SHA.
- Pin the Git dependency to a commit SHA or signed release tag.
- Prefer a pinned release or package version.

## paymcp-stripe-server

### Permissions

- **High:** `secrets.env` — Environment variable detected: STRIPE_API_KEY
- **High:** `secrets.env` — Environment variable detected: STRIPE_SECRET_KEY
- **Medium:** `database.query` — State-store (Redis) signal detected
- **Medium:** `database.mutate` — State-store access without read-only signal
- **High:** `payments.read` — Stripe secret key detected in environment
- **Critical:** `payments.charge` — Stripe secret credentials detected
- **Medium:** `network.egress` — Environment variable detected: STRIPE_API_KEY

### Install Risks

- **Medium:** `local-script` — The MCP server runs a local script. Static config analysis cannot verify the script contents.

### Recommendations

- Use the least-privileged credential possible and rotate it if exposed.
- Use read-only database credentials where possible.
- Use restricted API keys, enable webhook verification, and limit key permissions to the minimum required.
- Confirm expected outbound domains and avoid sending sensitive data unnecessarily.
- Review the script contents and dependencies before enabling the server.

## paymcp-x402

### Permissions

- **High:** `secrets.env` — Environment variable detected: OPENAI_API_KEY
- **High:** `payments.read` — Payment service signal inferred from server name or configuration
- **Medium:** `payment_protocol.x402` — x402 payment protocol inferred from environment variables
- **Medium:** `payments.receive` — Payment address environment variable detected
- **Medium:** `network.egress` — x402 payment environment variable detected: X402_PAY_TO_ADDRESS
- **Medium:** `network.egress` — Environment variable detected: OPENAI_API_KEY

### Install Risks

- **Medium:** `uvx-unpinned` — The uvx package is not pinned to a specific version.

### Recommendations

- Use the least-privileged credential possible and rotate it if exposed.
- Review payment flow, wallet/address configuration, and user approval behavior.
- Verify the receiving address, payment limits, and whether the server can initiate payment-gated actions.
- Confirm expected outbound payment domains.
- Confirm expected outbound domains and avoid sending sensitive data unnecessarily.
- Pin package versions (e.g., package==1.2.3).

## paymcp-subscription-demo

### Permissions

- **High:** `secrets.env` — Environment variable detected: STRIPE_SECRET_KEY
- **High:** `secrets.env` — Environment variable detected: OPENAI_API_KEY
- **High:** `payments.read` — Stripe secret key detected in environment
- **Critical:** `payments.charge` — Stripe secret credentials detected
- **Medium:** `network.egress` — Environment variable detected: STRIPE_SECRET_KEY
- **Medium:** `network.egress` — Environment variable detected: OPENAI_API_KEY

### Install Risks

- **Medium:** `uv-with-unpinned` — A runtime dependency is installed without a fixed version.
- **Medium:** `uv-with-unpinned` — A runtime dependency is installed without a fixed version.
- **Medium:** `uv-with-unpinned` — A runtime dependency is installed without a fixed version.
- **Medium:** `uv-with-unpinned` — A runtime dependency is installed without a fixed version.
- **Medium:** `local-script` — The MCP server runs a local script. Static config analysis cannot verify the script contents.

### Recommendations

- Use the least-privileged credential possible and rotate it if exposed.
- Use restricted API keys, enable webhook verification, and limit key permissions to the minimum required.
- Confirm expected outbound domains and avoid sending sensitive data unnecessarily.
- Pin runtime dependencies, for example: --with openai==<version>
- Pin runtime dependencies, for example: --with paymcp==<version>
- Pin runtime dependencies, for example: --with requests==<version>
- Pin runtime dependencies, for example: --with Pillow==<version>
- Review the script contents and dependencies before enabling the server.

---

*Generated by [mcp-label](https://github.com/hardiksethi22/mcp-label). This is a heuristic analysis, not a proof of safety.*