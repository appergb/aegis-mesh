# Repository agent guide

- Treat `SYSTEM_PROMPT.md`, `SECURITY_POLICY.md`, `AGENT_ROUTER.md`, schemas, and validated configs as contracts.
- Do not expand permissions, approval exemptions, tool inventories, assets, notification scope, or production claims.
- Use Python 3.11.15 and synthetic test data only.
- Run focused tests, `make validate`, `make build`, `make verify-dist`, and `git diff --check` for relevant changes.
- Never commit secrets, production endpoints, real evidence, personal data, or unauthorized security-test results.
