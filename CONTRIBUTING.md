# Contributing to Aegis Mesh

Thank you for helping improve Aegis Mesh.

1. Open an issue for significant contract, schema, security-boundary, or compatibility changes.
2. Fork the repository and create a focused branch.
3. Use Python 3.11.15 and run `./setup.sh`.
4. Add tests for behavior changes. Use only synthetic fixtures.
5. Run `make validate build verify-dist` and inspect `git diff --check`.
6. Open a pull request explaining the security impact, compatibility impact, tests, and rollback.

Never commit credentials, private endpoints, real evidence, personal data, or unauthorized scan output. New tools and assets must remain disabled until explicitly registered and independently verified. Changes may narrow security boundaries; expansions require an explicit design discussion and tests.

By submitting a contribution, you agree to license it under Apache-2.0 and to follow the Code of Conduct.

## Using with Codex

After cloning, open the repository in Codex and direct it to [AGENTS.md](AGENTS.md). Keep each change focused, review the resulting diff, and require the focused test plus the full validation/build commands documented there before opening a pull request. Codex must not be given production credentials, private evidence, or unauthorized targets through prompts or files.
