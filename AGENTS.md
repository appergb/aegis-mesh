# Aegis Mesh contributor agent guide

## Quick start

Use Python 3.11.15 and Git:

```bash
./setup.sh
make validate
make build
make verify-dist
git diff --check
```

Run a focused test first while editing, for example:

```bash
.venv/bin/python -m pytest -q tests/test_configs.py
```

## Architecture and key files

```text
SYSTEM_PROMPT.md / SECURITY_POLICY.md / AGENT_ROUTER.md
├── configs/       validated governance and disabled runtime example
├── schemas/       closed request, response, event, and evidence contracts
├── skills/        twelve role agents and three shared defensive skills
├── integrations/  pinned, disabled MCP integration specifications
├── adapters/      provider-neutral runtime mappings
├── scenarios/     synthetic evaluation contracts
└── scripts/       validation and reproducible release tooling
```

- Treat root governance files, schemas, and validated configs as contracts.
- `scripts/validation_core.py` owns strict loading, common validation, hashing, and semantic checks.
- `scripts/validate_package.py` is the offline package gate.
- `docs/architecture.md`, `docs/customization.md`, and `docs/deployment.md` define extension boundaries.

## Configuration and runtime

The repository is a static package: it starts no listener and exposes no port. The example variables are `AEGIS_MESH_ENVIRONMENT`, `AEGIS_MESH_RUNTIME_CONFIG`, and `AEGIS_MESH_LOG_LEVEL`; copy names from `.env.example`, but keep real configuration and secrets outside Git. `configs/runtime.example.yaml` remains disabled until a deployment supplies its own reviewed values.

## Change rules

- Preserve the default-deny production boundary. Do not expand permissions, approval exemptions, tool inventories, assets, notification scope, or production claims.
- Use synthetic test data only. Never commit secrets, production endpoints, real evidence, personal data, or unauthorized security-test results.
- Keep changes focused and add tests for contract or behavior changes.
- Before committing, run the focused tests plus `make validate`, `make build`, `make verify-dist`, and `git diff --check`.
