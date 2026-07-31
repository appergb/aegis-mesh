# Aegis Mesh

[![CI](https://github.com/appergb/aegis-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/appergb/aegis-mesh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11.15-3776AB.svg)](.python-version)

Aegis Mesh is a framework-neutral, defensive multi-agent security package for detection, protection, incident response, recovery, observability, evidence governance, and risk analysis. It is designed to be embedded into different model runtimes and operational environments without granting a model implicit production authority.

The repository includes twelve role-bound agents, three shared defensive skills, closed JSON Schemas, strict configuration validation, synthetic scenarios, evidence-chain contracts, and disabled-by-default MCP integration specifications. It does not connect to real services, scan assets, send notifications, store production evidence, or ship credentials.

## Why Aegis Mesh

- Portable: provider adapters are separate from the security contract.
- Governed: permissions, action classes, approval roles, and tool inventories come from validated configuration.
- Efficient: policy-authorized read-only work does not gain unnecessary human approval; irreversible external actions keep the approvals they actually require.
- Fail closed: unknown tools, assets, schemas, scopes, identities, or configuration are blocked.
- Verifiable: 23 scenario contracts, package validation, forward-result validation, and a reproducible source-bundle build are included.

## Quick start

Prerequisites: Python 3.11.15 and Git.

```bash
git clone https://github.com/appergb/aegis-mesh.git
cd aegis-mesh
./setup.sh
make validate
make build
```

`make build` creates versioned source archives and SHA-256 checksums in `dist/`. It does not create or deploy a live agent runtime.

## Repository map

- Root governance files: identity, safety, routing, and incident response.
- `skills/`: role agents and reusable defensive workflows.
- `schemas/`: closed structural request and response contracts.
- `configs/`: governance facts and a disabled runtime example.
- `integrations/`: pinned, disabled MCP policies and upstream evidence.
- `forensics/`: custody schemas, policy, and synthetic templates.
- `adapters/`: model-provider and MCP compatibility guidance.
- `scenarios/`: synthetic evaluation contracts.
- `scripts/` and `tests/`: validators, release build, and regression tests.

## Load order

```text
SYSTEM_PROMPT.md
→ SECURITY_POLICY.md
→ AGENT_ROUTER.md
→ INCIDENT_RESPONSE.md when an incident is active
→ validated deployment configuration
→ selected agent system prompt
→ selected agent/shared skill
→ least-privilege tool policy
→ incident-scoped untrusted context
```

Later layers may narrow, but cannot expand, earlier boundaries. A deployment adapter may translate provider mechanics but cannot add permissions, targets, approvals, disclosure, or tools.

## Customize and deploy

Read [Architecture](docs/architecture.md), [Customization](docs/customization.md), and [Deployment](docs/deployment.md). Copy `configs/runtime.example.yaml` into a deployment-owned location, keep secrets in a secret manager, and replace synthetic thresholds only with reviewed measurements from your environment.

Production remains blocked until provider identity, secrets, endpoints, owned assets, SLO/RTO/RPO, legal and vendor review, evidence storage, gateway/MCP conformance, and independent forward results are supplied. Static tests do not prove live protection or recovery performance.

## Security boundary

Aegis Mesh is defensive only. It prohibits hack-back, credential theft, persistence, destructive payloads, unauthorized scans, hidden disclosure, wildcard targets, and direct upstream MCP access. See [SECURITY.md](SECURITY.md) for vulnerability reporting and [SECURITY_POLICY.md](SECURITY_POLICY.md) for the runtime policy.

## Contributing

Contributions are welcome under the [contribution guide](CONTRIBUTING.md) and [code of conduct](CODE_OF_CONDUCT.md). By contributing, you agree that your contribution is licensed under Apache-2.0.

## License

Copyright 2026 Aegis Mesh Contributors. Licensed under the [Apache License 2.0](LICENSE).
