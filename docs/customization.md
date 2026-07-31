# Customization guide

A deployment profile is the only supported place for organization, region, provider, endpoint, asset, baseline, and legal values. Do not edit prompts to smuggle in runtime authority.

## Safe sequence

1. Fork or vendor a tagged Aegis Mesh release and preserve its checksum.
2. Copy `configs/runtime.example.yaml` into a deployment-owned private repository.
3. Register the exact provider model, gateway endpoint, secret references, owned assets, and resource aliases.
4. Measure service baselines and enter reviewed thresholds, SLO, RTO, and RPO values. The included QR bands and scenarios are synthetic examples, not universal production metrics.
5. Select only required agents and tools. Keep all MCP integrations disabled until their pinned source, license, tool list, wrapper, egress, and live conformance are verified.
6. Add a current jurisdiction profile using the notification legal-review template. The included PRC reference is optional and never selected automatically.
7. Run `make validate`, deployment-specific forward tests, and an independent review before enabling a production gate.

## Approval design

Do not add approval steps merely because an agent is involved. Passive observation and policy-authorized reads stay automatic. Approval is attached to the action's actual impact: ordinary reversible changes use the registered operational approval; irreversible external notification uses two distinct roles. Adapters cannot multiply or bypass these rules.

## Compatibility

Provider guidance is available for OpenAI, Claude, Kimi, and generic MCP runtimes under `adapters/`. A new adapter must preserve identifiers, timestamps, hashes, blocked states, audit fields, and the closed request/response schemas.
