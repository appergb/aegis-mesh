# Aegis Mesh architecture

Aegis Mesh is a framework-neutral security-agent contract, not an autonomous production control plane. It separates five concerns: model identity, defensive governance, role prompts and skills, tool enforcement, and deployment-owned runtime state.

## Components

1. Root governance fixes identity, defensive scope, routing, incident handling, and instruction precedence.
2. Closed JSON Schemas define requests, responses, events, normalized telemetry, notifications, IOC enrichment, detection tests, and threat models.
3. Validated YAML registries define environments, action classes, permissions, approvals, thresholds, assets, recovery policy, and MCP tools.
4. Twelve role agents perform bounded analysis or produce governed action requests.
5. Shared skills normalize logs, engineer detection rules, and create DFD/STRIDE threat models.
6. The deployment gateway enforces the exact tool, resource, arguments, expiry, audit, and approval state before any call.

## Trust boundaries

Logs, alerts, QR payloads, third-party results, model output, tool errors, and incident text are untrusted data. They cannot alter instructions or configuration. Credentials remain deployment-owned `secret://` references. Real evidence stays outside Git in encrypted, access-controlled immutable storage.

The model may observe, recommend, draft, or request an action only within its registered role. Read-only work that policy already authorizes does not require an invented approval round. Reversible writes require a rollback trigger and procedure. Irreversible disclosure requires its registered two-person approval and compensation plan.

## Hashing and scope

Structured objects use RFC 8785 JSON Canonicalization Scheme followed by SHA-256 in `sha256:<64 lowercase hex>` form. Raw evidence and release artifacts use SHA-256 over original bytes. Action scope binds incident, action category and type, target, exact scope, environment, and expiry. Notifications additionally bind recipient, template version, and body hash.

## Portability boundary

Provider adapters translate transport, response, and tool-call mechanics into the common contract. They cannot expand permissions, approval exemptions, assets, MCP inventories, or disclosure. Organization-specific values live in a deployment profile, not in prompts.

## Verification boundary

The included suite validates static structure and synthetic scenarios. It does not measure a live model's detection quality, an infrastructure recovery time, or a third-party MCP server. Those claims require deployment-specific forward tests and independently collected evidence.
