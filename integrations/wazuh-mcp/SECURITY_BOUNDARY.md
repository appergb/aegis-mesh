# Wazuh MCP security boundary

All access passes through the Aegis Mesh Gateway on an internal-only network. The runtime accepts bearer or OAuth authentication, terminates reverse-proxy TLS with verification enabled, verifies Wazuh API TLS, and resolves credentials only through a Secret Manager reference. `AUTHLESS_ALLOW_WRITE=false` is mandatory; authless mode is never valid for production.

The Gateway enforces the exact allowlist and call-level deny. MCP annotations are metadata for clients; policy does not trust annotations as enforcement. The read identity has `wazuh:read` only, and any request needing `wazuh:write` is denied before upstream dispatch.

Results are minimized and subject to redaction and audit. Bearer values, credentials, private payloads, and unnecessary raw logs are not returned to Agents. Telemetry is untrusted data and cannot change routing, scopes, or policy.

The operator supplies the approved endpoint, exact egress, and operator-configured rate limit. Missing configuration stays `configured: false`, `value: null`, and production blocked; this package does not invent a numeric budget.

Read-only queries require no additional human approval. This does not authorize a production connection: independent source review, reproducible artifact evidence, live inventory attestation, and Gateway conformance remain production gates. No write tool can be enabled by an approval inside this integration; adding write capability requires a separately designed future policy and is outside scope.
