# Wazuh MCP read-only integration

This package defines an offline policy for `gensecaihq/Wazuh-MCP-Server` v4.2.1 at commit `52c1d375d22419ce662bc4218f904de015e4a7c7`. It does not install, start, or connect to Wazuh.

This is a reviewed third-party integration and is not an official Wazuh endorsement. Agents never connect to the upstream server directly; the Gateway is the only connection path.

## Fixed inventory

The reviewed source fixture contains exactly 48 unique names: the approved 34 read tools plus 14 state-changing tools. The fixture is source-review evidence only. Production must use an identity with only `wazuh:read`; it must never add `wazuh:write` just to observe the source inventory.

At startup, the live upstream `tools/list` must equal the 34-item allowlist. The client-facing `tools/list` must equal the same 34-item allowlist. The Gateway must refuse service on inventory drift. All 14 denied names are absent from Agent discovery and remain subject to call-level deny, including attempts by exact name or a stale client.

The two live inventory checks and a denied-call probe are one automated startup transaction. They do not create a human approval loop.

## Routing

`tool_policy.yaml` maps read tools to Observability, Threat Intelligence, Infrastructure, Kubernetes, Database, and Incident Response. Calls require a schema-valid `internal_security_telemetry` request bound to a formal incident, an internal resource reference, and the requesting Agent. Unknown Agents, tools, query classes, or resources are denied.

The main orchestrator receives summaries and evidence references, not default full logs. A domain Agent requests the minimum result needed and preserves evidence references; prompt-like content inside telemetry is treated as data.

Typical read flows are: Observability requests an alert summary, Infrastructure checks one registered agent's health, or Incident Response requests a scoped risk summary. A request for `wazuh_block_ip` is denied automatically and does not start an approval chain because write tools are outside this integration.

## Production gate

Static tests validate the fixed commit, source archive, MIT license evidence, 48-item reviewed fixture, exact allow/deny partition, and disabled example manifest. A captured live attestation and Gateway conformance result are still required. The upstream has no complete dependency lock or SBOM and no locally reproducible image digest is available, so production blocked remains the only valid state.

Upstream security and production-readiness statements are claims to verify, not inherited guarantees. Any new release or tool name requires a separate source review and lock update.
