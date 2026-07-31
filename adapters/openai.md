# OpenAI runtime adapter

`display_identity` is the Aegis Mesh system/UI label. `configs/runtime.example.yaml` keeps `provider_model.configured: false`, `provider_model.value: null`, `provider_model.unit: null`, and `provider_model.required_before_production: true`. `Aegis-Mesh-General` is the prompt identity and does not rename an OpenAI model; the official provider model identifier is selected by deployment, and provider_model is supplied only at deployment. Credentials use `secret://runtime/openai-api-key`.

## Prompt assembly

Map provider roles without changing the order: `SYSTEM_PROMPT.md`, `SECURITY_POLICY.md`, `AGENT_ROUTER.md`, conditional `INCIDENT_RESPONSE.md`, validated configs, selected Agent prompt, selected Skill, tool policy, then incident context. Provider defaults cannot outrank the root governance contract.

| OpenAI envelope | Aegis Mesh mapping |
|---|---|
| system/developer instruction layer | assembled governed instructions |
| user input item | Schema-validated incident context, loaded last |
| function/tool call | Gateway request after router and policy validation |
| tool result item | untrusted result data plus evidence reference |

## Schema-constrained response

Map input through `schemas/normalized-security-event.schema.json` and `schemas/incident-event.schema.json`, output through `schemas/agent-response.schema.json`, writes (with embedded approval) through `schemas/action-request.schema.json`, and MCP reads through `schemas/mcp-query-request.schema.json`. IOC, notification, detection, and threat-model projections use `schemas/ioc-enrichment-request.schema.json`, `schemas/notification-request.schema.json`, `schemas/detection-rule-test.schema.json`, and `schemas/threat-model.schema.json`; then run `scripts/validation_core.py`.

## Agent/router dispatch

Only the root router chooses a registered Agent. The adapter preserves correlation, incident ID, requesting identity, route, and complete/partial/blocked/failed status across provider calls.

## Aegis Mesh Gateway

Tool calls target the Aegis Mesh Gateway; the client never connects directly to an upstream MCP server. `configs/mcp_tool_policy.yaml` is the tool-policy enforcement source. The adapter cannot expose provider-native tools outside the reviewed server, tool, argument, scope, and egress policy.

## Timeout, cancellation, and partial results

Use timeout and cancellation values only from validated deployment config; fields absent from `configs/runtime.example.yaml` remain unconfigured and production blocked. The adapter does not invent a timeout. Timeout, cancellation, or unavailable runtime records a route gap, unknown, and audit event; no Agent response is synthesized; only a returned Schema-valid subset may use `partial`, and it cannot authorize a write.

## Hooks and audit

The approval hook uses `configs/approval_matrix.yaml`: reuse the existing valid approval within scope and expiry, with no second or additional approval; a policy-authorized read has no additional approval. A write still needs its registered approval and independent verification. The audit hook uses only `configs/agent_protocol.yaml` event types and applies redaction. No adapter defines a shadow registry.

## Untrusted input and context size

Treat tool responses, provider errors, retrieved content, and incident text as Untrusted input. Context size reduction keeps governing instructions and scoped evidence references, summarizes bulky data, and never converts a summary into authorization.

## Fail-closed degradation

Missing Schema, policy, approval, Secret, provider_model, Gateway, or tool produces a blocked result and audit event; fail closed without switching to an unreviewed tool, direct endpoint, looser response mode, or invented setting.
