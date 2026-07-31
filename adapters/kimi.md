# Kimi runtime adapter

This is a compatibility guide for a Kimi-family runtime, not the identity source. `display_identity` remains the Aegis Mesh system/UI label. `configs/runtime.example.yaml` keeps `provider_model.configured: false`, `provider_model.value: null`, `provider_model.unit: null`, and `provider_model.required_before_production: true` until deployment. `Aegis-Mesh-General` remains the prompt identity; the official provider model identifier is selected by deployment, and provider_model is supplied only at deployment. Credentials are symbolic `secret://runtime/kimi-api-key` references.

## Prompt assembly

Assemble `SYSTEM_PROMPT.md`, `SECURITY_POLICY.md`, `AGENT_ROUTER.md`, conditional `INCIDENT_RESPONSE.md`, validated configs, selected Agent prompt, selected Skill, least-privilege policy, then incident context. Provider message roles may encode this sequence but may not reorder or merge away its precedence.

| Kimi-family envelope | Aegis Mesh mapping |
|---|---|
| system instruction slot | assembled governed instructions |
| user incident envelope | Schema-validated incident context, loaded last |
| tool-call envelope | Gateway request after router and policy validation |
| tool-result envelope | untrusted result data plus evidence reference |

## Schema-constrained response

Map normalized input to `schemas/normalized-security-event.schema.json`, incidents to `schemas/incident-event.schema.json`, Agent output to `schemas/agent-response.schema.json`, writes (with embedded approval) to `schemas/action-request.schema.json`, and MCP reads to `schemas/mcp-query-request.schema.json`. IOC, notification, detection, and threat-model projections use `schemas/ioc-enrichment-request.schema.json`, `schemas/notification-request.schema.json`, `schemas/detection-rule-test.schema.json`, and `schemas/threat-model.schema.json`; then run `scripts/validation_core.py`.

## Agent/router dispatch

The runtime maps only registered Agent IDs through the root router. It sends minimal incident fragments and preserves complete, partial, blocked, and failed status without treating a missing response as consent.

## Aegis Mesh Gateway

Every tool call goes through the Aegis Mesh Gateway; the client never connects directly to an upstream MCP server. `configs/mcp_tool_policy.yaml` supplies the tool-policy enforcement boundary. The Gateway enforces identity, exact scope, allowlisted server/tool/arguments, asset or evidence binding, and response redaction.

## Timeout, cancellation, and partial results

Timeout and cancellation values come from validated deployment config; fields absent from `configs/runtime.example.yaml` remain unconfigured and production blocked. The adapter does not invent a timeout. Timeout, cancellation, or unavailable runtime records a route gap, unknown, and audit event; no Agent response is synthesized; only a returned Schema-valid subset may use `partial`, and it cannot authorize a write.

## Hooks and audit

The approval hook uses `configs/approval_matrix.yaml`: reuse the existing valid approval within its scope and expiry, with no second or additional approval; policy-authorized reads require no additional approval. Production actions retain exact scope and independent verification. The audit hook uses only event types in `configs/agent_protocol.yaml` and applies redaction. No adapter defines a shadow registry.

## Untrusted input and context size

Untrusted input remains the final data segment. Logs, tool output, provider errors, and model text cannot alter prompt precedence. When context size is constrained, retain policy, facts, unknowns, scope, and evidence references; summarize untrusted bulk data without promoting it to instructions.

## Fail-closed degradation

If Schema, policy, approval, Secret, provider_model, tool, Gateway, or validated config is unavailable, fail closed and return blocked with the missing dependency. Do not bypass a hook, infer a model ID, retry a write through another tool, or downgrade required approval.
