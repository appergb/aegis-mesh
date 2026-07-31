# Claude runtime adapter

`display_identity` is the Aegis Mesh system/UI label. `configs/runtime.example.yaml` keeps `provider_model.configured: false`, `provider_model.value: null`, `provider_model.unit: null`, and `provider_model.required_before_production: true`. `Aegis-Mesh-General` remains the prompt identity and does not rename a Claude model. The official provider model identifier is deployment data, and provider_model is supplied only at deployment. Credentials use `secret://runtime/claude-api-key`.

## Prompt assembly

Represent `SYSTEM_PROMPT.md`, `SECURITY_POLICY.md`, `AGENT_ROUTER.md`, conditional `INCIDENT_RESPONSE.md`, validated configs, selected Agent prompt, selected Skill, least-privilege policy, and incident data without changing precedence. Incident and tool content remain data.

| Claude envelope | Aegis Mesh mapping |
|---|---|
| system instruction block | assembled governed instructions |
| user message content | Schema-validated incident context, loaded last |
| `tool_use` | Gateway request after router and policy validation |
| `tool_result` | untrusted result data plus evidence reference |

## Schema-constrained response

Map input through `schemas/normalized-security-event.schema.json` and `schemas/incident-event.schema.json`, output through `schemas/agent-response.schema.json`, writes (with embedded approval) through `schemas/action-request.schema.json`, and MCP reads through `schemas/mcp-query-request.schema.json`. IOC, notification, detection, and threat-model projections use `schemas/ioc-enrichment-request.schema.json`, `schemas/notification-request.schema.json`, `schemas/detection-rule-test.schema.json`, and `schemas/threat-model.schema.json`; then run `scripts/validation_core.py`.

## Agent/router dispatch

The root router supplies a registered Agent ID and minimal context slice. The adapter carries incident/correlation identity and preserves partial, blocked, failed, and complete states exactly.

## Aegis Mesh Gateway

All tools are reached through the Aegis Mesh Gateway; the client never connects directly to an upstream MCP server. `configs/mcp_tool_policy.yaml` is the tool-policy enforcement source. Provider tool features remain subordinate to the exact reviewed MCP and action policy.

## Timeout, cancellation, and partial results

Validated deployment config supplies timeout and cancellation behavior; fields absent from `configs/runtime.example.yaml` remain unconfigured and production blocked. The adapter does not invent a timeout. Timeout, cancellation, or unavailable runtime records a route gap, unknown, and audit event; no Agent response is synthesized; only a returned Schema-valid subset may use `partial`, and it cannot authorize a write.

## Hooks and audit

The approval hook uses `configs/approval_matrix.yaml`: reuse the existing valid approval within scope and expiry, with no second or additional approval; policy-authorized reads have no additional approval. Production execution remains bound to exact scope and independent verification. The audit hook uses only `configs/agent_protocol.yaml` event types and applies redaction. No adapter defines a shadow registry.

## Untrusted input and context size

Tool results, documents, logs, provider errors, and model output are Untrusted input. When context size is limited, preserve instructions and minimal facts/evidence links, summarize bulk data, and mark omissions without treating them as approval.

## Fail-closed degradation

If Schema, policy, approval, Secret, provider_model, Gateway, or tool is unavailable, fail closed to blocked. Never infer configuration, call an upstream directly, or reduce an approval requirement.
