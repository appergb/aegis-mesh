# Threat model

System: `[system-id]`
Status: `incomplete`

Use `status: incomplete` until required inventories and all six STRIDE dispositions are complete.

## Scope

- In scope: `[system components and flows]`
- Evidence references: `[source references]`

## Assumptions

- `[explicit, testable assumption]`

## Unknowns

- `[missing or unverified fact]`

## Explicit exclusions

- `[out-of-scope item and reason]`

## DFD inventory

| Type | Stable ID | Name or route | Classification / identity / boundary | Existing controls | Evidence |
|---|---|---|---|---|---|
| `[entity/process/store/flow/boundary/asset/classification/identity/control]` | `[id]` | `[name]` | `[references]` | `[control IDs]` | `[reference]` |

Missing inputs: `[trust boundaries, data classifications, calling identities, or other gaps]`

## STRIDE coverage

| Element ID | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|---|---|---|---|---|---|---|
| `[id]` | `[disposition]` | `[disposition]` | `[disposition]` | `[disposition]` | `[disposition]` | `[disposition]` |

## Finding record

### `[threat ID]` — `[category]` on `[affected element]`

- Attacker objective: `[defensive summary only]`
- Prerequisites: `[minimum conditions relevant to defense]`
- Existing controls: `[control IDs and evidence]`
- Gap: `[uncontrolled condition]`
- Likelihood: `[configured term or unknown]`
- Impact: `[configured term or unknown]`
- Severity: `[configured term or unknown]`
- Mitigation: `[smallest defensive change]`
- Residual risk: `[configured term or unknown]`
- Owner: `[existing accountable owner or unassigned]`
- Acceptance test: `[observable defensive result]`

## Closed JSON projection

Validate against `schemas/threat-model.schema.json`. Markdown details do not become extra JSON properties; only `threat_id`, `element_id`, `category`, `description`, `disposition`, and `mitigations` are emitted for each threat.

Build the complete root object directly from the schema. The closed projection contains the root metadata and DFD arrays plus threat entries shaped like this example. When required context is absent, keep the corresponding context array empty and provide a non-empty `missing_inputs` list. An internal flow that crosses no trust boundary uses an empty flow-level boundary array without implying missing context.

```json
{
  "threat_id": "[threat-id]",
  "element_id": "[element-id]",
  "category": "[registered-category]",
  "description": "[concise defensive summary and applicability rationale]",
  "disposition": "[registered-disposition]",
  "mitigations": ["[defensive measure or applicability rationale]"]
}
```
