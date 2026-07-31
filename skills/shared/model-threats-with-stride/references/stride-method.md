# DFD STRIDE method

## Category review

Review each applicable external entity, process, data store, and data flow against:

- **Spoofing** — false identity or unauthenticated attribution.
- **Tampering** — unauthorized change to code, configuration, state, or data in transit.
- **Repudiation** — inability to establish accountable, integrity-protected activity.
- **Information Disclosure** — exposure beyond the intended identity, purpose, or classification.
- **Denial of Service** — loss or material degradation of intended availability.
- **Elevation of Privilege** — obtaining authority beyond the caller's granted permissions.

Every applicable element receives all six dispositions. A disposition is `mitigated`, `accepted`, `not_applicable`, or `deferred`. `not_applicable` requires a concrete rationale for that element; `deferred` prevents complete status. Distinct findings may share an element and category when they represent different risks; do not merge them merely to reduce row count.

Use trust boundaries, assets, data classifications, calling identities, and controls as referenceable analysis context. They may have specific findings, but they do not require a mechanical six-category matrix.

## Finding record

For each threat ID, record the affected element, attacker objective, prerequisites, existing controls, gap, likelihood, impact, severity, mitigation, residual risk, owner, and acceptance test. Use the system's configured risk vocabulary; use `unknown` when the evidence is insufficient instead of inventing a score.

Attacker stories contain only the minimum detail needed to explain defensive risk and never become third-party attack instructions. Do not provide procedural exploitation, weaponized examples, or secrets.

## Closed JSON projection

The Markdown finding is the editable analysis record. Its schema projection contains only:

| Markdown concept | `schemas/threat-model.schema.json` field |
|---|---|
| threat ID | `threat_id` |
| affected element | `element_id` |
| STRIDE category | `category` |
| concise defensive summary and applicability rationale | `description` |
| decision | `disposition` |
| selected defensive measure or applicability rationale | `mitigations` |

Do not add the richer Markdown fields as JSON properties. Keep the shared threat ID stable so reviewers can trace the projection back to the detailed record.

## Completion check

A model may be `complete` only when:

- scope, assumptions, unknowns, and explicit exclusions are recorded;
- trust boundaries, data classifications, and calling identities are complete;
- DFD references resolve to known IDs;
- each applicable DFD entity, process, data store, and data flow has at least one reviewed finding or disposition for each of the six categories;
- no disposition is `deferred`; and
- the JSON passes structural and semantic validation.

Otherwise set `status: incomplete`, preserve known facts, and list the concrete gaps in `missing_inputs`. Analysis does not create a new approval or action workflow.
