# Sigma profile

## Pinned toolchain

Use `configs/standards_versions.yaml` as the version source: Sigma specification 2.1.0, pySigma 1.4.0, Elasticsearch backend 2.1.0, and Sysmon pipeline 2.0.0. Parse with `SigmaCollection`, apply the registered Sysmon pipeline only to compatible Windows process events, and require successful Elasticsearch/Lucene conversion for the target field mapping. Do not use a floating latest version.

## Required rule content

Every rule includes title, UUID `id`, official status (`experimental` or `test`), description, author, date and modified, evidence-backed references, ATT&CK tags, precise logsource, field-based detection, explicit condition, false positives, and level. The description separates observed behavior from hypotheses. Field mapping must match the configured source and target backend.

Reject free-text-only inputs, unresolved field aliases, missing logsource, invalid UUIDs, unknown tags, unsupported modifiers, unconverted rules, and rules whose negative fixture matches. Lucene conversion success does not prove detection quality; positive, negative, configured performance, human review, staging, and rollback gates remain mandatory.

## Synthetic profile fixtures

The committed synthetic rules exercise a Sysmon process-creation mapping. `sigma-valid.yaml` uses a discriminating synthetic marker and must match only its positive fixture. `sigma-high-fp.yaml` intentionally matches the legitimate maintenance fixture and must remain a failed/test example. The fixtures are synthetic JSON and contain no operational telemetry, identifying record, credential material, or runtime credential.

The fixture suite is a deterministic package test, not a production volume budget. Production performance limits must come from the deployment owner and remain unconfigured until supplied.
