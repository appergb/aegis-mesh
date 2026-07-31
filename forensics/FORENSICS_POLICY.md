# Forensic source fingerprinting and custody policy

## Scope and attribution boundary

This package processes passive telemetry already collected from owned or explicitly authorized assets only. No active intrusion, hack-back, counterattack, scanning of non-owned assets, or personal identity inference is permitted.

A single IP, ASN, region, TLS, JA3, JA4, or transport fingerprint cannot establish a person's identity. NAT, shared networks, proxies, VPNs, Tor, compromised hosts, botnets, and provider reassignment make that inference unreliable. Classification describes observed infrastructure behavior, not a natural person or a final legal conclusion. `confirmed-malicious` requires independent supporting evidence and the configured transition policy.

Do not collect or embed passwords, private keys, full Authorization headers, full cookies, plaintext tokens, unnecessary request bodies, precise addresses, coordinates, names, personal email addresses, or phone numbers. User-agent, account, session, and device values are deployment-keyed HMAC pseudonyms; keys and raw identifiers never enter this package.

## Evidence reference and hash rules

The three forensic schemas reuse the base six-field evidence reference without adding fields or changing its opaque `evidence://` URI. Raw evidence uses SHA-256 of the original bytes. Structured fingerprints, events, and manifests use RFC 8785 JSON Canonicalization Scheme before SHA-256 and the form `sha256:<64 lowercase hex>`. Re-serializing raw evidence before hashing is prohibited.

`fingerprint_hash` is the JCS SHA-256 of the complete fingerprint after removing only its top-level `fingerprint_hash`; `supersedes_fingerprint_hash` remains in the projection. `event_hash` is the JCS SHA-256 of the complete custody event after removing only its top-level `event_hash`. The first `previous_event_hash` is `null`; each later value equals the prior event's `event_hash`, and `chain_head_hash` equals the last event hash. These rules avoid self-reference without weakening the chain.

`raw_evidence_ref.incident_id` must match the fingerprint incident and its `content_hash` must match the fingerprint `content_hash`. Time ordering, incident binding, proxy trust, CIDR containment, sensitive-value rejection, and hash-chain linkage are enforced automatically by `scripts/validation_core.py`; JSON Schema covers only expressible structure.

## Simple ownership model

Observability Agent and registered collectors append raw evidence-reference metadata. Threat Intelligence Agent appends versioned derived source fingerprints. Incident Response Agent appends custody and lifecycle events. Corrections create a new version linked to the superseded hash; no record is overwritten. These responsibilities do not introduce a new approval round.

Every custody event records actor, timestamp, action, reason, one approval reference, input/output hashes, storage reference/version, transformation note, previous-event hash, and event hash. Collection, transform, access, export, and delete share this one event shape. Export and delete use the approvals already required by governance; the forensic package does not add another reviewer or repeated approval.

## Governance defaults

`configs/forensics_policy.yaml` is authoritative. No shadow roles, thresholds, approval classes, or classification states may be invented.

- Retention is currently `configured: false`; no production retention schedule or automatic deletion is claimed.
- RBAC is deny by default and has no grants. Deployment owners must configure finite retention and least-privilege grants before production.
- Pseudonymization is enabled and direct identity inference is forbidden.
- Legal Hold blocks ordinary deletion. Changing it uses the existing `two_person_high_impact` class.
- export remains denied until two-person irreversible approval; disclosure is limited to the approved evidence IDs and minimum fields.
- delete remains denied until two-person irreversible approval and provider verification. Deletion appends proof or a tombstone and never removes custody history.

A single bounded action uses its one valid governance authorization reference. The package must not split it into extra forensic approvals or send it through repeated manual review.

## Storage and repository boundary

Git is not an evidence store. Only synthetic examples are committed. `forensics/records/` contains only its deny-all `.gitignore`; real records are runtime-mounted to an access-controlled, encrypted, audited, immutable-versioned evidence store. The static package fixes `production_gate` to `false`; only a separately verified deployment contract may change that state, and this package cannot claim production readiness.

Exports are minimized and redacted. Interfaces should hide full IP values by default. Legal Hold history is append-only. No role may overwrite earlier fingerprints, events, manifests, exports, or deletion proofs.
