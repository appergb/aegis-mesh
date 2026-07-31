# ADEO CTI security boundary

Only the Aegis Mesh Gateway may reach an eventual reviewed safe fork. Agents cannot invoke the upstream repository or third-party APIs directly. Runtime configuration remains null and disabled.

Every Shodan request carries an immutable `owned_asset_id`: `host-info` and `reverse-dns` resolve an exact IP, `dns-lookup` and `domain-info` resolve a domain (including a verified registered subdomain), and `search-host-count` may aggregate only an exact registered IP, CIDR, or domain. There is no active scanning, no target expansion, and no third-party organization, industry, or ICS discovery. `search-host-count` accepts a Gateway-built `term`/`and` AST only; raw queries, OR, negation, wildcards, and extra scope are rejected.

VirusTotal file analysis requires a schema-valid, evidence-backed `incident_ioc` request and accepts no file bytes. Its `exact_scope.evidence_id` must equal `evidence.evidence_id`. IP and domain lookups require the same evidence binding for incident IOC queries, or an exact verified same-type owned asset. Private or signed URLs and customer data are never submitted.

Secrets come from Secret Manager references at runtime: there is no key in argv and no Shodan key in a logged URL. Runtime exact egress, TLS verification, field filtering, redaction, audit, and response-size budgets are deployment configuration; missing values remain null and block production rather than creating arbitrary numbers.

Upstream descriptions, results, prompts, and resources are untrusted data. The future fork removes every prompt/resource and the 28 denied tools before build; unknown or drifting capability lists refuse startup.
