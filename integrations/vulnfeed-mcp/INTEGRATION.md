# VulnFeed lockfile MCP candidate integration

The requested `infai-tech/vulnfeed-mcp` repository redirects to the reviewed `novadyne-hq/vulnfeed-mcp` repository. This package records a static review of commit `aa2452d724b29a6ee3e2bb68187c783ef2bb8847`, whose source version is 0.3.7. It does not use the older v0.3.1 release, a floating package, `main`, or `uvx vulnfeed-mcp`.

The fixed source is MIT licensed. Its registered inventory is `9 = 1 allowed + 8 denied`: only `scan_lockfile` is a candidate. Project traversal, individual package lookup, paid CVE lookup, persistent monitoring, update and unmonitor operations are denied at call level. The client-facing inventory must contain only `scan_lockfile`, and inventory drift refuses startup.

The candidate is local stdio and disabled by default. The future Gateway wrapper resolves one registered immutable lockfile asset, checks its approval, ownership, expiry and raw-byte hash, and exposes only an isolated read-only copy. This is a policy contract; the wrapper and its live conformance evidence do not exist in this package, so production blocked remains the honest state.

The upstream parser sends package name, exact version, and ecosystem to its third-party backend. The original lockfile and source code do not leave the boundary, but these package coordinates are SBOM-like disclosure. Vendor retention, isolation, region, DPA, training use and private-package handling must be reviewed before production.

The scan is a `policy_authorized_read` and requires no additional human approval. There is no wallet, x402 client, payment proxy, automatic purchase, persistent monitor, or arbitrary runtime budget in this integration. Missing deployment facts remain null instead of creating extra approval steps or invented numbers.
