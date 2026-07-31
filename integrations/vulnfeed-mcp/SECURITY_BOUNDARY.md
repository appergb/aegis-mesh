# VulnFeed security boundary

The Gateway, not the model, resolves an approved `owned_asset_id` of type `lockfile`. It verifies the registry owner, proof, approval, validity, immutable path and expected raw-byte SHA-256. An incident IOC, model-supplied path, project directory or unregistered file cannot substitute for that asset.

The future wrapper must reject symlinks in the file or any path component, require a regular file whose canonical path is inside the approved root, verify raw-byte SHA-256 before and after copying, and place only that file in a per-call dedicated read-only directory. It exposes no repository, other lockfile, user home or Secret path. Only the isolated copy path is supplied upstream.

The wrapper forces `show_all=true`; the model cannot change it. Complete findings are normalized before summarization, so response-size handling cannot silently restore the upstream low-EPSS filter.

Only an exact deployment-approved HTTPS backend may receive package name, exact version and ecosystem. `VULNFEED_WORKER_URL`, `WORKER_URL`, `VULNFEED_TRANSPORT`, `VULNFEED_API_KEY` and `WORKER_BOOTSTRAP_KEY` are removed from the v1 upstream environment; the model cannot alter transport or endpoint, inherit a paid credential, or activate a paid feature. By default, private package names and internal project names stay blocked until the vendor-data review is complete.

Wallet, x402, payment proxy and automatic payment are absent. Any HTTP 402 is normalized to a non-executable budget alert and failed result; the Gateway drops payment challenges and will never pay, retry with payment, switch to a paid tool, or create an artificial payment-approval chain.

EPSS describes the predicted probability that a public CVE will be exploited in the future 30 days; it does not prove known exploitation. Only CISA KEV or a verified vendor advisory may set `known_exploited=true`. EPSS probability, percentile and data date remain separate fields. Third-party descriptions, URLs and error bodies are untrusted, filtered, redacted and audited.
