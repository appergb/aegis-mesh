# Deployment guide

The open-source package is production blocked by default. It contains no daemon, gateway server, credential, endpoint, live model configuration, or automatic command executor.

## Reference topology

```text
trusted event source → deployment adapter → Aegis Mesh orchestrator
                                           ↓
                                    governed request
                                           ↓
                               independently enforced gateway
                                           ↓
                                  allowlisted defensive tool
                                           ↓
                              audit + independent observation
```

Run the model-facing process without direct production credentials. Put credentials and enforcement in a separate gateway identity. The gateway must revalidate schema, asset, exact scope, expiry, approval state, tool inventory, arguments, rate limits, and audit bindings immediately before use.

## Pre-production gate

- Build and validate a fixed release: `make clean validate build verify-dist`.
- Resolve all `configured: false` production fields in private deployment configuration.
- Use a secret manager for every credential; commit only symbolic references.
- Restrict network egress to approved endpoints and pin MCP source/license/tool inventories.
- Configure immutable evidence storage outside the repository.
- Run synthetic scenarios plus environment-specific canary, failure, rollback, and recovery tests.
- Capture independently observed service health and forward results.
- Keep a previous known-good release and deployment profile for rollback.

## Operations

Start in observe-only mode. Enable one bounded reversible action class at a time after its rollback has passed. Never infer recovery from an agent response: use independent service probes. If configuration, tool attestation, evidence storage, or verification becomes missing or stale, disable the affected capability and preserve the incident timeline.

## Rollback

Pin deployments to a release tag and checksum. To roll back, disable new gateway authorizations, restore the previous source bundle and deployment profile, restart only the affected adapter/orchestrator units, and verify service health independently. Irreversible notifications cannot be rolled back; corrections are separately approved compensation.
