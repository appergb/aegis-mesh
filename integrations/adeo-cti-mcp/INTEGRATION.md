# ADEO CTI MCP candidate integration

This package records an offline review of `ADEOSec/mcp-shodan` commit `ba7c6962c7bcb69964a44da9228cf5d43b7e7606`. It does not copy, patch, install, run, or connect to the upstream code. This is a third-party candidate, not an endorsement by Shodan or VirusTotal.

## License evidence

The license unresolved state is mandatory: the fixed commit has no LICENSE file, `package.json declares MIT`, while the `README states All rights reserved`. Until the copyright holder supplies compatible permission, the source cannot be copied into a fork or production artifact.

The same commit has mismatched root dependencies between `package.json` and `package-lock.json`; Docker and Smithery arguments also differ from the source interface. These are recorded as evidence gaps rather than fixed by this repository.

## Candidate surface

Static source review found `36 = 8 retained + 28 removed`, plus `14 prompts` and `3 resources`. The eight retained names are passive candidates only. In a future licensed safe fork, the other tools, every prompt, and every resource must be physically removed; hiding them in a client is insufficient. The fork's live tools list must be exactly eight and its prompt/resource lists empty.

`vt-readonly-url-report` is a separate Aegis Mesh Gateway specification and is not part of the upstream 36 or future fork eight. It never reuses the upstream URL-analysis tool.

## Query flow

All calls use the Aegis Mesh Gateway and the existing `policy_authorized_read` path. Shodan candidates require a registered owned asset. VirusTotal candidates require a type-matched incident IOC or, only for IP/domain, an exact verified owned asset. Results are passive, minimized, redacted, audited, and treated as untrusted data.

These reads require no additional human approval. Missing license permission, safe fork, credential fix, accepted dependency lock, SBOM, reproducible artifact, deployment configuration, live inventory, or Gateway conformance keeps production blocked. Static tests do not represent live conformance.
