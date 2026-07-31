# Security policy

## Supported versions

Security fixes are applied to the latest tagged release and `main`.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability or exposed secret. Use GitHub's private vulnerability reporting for this repository. Include the affected version, impact, reproduction steps using synthetic data, and a suggested mitigation if available.

Do not test against systems you do not own or have explicit authorization to assess. Do not include credentials, production evidence, personal data, or exploit activity against third parties.

Maintainers will acknowledge a report when capacity permits, validate it, coordinate a fix and advisory, and credit reporters who request attribution. This document does not promise a response time or bounty.

## Operational scope

The repository is a static defensive package and is production blocked by default. A deployment is responsible for model, gateway, credentials, asset authorization, legal review, evidence storage, monitoring, rollback, and live conformance.
