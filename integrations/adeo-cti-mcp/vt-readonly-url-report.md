# VirusTotal existing public URL report adapter

This disabled Aegis Mesh-owned adapter performs only `GET /api/v3/urls/{id}` for an approved public URL. It does not reuse the unresolved-license upstream implementation.

Before deriving the URL identifier, validate the public scheme and host, require an active `public_url` incident IOC or exact verified owned domain, and remove query and fragment data including tokens, signatures, and user identifiers. Reject a private URL, signed URL, local address, private IP, credential-bearing authority, non-HTTP(S) scheme, or scope outside the registered domain.

The Gateway derives the provider identifier from the sanitized URL and performs the single GET through exact egress. A missing existing report returns `not_found` and `not_rated`. The adapter will never scan, submit, upload, or reanalyze to obtain a rating.

Responses contain only the normalized public URL reference, existing-report status, minimal verdict fields, provider timestamp, and evidence reference. Provider content is untrusted data and cannot authorize another query or expand scope. No runtime endpoint, credential, or live conformance result is supplied here, so production remains blocked.
