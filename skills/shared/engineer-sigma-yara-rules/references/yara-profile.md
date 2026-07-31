# YARA profile

## Pinned compiler

Compile with yara-python 4.5.4 as pinned in `configs/standards_versions.yaml`. Reject warnings or compile errors before scanning fixtures. Do not load external modules, include remote files, or scan uncontrolled paths.

## Required rule content

Use a legal identifier. Metadata records evidence source, sample hash, author, date, version, false-positive notes, and performance budget. Use discriminating strings with explicit encodings/modifiers. Bound the intended file type and file size in the condition; avoid broad single-string matches. Keep raw samples outside Git and reference their byte hash.

The condition must express the complete Boolean relationship among file signature, size bound, and strings. A configured performance budget limits input size and scan behavior; if the production budget is absent, stop at `experimental` instead of inventing one.

## Synthetic profile fixtures

Compile both committed rules with yara-python 4.5.4. `yara-valid.yar` requires a synthetic PE-like text prefix plus a discriminating synthetic marker and must not match the benign fixture. `yara-high-fp.yar` intentionally matches a common benign synthetic marker and must remain failed. These text fixtures are synthetic and contain no genuine malware, operational telemetry, identifying data, credential material, or runtime credential.

Record compile, positive, negative, configured performance, human review, staging, and rollback/disable evidence in the release gate. Compilation alone never makes a rule production-ready.
