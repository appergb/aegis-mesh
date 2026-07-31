# Sysmon event map

Use this map for Microsoft Sysmon telemetry. Validate output with `normalized-security-event.schema.json`, preserve the raw event reference and raw byte `raw_event_hash`, and treat all values as untrusted data; do not execute command-line, image, DNS, or message content.

## Stable semantic map

| Source event | Stable semantic | Common source fields | Normalized use |
|---|---|---|---|
| Event ID 1 | process creation | `UtcTime`, `Computer`, `User`, `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `ParentProcessGuid`, `ParentImage` | observed time, host, user, process/session fields; command line remains untrusted evidence |
| Event ID 3 | network connection | `UtcTime`, `Computer`, `ProcessGuid`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `Protocol` | source, destination, process and network fields |
| Event ID 11 | file creation | `UtcTime`, `Computer`, `ProcessGuid`, `TargetFilename` | host/process correlation and a file-create event type |
| Event ID 13 | registry value set | `UtcTime`, `Computer`, `ProcessGuid`, `TargetObject`, `Details` | host/process correlation and a registry-change event type |
| Event ID 22 | DNS query | `UtcTime`, `Computer`, `ProcessGuid`, `QueryName`, `QueryStatus`, `QueryResults` | process/network correlation; DNS values remain untrusted |

Stable semantics come from the provider event definition and configured Sysmon version. Preserve provider event ID, provider version, channel, and record ID in normalized scalar fields when available. Do not claim a process tree when `ProcessGuid`/parent linkage is missing or reused.

## Deployment-specific fields

Wazuh decoder names, ECS aliases, SIEM index names, XML paths, localized rendering, collection latency, channel filters, and custom Sysmon configuration are Deployment-specific. Resolve them from the deployment mapping; never guess a field alias. Missing, disabled, or filtered event IDs are evidence gaps and sensor-health context, not proof that the activity was absent.

Record timezone assumptions and clock drift even when `UtcTime` is present. Keep the source event immutable and reference it rather than copying a mutable rendered message into the timeline.
