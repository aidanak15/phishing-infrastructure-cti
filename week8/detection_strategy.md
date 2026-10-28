# Week 8 — Splunk Detection Strategy (Planned)

## Principle

The goal is to specify **what would be checked**, not to claim attacks were performed or detected. The earlier `phishing_logs` index included DNS and proxy-type events, but its exact field extractions and `sourcetype` values should be verified before running these examples. For network evidence, check that records actually contain `url`, `host`, `uri`, `src_ip`, `dest_ip`, `method`, `bytes_out` or their equivalents.

## Data needed

| Phase | Data source | Fields to confirm |
|---|---|---|
| Initial Access | HTTP/proxy and optionally mail gateway | `_time`, training URL/host, `src_ip`, action |
| Persistence | Unix scheduler/audit logs (new source) | `_time`, host, task identity, actor, result |
| Collection | File audit (new source) | `_time`, host, dummy file path, process/action |
| Exfiltration | HTTP/proxy/network logs + receiver audit | `_time`, destination, method, bytes, receiver result |

## Illustrative read-only SPL searches

These are **templates** to adapt to actual data, not verified detections. They do not generate events or perform attacks.

### Q1: Inventory existing events in the old project index

```spl
index=phishing_logs earliest=-30d
| stats count by sourcetype
| sort - count
```

If old project data is older than 30 days, replace the time range with an explicitly recorded historical period or `All time` in Splunk UI.

### Q2: Find the controlled training URL if HTTP fields exist

```spl
index=phishing_logs earliest=0
| eval requested_url=coalesce(url, uri, request, http_url)
| search requested_url="*training*"
| table _time sourcetype src_ip requested_url action status
| sort _time
```

**Interpretation:** this identifies records matching an example training substring. Confirm the exact authorized hostname and field names using the original Week 6 data; a match proves navigation/logging, not compromise.

### Q3: Baseline traffic destinations (exploratory only)

```spl
index=phishing_logs earliest=0
| eval destination=coalesce(dest_ip, dst_ip, destination_ip, host)
| stats count by destination sourcetype
| sort - count
```

**Interpretation:** possible network investigation starting point; no exfiltration detection claim.

### Planned Q4: Unix scheduler records — only if indexed later

```spl
index=<LAB_ENDPOINT_INDEX> sourcetype=<VERIFIED_CRON_SOURCETYPE>
| table _time host user action message
| sort _time
```

`<...>` placeholders must be replaced after checking real ingest configuration. This is a monitoring *design*, not a runnable SPL query until configured.

### Planned Q5: Correlate approved transfer events — only if indexed later

```spl
index=<LAB_NETWORK_INDEX> sourcetype=<VERIFIED_HTTP_SOURCETYPE>
| table _time src_ip dest_ip http_method url bytes_out status
| sort _time
```

For a future lab test, inspect the exact approved destination and compare source/request metadata to the receiver-side record. Do not equate arbitrary POSTs with exfiltration.

## Success metrics for future exercise

- **Visibility:** telemetry captured at each stage (yes/no).
- **Correctness:** matching hostname, URL, marker ID, time range and receiver confirmation.
- **Detection:** relevant rule or analyst query returns the expected records (yes/no), with screenshots and timestamps if run.
- **Cleanup:** no scheduled test artifacts left behind (yes/no).

## Expected gaps

Current Week 5 proxy and DNS logs do not alone establish cron changes or local file reads. Additional authorized endpoint auditing would be required. The Week 7 public CAR sample should not be correlated into the same timeline as if it were produced by the Week 8 scenario.

## Reference

- https://attack.mitre.org/detectionstrategies/DET0149/
