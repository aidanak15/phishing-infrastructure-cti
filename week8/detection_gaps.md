# Detection Gaps and Proposed Improvements

**Assessment status:** design review; **not** a measured Week 8 detection experiment. No Week 8 CALDERA operation or exfiltration has been run.

| Stage | Current evidence from prior work | Gap / uncertainty | Proposed defensive validation | Status |
|---|---|---|---|---|
| Infrastructure context (T1583.001, T1608.005) | Week 5 DNS/proxy datasets; Week 6 training webpage | No verified domain acquisition, CT/RDAP chronology, or complete phishing infrastructure timeline | Enrich *known, permitted* domains with public contextual data and check fields against raw log records | Proposed |
| Initial Access (T1566.002) | Week 6 HTTP training-link visit and Splunk search results | No email delivery evidence, no demonstrated compromised host | Link approved test-message metadata to a test URL visit only if both sides are logged | Partially observed / proposed |
| Persistence (T1053.003) | No Week 8 host scheduler telemetry | No cron creation/execution events and no host-to-link chain | Use a non-executing sample of scheduler telemetry or an approved benign lab marker; validate source fields before writing an SPL rule | Not tested |
| Collection (T1005) | No recorded collection actions | Cannot identify real file access or source host | Use fictional file activity sample with known timestamps and explicitly synthetic labels | Not tested |
| Exfiltration (T1048.003) | Prior proxy data not tied to Week 8 operation | No proof of file transfer, receiver match, or outbound non-C2 channel | In a future authorized lab, compare sender, receiver, byte count and timestamps for a harmless test file | Not tested |

## Defensive priorities

1. **Evidence integrity:** label public, synthetic, and live lab data separately; document source and collection time.
2. **Field validation:** inspect actual Splunk fields (`index`, `sourcetype`, URL/host/IP fields) before adapting searches. Do not assume Linux host logs are in the earlier `phishing_logs` index.
3. **Cross-stage correlation:** correlate only events that truly share test host identifiers and a defensible time window.
4. **Coverage tracking:** record `planned`, `observed`, `detected`, and `not tested` separately. A mapped ATT&CK technique does not imply a successful detection.
5. **Safety and cleanup:** any later simulation must use an isolated authorized machine and fictional data, with artifacts removed afterwards.

## Week 9 handoff (proposal only)

Validate one benign telemetry example for persistence and one for data-transfer visibility; preserve source log snippets and annotate false positives / missing fields. CALDERA may be investigated separately but is not required to claim Week 8 documentation complete.
