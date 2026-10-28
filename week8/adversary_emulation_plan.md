# Adversary Emulation Plan — Phishing Infrastructure

## 1. Purpose and research question

This Week 8 plan organizes a hypothetical phishing-infrastructure incident into defensible MITRE ATT&CK stages. **Research question:** Can a defender correlate controlled link navigation, task-scheduling changes and staged test-data movement using its available telemetry? This is a *plan* for later assessment, not a claim of attack execution.

## 2. Scope, assets and rules of engagement

- **Environment:** isolated authorized training setup; a web training page; an optional Linux/macOS test endpoint; an offline or lab-only evidence collector and Splunk instance.
- **Authorized data:** a clearly labeled dummy text file, such as `W8_DECOY_ONLY.txt`, containing no personal or secret data.
- **Prohibited:** real credential collection, third-party system access, malware, real phishing delivery, uncontrolled persistence, destructive actions and uploads to public services.
- **Safety controls:** record lab ownership and approvals; prepare snapshots where relevant; stop if network access leaves the isolated environment; review and remove any benign test artifacts after authorized validation.
- **Execution status:** nothing described for Week 8 has been executed unless separately documented with actual logs and timestamps.

## 3. Context and evidence inherited from Weeks 5–7

**Week 5** used Splunk for hypothesis-driven hunting on DNS and proxy event data. **Week 6** demonstrated access to a controlled training link and reviewed HTTP events as *partial* T1566.002 evidence. The training page did not demonstrate a phishing message, payload execution or compromise. **Week 7** studied MITRE CAR mapping with a public JSON host-discovery sample. None of these independently proves persistence or exfiltration in this Week 8 scenario.

## 4. Hypothetical sequence

### Stage A — Initial Access: T1566.002 (Spearphishing Link)

**Threat behavior:** a phishing message directs a target toward a deceptive link.  
**Safe representation:** describe an authorized training-link interaction; reuse Week 6 HTTP evidence only as a prior navigation example. Do not send deceptive messages or assume the user was compromised.  
**Potential signals:** messaging gateway event linked to an URL (if separately available), DNS lookup, proxy/web request, referrer and timestamp.  
**Validation:** establish the lab URL and observed HTTP event; label the broader technique **partial representation** unless message delivery and any subsequent compromise are independently established.

### Stage B — Persistence: T1053.003 (Scheduled Task/Job: Cron)

**Threat behavior:** a recurring task could re-launch activity on a Unix-like endpoint.  
**Safe representation:** document a harmless scheduled marker task in an **authorized Linux/macOS test machine**; do not provide or deploy a hidden job. This is a future controlled check, separate from the Week 6 web browser demonstration.  
**Potential signals:** crontab configuration change, scheduler/audit event, process execution and timestamp.  
**Validation:** when authorized, compare scheduled-task metadata and any marker result; confirm removal afterwards. No current detection can be claimed from Week 5 proxy logs alone.

### Stage C — Collection: T1005 (Data from Local System)

**Threat behavior:** an adversary may locate local files before transfer.  
**Safe representation:** create a fictional lab-only marker file and describe its access or staging in a sandbox.  
**Potential signals:** file access (if auditing is enabled), process metadata, timestamp and designated test path.  
**Validation:** confirm that only the declared dummy artifact is referenced, without opening real private files.

### Stage D — Exfiltration: T1048.003 (Unencrypted Non-C2 Protocol)

**Threat behavior:** data could leave a host using an unencrypted protocol, such as HTTP, that is **not** the existing command-and-control channel.  
**Safe representation:** specify a prospective lab-only HTTP transfer of the dummy artifact to a separately approved local receiver, without implementing it in this Week 8 plan.  
**Potential signals:** outbound HTTP request, destination, source, request method, recorded bytes, time and receiver-side confirmation.  
**Validation:** a future authorized exercise must prove the receiver obtained the exact dummy data and that the transfer was outside any C2 channel. A website visit alone is *not* evidence of exfiltration.

## 5. ATT&CK summary

| Order | ATT&CK tactic | ID | Technique | State |
|---|---|---|---|---|
| A | Initial Access | T1566.002 | Spearphishing Link | Week 6 partial navigation reference |
| B | Persistence | T1053.003 | Scheduled Task/Job: Cron | Planned |
| C | Collection | T1005 | Data from Local System | Planned |
| D | Exfiltration | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Planned |

These are *conceptual stages*, not evidence that Stage A caused B–D. Details are in [attack_mapping.md](attack_mapping.md).

## 6. Detection and correlation

Use a time-bound incident timeline joining verified hostname, timestamp, training URL, process/task identifier and **only if available** destination and data-transfer records. Splunk field names differ by sourcetype, so detection queries must first be adapted to actual indexed fields. See [detection_strategy.md](detection_strategy.md).

## 7. CALDERA modeling

In CALDERA terminology an **ability** represents one test behavior; an **adversary profile** sequences reviewed abilities; an **operation** tests them against authorized agents. Our proposed profile describes these objects only. No CALDERA server, agent, ability or operation has been installed or run for Week 8. See [caldera_profile.md](caldera_profile.md).

## 8. Success criteria and reporting

| Check | What counts as evidence | Current result |
|---|---|---|
| Required phases documented | A/B/D with accurate ATT&CK IDs | Met by this plan |
| Prior link-navigation evidence distinguished | Week 6 HTTP visit labeled partial | Described, not revalidated here |
| Persistence validation | Scheduler change + benign marker + cleanup | Not executed |
| Collection validation | Dummy file access/staging audit | Not executed |
| Transfer validation | Receiver confirmation + network records | Not executed |
| Splunk correlation | Saved searches over real matched events | Not executed for Week 8 |

## 9. Limitations and future work

Splunk DNS/proxy events cannot prove an endpoint cron job without additional endpoint telemetry. Week 7 public CAR data is not part of the same attack timeline. The planned Linux/macOS cron behavior cannot be inferred from Windows-only logs. For a future exercise, obtain authorization, choose the actual host/collector configuration, validate field names and compare detection outcomes to the documented criteria. Record failures as failures.

## 10. Conclusion

The plan fulfills the required **Initial Access → Persistence → Data Exfiltration** progression, with Collection added for clarity. Its value is a measurable defensive checklist; its limitation is that it has not yet been executed as a correlated incident.

## Sources

- https://attack.mitre.org/techniques/T1566/002/
- https://attack.mitre.org/techniques/T1053/003/
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1048/003/
- https://caldera.readthedocs.io/en/stable/
- Local project context: Weeks 5–7 project documentation (consult the original evidence before claiming results).
