# Week 8 — MITRE ATT&CK Mapping

## Technique map

| Sequence | Tactic | ID | Exact Enterprise technique | Platform | What the lab would represent | Evidence to seek |
|---|---|---|---|---|---|---|
| A | Initial Access | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Messaging/web; cross-platform | Controlled training URL navigation, not full compromise | Email-link event if available; HTTP/DNS events |
| B | Persistence | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job: Cron | Linux/macOS | Clearly labeled benign scheduled marker on an authorized host | Cron/task-change audit and process logs |
| C | Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Multiple platforms | Reference only fictional lab file | File access or staging logs if enabled |
| D | Exfiltration | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Multiple platforms | Proposed HTTP transfer of dummy data to approved lab receiver | Proxy/network bytes + receiver confirmation |

## Accuracy notes

1. **T1566.002** is primarily a phishing-link delivery technique. Week 6's visited link alone supports only partial emulation and no successful initial compromise.
2. **T1053.003** refers to Cron; use **T1053.005** instead *if* the future target is Windows Task Scheduler. The Week 8 proposal intentionally assumes Unix-like persistence.
3. **T1005** requires a file-collection behavior; the existence of a file without access evidence does not prove collection.
4. **T1048.003** requires exfiltration over an unencrypted **non-C2** channel. Local file copies or normal page views do not satisfy it. A controlled transfer remains a prospective simulation rather than stolen data.
5. Do not conflate ATT&CK **tactics** with *observed incidents*. These IDs classify hypothesized behavior; logs must support claims of actual occurrence.

## Coverage snapshot

| Stage | Prior project coverage | Remaining evidence gap |
|---|---|---|
| A | Week 6 controlled training-link HTTP visit | Delivered message and compromised host not established |
| B | No confirmed cron activity in Weeks 5–7 | Need scheduler/audit events |
| C | No verified Week 8 file-collection run | Need harmless file access evidence |
| D | Prior proxy dataset existed in Week 5 | Need a distinct lab transfer, receiver and matching logs |
