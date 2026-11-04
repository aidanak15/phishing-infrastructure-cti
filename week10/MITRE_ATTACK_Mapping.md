# Week 10 — APT29 MITRE ATT&CK Mapping

**Project:** Cyber Threat Intelligence Analysis of Phishing Infrastructure  
**Analysis type:** Public-source TTP mapping only (no new lab execution)  
**Primary source:** [MITRE ATT&CK APT29 (G0016)](https://attack.mitre.org/groups/G0016/)

## 1. Objective

Map selected techniques documented for APT29 to ATT&CK tactics, phishing-infrastructure CTI needs, and realistic defensive telemetry. This table is a subset of the [G0016 techniques list](https://attack.mitre.org/groups/G0016/); it must not be interpreted as one chronological attack chain.

## 2. ATT&CK Mapping

| Tactic | Technique ID | Technique | Documented behavioral summary | CTI or SIEM evidence to investigate |
|---|---|---|---|---|
| Resource Development | T1584.001 | Compromise Infrastructure: Domains | APT29 used compromised domains as infrastructure in documented campaigns | Domain history, passive DNS, hosting changes, certificate history |
| Resource Development | T1587.001 | Develop Capabilities: Malware | APT29 used custom malware capabilities | Reported file hashes and validated campaign indicators |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Targeted attachments used to deliver malicious content | Email header logs, attachment details, mail security telemetry |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Targeted links used in initial-access attempts | URLs, redirects, proxy/DNS logs, mail gateway logs |
| Execution | T1204.002 | User Execution: Malicious File | Execution depended on a recipient opening a delivered file | Parent-child process relationships and endpoint events |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | APT29 used PowerShell for command execution | Windows process creation and PowerShell audit telemetry |
| Persistence | T1546.003 | Event Triggered Execution: WMI Event Subscription | Used WMI subscriptions for persistence | WMI operational logs and endpoint configuration changes |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Used autorun registry entries | Registry change telemetry and autorun inventory |
| Persistence | T1136.003 | Create Account: Cloud Account | Created accounts to maintain access | Cloud identity and administrator audit logs |
| Privilege Escalation | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Used Windows elevation-control bypass techniques | Windows elevation and process telemetry |
| Credential Access | T1110.003 | Brute Force: Password Spraying | Attempted logins across multiple accounts | Authentication failures across accounts, identity audit events |
| Credential Access | T1003.002 | OS Credential Dumping: Security Account Manager | Credential-related access to Windows registry hives | Windows security and sensitive registry access events |
| Credential Access | T1003.004 | OS Credential Dumping: LSA Secrets | Access to LSA-related secret material | Endpoint detection and Windows security events |
| Credential Access | T1003.006 | OS Credential Dumping: DCSync | Directory replication techniques used in credential access | Domain controller replication and identity telemetry |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | Utilities used to archive collected information | Process and file creation telemetry |
| Command and Control | T1090.004 | Proxy: Domain Fronting | Used trusted domains/services as fronts for communication | Proxy, TLS and network destination telemetry |

**Interpretation:** A technique listed for APT29 is not proof that a corresponding event in our lab was produced by that group. Campaign attribution requires independent contextual evidence.

## 3. Comparison with Week 9

| Activity in Week 9 | Result | Relation to documented APT29 |
|---|---|---|
| T1059.004 — Unix Shell on Kali | Manually adapted and executed; one selected event forwarded to Splunk | Not the same as APT29's T1059.001 PowerShell technique; no group emulation is claimed |
| T1082 — System Information Discovery on Kali | Executed; two selected events manually forwarded | Separate laboratory exercise; not in the currently displayed G0016 group-technique table |
| T1003.007 / T1003.008 | Theoretical review only | Different Linux subtechniques than T1003.002/.004/.006 listed for APT29; no credentials accessed |
| Synthetic `/bin/sh` alert-validation event | One scheduled alert trigger in Splunk | Demonstrates scheduled search behavior, not automatic detection of a real event or APT29 |

Only selected `execve` telemetry was extracted and sent manually via HEC. Continuous forwarding, phishing infrastructure monitoring, cloud identity telemetry and APT29 detection were **not** validated.

## 4. Detection Gaps and Recommendations

- **Endpoint platform:** Add an approved Windows lab with appropriate Windows audit/Sysmon logging for the Windows techniques.
- **Continuous logging:** Configure supported log forwarding and validate completeness before describing detection coverage.
- **Phishing CTI:** Investigate email headers, redirected URLs, suspicious domains, certificate metadata and corroborating DNS/proxy records using approved datasets.
- **Identity:** Correlate login anomalies from approved identity audit logs instead of inferring password spraying from shell commands.
- **Interpretation:** Separate tested detections, synthetic rule checks and theoretical monitoring hypotheses.

## 5. Selected References

1. [MITRE ATT&CK — APT29 / G0016](https://attack.mitre.org/groups/G0016/)
2. [Mandiant — Tracking APT29 Phishing Campaigns](https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns/)
3. [Mandiant — APT29 Uses WINELOADER to Target German Political Parties](https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties)
4. [CrowdStrike — COZY BEAR Adversary Profile](https://www.crowdstrike.com/en-us/adversaries/cozy-bear/)
5. [Week 9 README](../week9/README.md)

## 6. Evidence Status

- MITRE group page screenshot: **not yet captured**.
- Navigator import screenshot: **not yet captured**.
- No new practical tests were performed for Week 10.
