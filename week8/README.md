# Week 8 — Creating a Plan to Emulate an Attacker's Action

**Project:** Cyber Threat Intelligence Analysis of Phishing Infrastructure  
**Deliverable:** ATT&CK-aligned adversary emulation plan (documentation only)  
**Status:** Planned; no Week 8 operation has been run or validated.

## Objective

Develop a controlled, four-step scenario covering the three required phases: **Initial Access → Persistence → Data Exfiltration**. A **Collection** step is included to explain what would be transferred. The objective is to define observable telemetry and defensive tests, not to compromise a device.

## Relationship to previous weeks

- **Week 5:** Splunk searches involving DNS and proxy event datasets (`phishing_logs`). The prior dataset is not proof that Week 8 behavior was executed.
- **Week 6:** An authorized training-link visit was captured as HTTP evidence and mapped *partially* to T1566.002. There was no demonstrated phishing email or endpoint compromise.
- **Week 7:** MITRE CAR mapping and analysis using a public host-discovery JSON example. The sample is separate from Week 6 HTTP evidence.

## Documents

| File | Purpose |
|---|---|
| [adversary_emulation_plan.md](adversary_emulation_plan.md) | Main scenario, rules, stages, success checks and limits |
| [attack_mapping.md](attack_mapping.md) | ATT&CK IDs, interpretation and telemetry |
| [detection_strategy.md](detection_strategy.md) | Planned Splunk validation and illustrative SPL |
| [caldera_profile.md](caldera_profile.md) | Conceptual CALDERA objects; not executable abilities |
| [attack_flow.md](attack_flow.md) | Mermaid diagram of the scenario |

## Overview

| Phase | ATT&CK ID | Stage status |
|---|---|---|
| Initial Access | T1566.002 — Spearphishing Link | Prior Week 6 link-navigation observation only |
| Persistence | T1053.003 — Scheduled Task/Job: Cron | Planned, not executed |
| Collection | T1005 — Data from Local System | Planned with fictional test data |
| Exfiltration | T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol | Planned, not executed |

## MITRE ATT&CK Navigator Visualization

![Week 8 ATT&CK Navigator](week8/attack_navigator.svg)

**Figure 1.** MITRE ATT&CK Navigator layer showing the
selected techniques for the Week 8 phishing infrastructure
adversary emulation plan.

The highlighted techniques represent the planned attack
stages. Only T1566.002 has partial supporting evidence
from Week 6; the remaining stages have not been executed.


**Operating-system assumption:** the hypothetical persistence host is a separately authorized Linux VM or macOS test machine, because `cron` is not a Windows Scheduled Task. The earlier training webpage and HTTP records do not establish which endpoint was compromised.

## Scope

Only an isolated lab with owner authorization, fictional markers, and reviewed non-destructive behavior. No real phishing, malware, stolen credentials, third-party data, public uploads or deployed persistent access. All tasks remain proposals unless separately verified.

## References

- [MITRE ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK T1053.003](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK T1005](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK T1048.003](https://attack.mitre.org/techniques/T1048/003/)
- [MITRE CALDERA](https://caldera.readthedocs.io/en/stable/)


