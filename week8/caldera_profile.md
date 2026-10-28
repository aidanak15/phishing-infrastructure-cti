# Week 8 — CALDERA-Style Adversary Profile (Conceptual)

> Planning artifact, **not executable CALDERA YAML**. No agent, server, operation, payload or ability is deployed.

## Why CALDERA is mentioned

MITRE CALDERA represents tests as **abilities**, combines abilities into an **adversary profile**, and runs that profile in an **operation** against authorized agents. The **planner** controls ordering, while the resulting operation artifacts can be reviewed for defensible observations.

## Proposed profile

**Name:** `Phishing-Infrastructure-Visibility-W8`  
**Objective:** test whether a defender can observe the planned phishing-navigation, scheduled marker, dummy-data access, and controlled lab transfer sequence.

| Order | Conceptual ability label | ATT&CK | Planned harmless representation |
|---|---|---|---|
| 1 | `document-training-link` | T1566.002 | Compare recorded training URL and HTTP observation |
| 2 | `inspect-scheduled-marker` | T1053.003 | Review a labeled benign task on an authorized Unix-like lab host |
| 3 | `inspect-decoy-file-access` | T1005 | Review access to fictional marker data |
| 4 | `inspect-local-http-transfer` | T1048.003 | Review a prospective dummy-data HTTP transfer and receiver evidence |

These labels are descriptions only. CALDERA abilities require concrete, reviewed definitions and applicable agents; a manual external email/web observation may need **out-of-band evidence** rather than pretending that an endpoint ability reproduced phishing delivery.

## Hypothetical operation settings

| Property | Proposed setting |
|---|---|
| Network | Isolated and explicitly authorized laboratory |
| Endpoint | Linux/macOS test host for Cron stage |
| Execution | Manual approval before each separately reviewed benign test |
| Data | Dummy test markers only |
| Reporting | Separate per-stage evidence, timestamps and detection results |
| Cleanup | Stop exercise and remove all test artifacts |
| Current status | NOT DEPLOYED / NOT EXECUTED |

## Model boundaries

- An ATT&CK technique ID is not automatically an available CALDERA ability.
- A visited link is not a verified phishing compromise.
- A created scheduled job is not proof it ran or survived reboot.
- A copied local file is not network exfiltration.
- An ordinary HTTP request is not proof of T1048.003 without verified data movement and non-C2 context.

## References

- https://caldera.readthedocs.io/en/stable/
- https://attack.mitre.org/
