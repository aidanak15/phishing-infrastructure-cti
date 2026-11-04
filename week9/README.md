# Week 9 — Atomic Red Team: Phishing-Related Technique Simulation and SIEM Analysis

## 1. Introduction

This week focuses on Atomic Red Team, an open-source framework developed by Red Canary for testing security detection capabilities using techniques mapped to MITRE ATT&CK.

Our group project, **Cyber Threat Intelligence Analysis of Phishing Infrastructure**, investigates indicators and activities associated with phishing campaigns.

For Week 9, we performed two safe, adapted Atomic Red Team tests in an isolated Kali Linux virtual machine and analyzed the recorded events using Splunk Enterprise.

## 2. Objectives

- Understand the purpose of Atomic Red Team.
- Perform safe tests mapped to MITRE ATT&CK.
- Collect Linux process execution events using Auditd.
- Forward selected events to Splunk SIEM.
- Develop SPL queries to identify the test activities.
- Evaluate telemetry visibility and detection limitations.

## 3. Laboratory Environment

| Component | Configuration |
|---|---|
| Host OS | macOS Sequoia |
| Virtualization | UTM |
| Test Machine | Kali Linux 2025.1 |
| Architecture | x86_64 |
| Test reference | Atomic Red Team YAML definitions (manually adapted; no Invoke-AtomicRedTeam runner used) |
| Logging | Linux Audit (auditd) |
| SIEM | Splunk Enterprise (installed version: to be verified in Splunk Web) |
| Containerization | Docker |
| Data Transfer | HTTP Event Collector (HEC) |
| Splunk Index | `atomic_week9` |

## 4. Methodology

The experiment followed these steps:

1. Prepared Kali Linux and Splunk Enterprise.
2. Installed and configured Linux Audit.
3. Enabled monitoring of process execution events.
4. Reviewed the [T1059.004 YAML](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.yaml) and [T1082 YAML](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.yaml) test definitions.
5. Manually executed two harmless adaptations of the documented procedures. `Invoke-AtomicRedTeam` was not used.
6. Extracted relevant audit events.
7. Forwarded selected, sanitized events to Splunk through HEC.
8. Analyzed the results with SPL queries.

The experiments were conducted in a controlled educational environment without malicious payloads or credential extraction.

## 5. Executed Tests

### 5.1 T1059.004 — Command and Scripting Interpreter: Unix Shell

**Atomic Test #1: Create and Execute Bash Shell Script**

**Objective:** Demonstrate shell script execution and verify process execution logging.

A simple shell script was created to display a message and perform a local connectivity check using `127.0.0.1`.

The shell-script procedure was manually adapted from [Atomic Red Team T1059.004 Test #1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.yaml). Its test content was simplified to a benign local loopback check.

**Observed results:**

- The shell script executed successfully.
- The connectivity check completed with four successful responses.
- Linux Audit recorded an `EXECVE` event for the shell execution.
- One selected event was forwarded to Splunk.

**SIEM result:** The execution event was successfully retrieved using an SPL search.

### 5.2 T1082 — System Information Discovery

**Atomic Test #3: List OS Information**

**Objective:** Demonstrate system information discovery and verify logging of the related commands.

The following commands were executed:

- `uname -a`
- `cat /etc/os-release`
- `uptime`

The commands collected operating system information, kernel information, and system uptime. They were manually adapted from [Atomic Red Team T1082 Test #3](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.yaml), not executed with an automated test runner.

**Observed results:**

- System information was successfully collected.
- Linux Audit recorded process execution activity.
- Two selected events, corresponding to `uname` and `uptime`, were forwarded to Splunk.

**SIEM result:** Both events were successfully retrieved using SPL.

### 5.3 Cleanup

After completing the Atomic Red Team experiments, the temporary `art.sh` shell script was removed from the Kali Linux test environment.

The test output files and screenshots were retained as evidence.

No persistent system modifications or malicious payloads were introduced by the two adapted test procedures.

## 6. MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Tactic | Relevance to Phishing |
|---|---|---|---|
| T1059.004 | Unix Shell | Execution | Shell commands may be executed after a successful phishing compromise |
| T1082 | System Information Discovery | Discovery | Attackers may collect system information after obtaining access |

The tests do not reproduce a complete phishing attack. They demonstrate post-access behaviors that can be relevant when investigating phishing-related incidents.

### 6.1 Connection to Phishing Infrastructure CTI

Our project focuses on identifying and analyzing indicators of compromise (IOCs) associated with phishing infrastructure, including suspicious domains, URLs, and network activity.

Threat intelligence can help identify potentially malicious infrastructure, while endpoint telemetry provides additional context about activities occurring on affected systems.

For example, after investigating a suspicious phishing-related URL, a security analyst may examine endpoint logs for unusual command execution or system discovery activity.

The Week 9 tests demonstrate two types of post-access behavior: Unix shell execution (T1059.004) and system information discovery (T1082).

By combining phishing-related IOCs with endpoint logs in a SIEM, analysts can develop more informed threat hunting hypotheses.

These laboratory tests did not establish a direct connection between the simulated commands and any real phishing campaign.

## 7. SIEM Detection Analysis

Linux Audit was configured to collect process execution events using the `execve` system call.

Selected events were processed and forwarded through Splunk HTTP Event Collector to the `atomic_week9` index. The `week9:atomic` sourcetype stores selected, manually structured test results; `week9:audit` stores selected audit-like telemetry and the separate control event used for scheduled alert validation. These are not evidence of continuous raw Auditd forwarding.

### Detection Summary

| Technique | Executed | Audit Logs | Splunk Events | Result |
|---|---|---|---:|---|
| T1059.004 | Yes | Observed | 1 | Visible |
| T1082 | Yes | Observed | 2 | Visible |
| **Total** | **2 tests** | **Observed** | **3 selected** | **All 3 manually forwarded events retrieved** |

Both selected tests generated observable telemetry.

These Week 9 atomic-test results demonstrate retrieval of manually forwarded events, not automated forwarding or broad threat detection. A separate scheduled alert was validated only with a synthetic control event (Section 10).

### 7.1 Linux Audit Configuration

Linux Audit (auditd) was configured in Kali Linux to monitor process execution through the `execve` system call.

The following audit rule was used during the experiment:

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -F auid=$(id -u) -k week9_exec
```

The rule records process execution events associated with the test user's audit identity.

Relevant audit events were inspected using:

```bash
sudo ausearch -k week9_exec -i
```

The rule was configured for the laboratory session. It was not documented as a persistent audit rule across system reboots. The `auid` filter targets the current logged-in user's audit identity and relies on a valid Linux `loginuid`; if no events appear, inspect the audit session/login UID configuration before drawing conclusions.

### 7.2 Splunk Detection Queries

**Query 1 — T1059.004 Unix Shell**

```spl
index=atomic_week9 sourcetype="week9:atomic" technique="T1059.004"
| table _time host technique command script audit_id status
```

**Query 2 — T1082 System Information Discovery**

```spl
index=atomic_week9 sourcetype="week9:atomic" technique="T1082"
| table _time host technique command audit_id status
```

**Query 3 — Detection Summary**

```spl
index=atomic_week9 sourcetype="week9:atomic"
| stats count AS events values(command) AS commands BY technique test
| sort technique
```

**Query 4 — Scheduled Unix Shell Alert**

```spl
index=atomic_week9 sourcetype="week9:audit"
| search command="/bin/sh"
| table _time host command audit_id
```

The scheduled alert ran every five minutes and searched the preceding ten minutes of indexed events.

The alert was successfully validated using a separate synthetic event transmitted through Splunk HEC.

**Interpretation:** The searches confirm successful ingestion and retrieval of selected events. Because the original Auditd events were manually forwarded, these results do not establish continuous telemetry collection or comprehensive detection coverage.

## 8. Limitations

- Only two safe, manually adapted Atomic Red Team tests were executed.
- The experiments were performed in an isolated Kali Linux virtual machine.
- Selected Linux Audit events were manually extracted, sanitized, and forwarded to Splunk HEC. Therefore, the results validate the selected-event ingestion pipeline rather than continuous or comprehensive detection coverage.
- An automated Splunk alert was successfully triggered using a separate synthetic validation event. Detection based on an independently forwarded real Auditd event was not yet validated.
- The alert condition `command="/bin/sh"` is narrow and may miss other shell executable paths, including `/bin/bash` and `/usr/bin/sh`.
- The three selected Atomic Test events were visible in Splunk, but this does not establish a general detection rate.
- The tests did not reproduce a complete phishing attack.
- Original Auditd execution timestamps and Splunk ingestion timestamps were not identical.
- T1003 was analyzed theoretically; no credential dumping was performed.

## 9. Experimental Evidence

The following screenshots document the execution of the adapted Atomic Red Team tests and the analysis of their events in Splunk SIEM.

### Test 1 — T1059.004: Unix Shell

**Test execution in Kali Linux:**

![T1059.004 Execution](screenshots/03_atomic_test_execution.png)

**Event received in Splunk:**

![T1059.004 Splunk Event](screenshots/04_atomic_test_splunk.png)

**SPL detection query results:**

![T1059.004 Detection](screenshots/05_t1059_detection.png)

### Test 2 — T1082: System Information Discovery

**Test execution and Linux Audit events:**

![T1082 Execution](screenshots/06_T1082_execution.png)

**Events received in Splunk:**

![T1082 Splunk Events](screenshots/07_T1082_splunk.png)

### Overall Detection Summary

![Week 9 Detection Summary](screenshots/08_week9_detection_summary.png)

Both selected tests generated Linux Audit process telemetry that was manually selected and transferred to Splunk. The screenshots here show manual SPL validation; the **separately validated synthetic-event scheduled alert** is documented in Section 10.

## 10. Automated Detection Alert Validation

An additional scheduled alert was configured in Splunk Enterprise to monitor Unix shell execution events.

**Alert configuration:**

- Alert name: Week9 - Unix Shell Execution Detection
- Search index: `atomic_week9`
- Sourcetype: `week9:audit`
- Detection condition: `command="/bin/sh"`
- Schedule: Every 5 minutes
- Search window: Last 10 minutes
- Trigger condition: Number of Results greater than 0
- Action: Add to Triggered Alerts
- Severity: Medium

A synthetic validation event was submitted through Splunk HEC to test the alert.

**Observed results:**

- The validation event was successfully indexed.
- The scheduled search matched one event.
- Splunk recorded one automatic alert trigger on November 4, 2026, at 07:10 UTC.
- The matching event was visible through the View Results page.

**Conclusion:** The experiment successfully validated an automated Splunk alert using controlled test telemetry. This demonstrates rule execution and alert generation, but does not establish the ability to detect real phishing attacks.

### Alert Evidence

![Triggered Alert](screenshots/09_splunk_alert_triggered.png)

![Alert Results](screenshots/10_splunk_alert_results.png)

## 11. Additional MITRE ATT&CK Analysis — T1003

**Technique:** T1003 — OS Credential Dumping  
**Tactic:** Credential Access  
**Analysis type:** Theoretical (not executed)

### Linux-Specific Subtechniques

**T1003.007 — Proc Filesystem**

This subtechnique concerns attempts to obtain credential-related information through the Linux `/proc` filesystem.

**T1003.008 — /etc/passwd and /etc/shadow**

This subtechnique concerns attempts to access Linux account information and password hash storage files.

### Relevance to Our Laboratory

Our Kali Linux environment uses Linux Audit to monitor process execution. However, the current `execve` monitoring rule does not provide comprehensive visibility into file access or credential-related activity.

Additional, appropriately configured file-access auditing would be required to investigate suspicious access to sensitive authentication resources.

Both subtechniques were analyzed theoretically. No credential extraction or password hash collection was performed. T1003 concerns credential access after compromise; it is relevant to interpreting potential post-phishing activity, but it was not tested in this laboratory.

### Potential Detection Indicators

- Unusual access to credential-related operating system resources.
- Suspicious process activity involving sensitive authentication components.
- Unexpected access attempts by unauthorized accounts.
- Security monitoring alerts related to credential access.

### Monitoring Recommendations

Organizations should collect relevant operating system security logs, monitor access to sensitive resources, apply least-privilege access controls, and investigate suspicious credential-related activity.

### Experiment Scope

The practical experiments remained focused on T1059.004 and T1082. No credential dumping commands or access to authentication secrets were performed.

## 12. Conclusion

Week 9 demonstrated how safe, manually adapted Atomic Red Team procedures can support security monitoring and threat hunting.

Two techniques, T1059.004 (Unix Shell) and T1082 (System Information Discovery), were successfully executed in Kali Linux. Linux Audit recorded the corresponding process execution activity, and three selected events were manually forwarded to Splunk Enterprise.

The experiment confirmed that selected Auditd events could be transferred, indexed, and analyzed using SPL queries. However, this represents validation of the manual event ingestion pipeline rather than comprehensive or continuous detection coverage.

A scheduled Splunk detection alert was also configured and successfully triggered using one separate synthetic validation event. This confirmed that the alert rule and scheduling mechanism worked, but did not establish automatic detection of real Auditd events.

Additionally, T1003 (OS Credential Dumping) was reviewed theoretically to identify relevant credential-access risks and potential monitoring opportunities. No credential dumping was performed.

These results demonstrate how endpoint telemetry, SIEM analysis, and MITRE ATT&CK mapping can support investigations of suspicious post-compromise activity associated with phishing incidents.

Future improvements include automated Auditd log forwarding, broader shell execution detection rules, and validation using newly generated real audit events.

## 13. References

1. Red Canary — Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
2. MITRE ATT&CK — T1059.004: https://attack.mitre.org/techniques/T1059/004/
3. MITRE ATT&CK — T1082: https://attack.mitre.org/techniques/T1082/
4. Red Canary — Atomic Red Team Wiki: https://github.com/redcanaryco/atomic-red-team/wiki
5. Official T1059.004 test YAML: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.yaml
6. Official T1082 test YAML: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.yaml
7. Splunk Documentation: https://docs.splunk.com/

## 14. Use of AI

ChatGPT (OpenAI) was used during the Week 9 laboratory and reporting workflow.

| Task | Tool | Verification |
|---|---|---|
| Atomic Red Team and ATT&CK explanations | ChatGPT | Compared the descriptions to Atomic Red Team YAML and MITRE pages |
| Auditd / HEC troubleshooting | ChatGPT | Checked terminal output, actual Auditd events and successful Splunk indexing |
| SPL queries and scheduled alert documentation | ChatGPT | Reviewed Splunk search results and the scheduled alert's trigger history |
| Report structure and limitations | ChatGPT | Compared every claimed outcome against observed screenshots and test results |

The team should disclose any additional AI tools they actually used before submission. A separate synthetic control event, not a real forwarded audit record, was used for scheduled alert validation. AI assistance did not replace laboratory experiments.