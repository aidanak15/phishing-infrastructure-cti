# Week 9 — Atomic Red Team Test Results

**Project:** Cyber Threat Intelligence Analysis of Phishing Infrastructure

**Date:** November 4, 2026

## 1. Test Environment

- Operating System: Kali Linux 2025.1
- Virtualization: UTM
- Monitoring: Linux Audit (auditd)
- SIEM: Splunk Enterprise
- Index: `atomic_week9`
- Data Collection: Splunk HTTP Event Collector (HEC)

## 2. Executed Tests

| Test | MITRE ATT&CK Technique | Execution | Audit Logs | Splunk Events |
|---|---|---|---|---:|
| Atomic Test #1 | T1059.004 — Unix Shell | Successful | Observed | 1 |
| Atomic Test #3 | T1082 — System Information Discovery | Successful | Observed | 2 |
| **Total** | **2 techniques** | **2 successful** | **Observed** | **3** |

Both tests were performed manually using safe adaptations of official Atomic Red Team procedures.

## 3. Test 1 — T1059.004

**Test name:** Create and Execute Bash Shell Script

**Objective:** Verify that execution of a simple shell script generates observable process execution events.

**Execution details:**

- Created a shell script named `art.sh`.
- Executed the script using `sh`.
- Performed four ping requests to the loopback address `127.0.0.1`.
- Recorded the output in `test1_output.txt`.

**Results:**

- Shell script execution: Successful
- Ping responses: 4/4
- Packet loss: 0%
- Linux Audit event type: EXECVE
- Command: `sh`
- Script: `art.sh`
- Audit ID: `1793773064.020:3965`
- Splunk events: 1

**Result:** The selected process execution event was successfully forwarded to Splunk and retrieved using an SPL query.

## 4. Test 2 — T1082

**Test name:** List OS Information

**Objective:** Verify process execution telemetry generated during system information discovery.

**Commands executed:**

- `uname -a`
- `cat /etc/os-release`
- `uptime`

**Results:**

- OS information: Collected
- Linux Audit events: Observed
- Splunk command events: 2
- Commands visible in Splunk: `uname`, `uptime`

**Audit event identifiers:**

- `uname`: `1793773401.864:6042`
- `uptime`: `1793773414.025:6116`

**Result:** Both selected process execution events were successfully forwarded to Splunk and retrieved using SPL.

## 5. Detection Summary

| Metric | Result |
|---|---|
| Techniques tested | 2 |
| Successful test executions | 2 |
| Selected events forwarded to Splunk | 3 |
| Selected events visible in Splunk | 3 |
| Telemetry visibility for selected tests | 2/2 |
| Automated alerts verified | 1 (synthetic validation event) |

**Interpretation:** Both selected test procedures produced observable telemetry in the configured laboratory environment. This does not establish a general threat detection rate.

## 6. Limitations

The experiments were performed in an educational virtual machine. The test procedures were adapted to avoid harmful actions. Selected audit events were manually extracted, sanitized, and forwarded to Splunk.

Process execution telemetry and manual ingestion of selected Auditd events were validated. One scheduled Splunk alert was successfully triggered using a separate synthetic validation event. Continuous automatic log forwarding and alert detection based on a newly forwarded real Auditd event were not validated. No complete phishing campaign, credential dumping activity, or production security control was tested.
## 7. Conclusion

Both selected Atomic Red Team procedures were successfully executed and analyzed. Linux Audit recorded relevant process execution activity, and Splunk received three selected events.

The experiment demonstrates a basic workflow for validating process telemetry during the investigation of phishing-related post-access behavior.