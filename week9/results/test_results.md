# Week 9 — Atomic Red Team Test Results

**Project:** Cyber Threat Intelligence Analysis of Phishing Infrastructure

**Date:** November 4, 2026

## 1. Test Environment

- Operating System: Kali Linux 2025.1
- Virtualization: UTM
- Monitoring: Linux Audit (auditd)
- SIEM: Splunk Enterprise 10.6.0.5 (build `86587d4e3b27`)
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
| Scheduled alert validations | 2 separate checks: synthetic control event and one genuine manually forwarded Auditd event |
| Additional real Auditd event | ID `48047`, `/bin/sh`, manually forwarded through HEC |
| Real-event scheduled alert result | 1 matching event; triggered November 4, 2026, at 08:55:01 UTC |

**Interpretation:** Both selected test procedures produced observable telemetry in the configured laboratory environment. This does not establish a general threat detection rate.

## 6. Additional Scheduled Alert Validation — Real Auditd Event

On November 4, 2026, an additional benign shell command generated a genuine Linux Audit event, ID `48047`, recorded under the `week9_exec` key. The command was `/bin/sh -c 'echo "Week9 real audit event validation"'`; `ausearch -a 48047 -i` confirmed the associated `EXECVE` and `SYSCALL` records. This was a separate validation from the two Atomic Red Team adaptations.

The record was manually transformed to Splunk HEC JSON while preserving the raw audit output in `audit_raw`. The resulting event included `command=/bin/sh`, `audit_id=48047`, and `validation_type=real_audit_manual_forward`. HEC acknowledged submission with `{"text":"Success","code":0}`. A Splunk search retrieved the event, and the next scheduled alert search at **08:55:01 UTC** returned **one result**. Trigger History recorded the alert and its View Results displayed event ID `48047`.

Evidence: [Auditd record](../screenshots/11_real_audit_event.png), [Alert trigger history](../screenshots/12_real_audit_alert_triggered.png), and [Scheduled search results](../screenshots/13_real_audit_alert_results.png).

## 7. Limitations

The experiments were performed in an educational virtual machine. The test procedures were adapted to avoid harmful actions. The three events from the original Atomic Red Team adaptations were manually extracted and forwarded to Splunk. A separate real Auditd event, ID `48047`, was subsequently forwarded and used to validate the scheduled alert; an earlier synthetic event was also used for control testing.

The real-event validation confirms that a scheduled search can match and trigger on a **manually** forwarded real audit event. It does not establish continuous automatic log forwarding or comprehensive detection coverage. No complete phishing campaign, credential dumping activity, or production security control was tested.

## 8. Conclusion

Both selected Atomic Red Team procedures were successfully executed and analyzed. Linux Audit recorded relevant process execution activity, and Splunk received three selected events.

The experiment demonstrates a basic workflow for validating process telemetry during the investigation of phishing-related post-access behavior. The separate real-event check further showed that a scheduled alert can fire on a manually forwarded Auditd record, without proving automated event collection.