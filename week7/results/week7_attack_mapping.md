# Week 7 — MITRE CAR ATT&CK Mapping

## Selected Analytic
CAR-2016-03-001 — Host Discovery Commands

## SIEM Platform
Splunk Enterprise

## Data Source
Original publicly available recorded Sysmon events from MITRE CAR.

## Observed Events

| Process | Parent | ATT&CK Technique | Tactic |
|---|---|---|---|
| whoami.exe | msbuild.exe | T1033 — System Owner/User Discovery | Discovery |
| net.exe start | powershell.exe | T1007 — System Service Discovery | Discovery |

## Detection Results
The adapted SPL query matched two recorded process creation events.

The results demonstrate that the selected command-name detection
logic matches the two published examples.

## Limitations
Only two positive examples were evaluated.
No independent negative dataset was tested.
False-positive and false-negative rates cannot be determined.

The presence of discovery commands does not establish malicious intent.

The original event timestamps are from May 18, 2019.
Splunk assigned ingestion-time timestamps during upload.

## References
- https://car.mitre.org/analytics/CAR-2016-03-001/
- https://attack.mitre.org/techniques/T1033/
- https://attack.mitre.org/techniques/T1007/
