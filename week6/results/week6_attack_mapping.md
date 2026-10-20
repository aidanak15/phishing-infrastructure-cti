# Week 6 — MITRE ATT&CK Mapping

## Project
Cyber Threat Intelligence Analysis of Phishing Infrastructure

## Selected Technique
- Tactic: Initial Access
- Technique: T1566 — Phishing
- Sub-technique: T1566.002 — Spearphishing Link

## Real-World Email Analysis
Two redacted real-world email samples from
cw-l/email-corpus were examined.

Findings:
- 2 email samples
- 12 HTML hyperlinks
- Shared host: storage.googleapis.com
- 12 hyperlinks contained URL fragments
- No query parameters were observed

The email themes suggested account restriction
and suspension. These characteristics are
consistent with potential phishing lures,
but do not establish a successful attack.

## Controlled Laboratory Demonstration
A local educational HTTP page was hosted on
127.0.0.1:8088.

The browser requested /index.html, and
the server returned HTTP status 200.

The request was imported into Splunk:
- Index: phishing_week6
- Sourcetype: week6_http_log
- Source: http_server.log

An SPL query identified one successful
GET request to /index.html.

## ATT&CK Interpretation
T1566.002 is the candidate technique associated
with the phishing-link investigation.

The local HTTP event demonstrates observable
link-access telemetry, not the delivery or
execution of a phishing attack.

## Limitations
No actual phishing messages were sent.
No real phishing websites were visited.
No credentials were collected.
No compromise was observed.

## References
https://attack.mitre.org/techniques/T1566/002/
https://attack.mitre.org/techniques/T1566/
https://github.com/cw-l/email-corpus
