# Week 6 — Phishing Link Analysis Simulation

## Objective
Study MITRE ATT&CK T1566.002 (Spearphishing Link)
using real-world redacted phishing-related emails.

## Dataset
Source: cw-l/email-corpus (GitHub).
Two real-world redacted email samples were analyzed.

## Observed Results
- 2 email samples examined.
- 12 HTML hyperlinks extracted.
- Shared hostname: storage.googleapis.com.
- 12 links contain URL fragments.
- No query parameters observed.

## Laboratory Activity
1. Parse email headers and HTML.
2. Extract hyperlink metadata without opening URLs.
3. Compare domains and URL structure.
4. Import analysis results into Splunk.
5. Correlate shared hosting indicators.
6. Map findings to ATT&CK T1566.002.

## Limitations
This laboratory reproduces the defensive analysis
workflow, not an actual phishing attack.
No phishing emails were sent.
No phishing URLs were opened.
No credential submission or compromise occurred.
