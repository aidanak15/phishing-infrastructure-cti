# Week 6 — Evidence-Based ATT&CK Mapping

**Scope:** two offline redacted `.eml` samples, their aggregated Splunk metadata, and one local-only HTTP page visit. **Selected research technique:** T1566.002, under Initial Access.

| Activity | Tactic | ATT&CK relation | Evidence | Confidence / limitation |
|---|---|---|---|---|
| Account-restriction themes in two sampled messages | Initial Access (context) | Potential T1566 | Offline message subject review | Themes observed; intent not independently confirmed |
| 7 and 5 HTML hyperlink attributes in messages | Initial Access (context) | Candidate T1566.002 | Offline HTML parsing, aggregate CSV | Links observed; no destination visit or attributed campaign |
| Shared defanged hostname `storage[.]googleapis[.]com` | None independently | Infrastructure correlation only | Splunk grouping returns 2 email rows / 12 links | Legitimate shared hosting; **not** a verified malicious IOC |
| Written fictional notice with clearly labeled educational link | Initial Access (modeled) | T1566.002 link-in-message scenario | README scenario | Not sent or captured as email traffic |
| Browser GET `/index.html`, HTTP 200, on loopback | None established | Supporting benign click-access telemetry | `http_server.log` and Splunk | Page access confirmed, not attack execution |
| Defensive event query | Defender activity | No adversary technique | Saved SPL query | Detection of local HTTP access only |

## Evidence inventory

- `../data/week6_email_analysis.csv`: two derived aggregate records.
- `../queries/week6_http_detection.spl`: verified page-access query.
- `http_server.log`: three HTTP server log lines, including one GET 200.
- `../navigator/week6_attack_layer.json`: a visualization of the studied technique, not a successful attack indicator.
- `../screenshots/01_email_analysis.png` through `07_http_detection.png`: evidence screenshots.

## Investigation caveats

A shared hostname and message pretexts are not sufficient to identify an adversary or malicious service. HTTP 200 is not proof of an email-click journey, and no delivery or credential evidence was produced. A complete evaluation would require correlated mail and network records obtained in an authorized environment.

## Validated Local Training Demonstration

| Activity | ATT&CK Tactic | Technique | Evidence | Status |
|---|---|---|---|---|
| Educational message containing a localhost link | Initial Access (scenario context) | T1566.002 | training_message.html | Prepared |
| Local page navigation during training | Initial Access (scenario context) | T1566.002 | training_http_server.log | Observed in laboratory |
| HTTP GET /index.html, status 200 | Not independently attributable to an ATT&CK tactic | N/A | Splunk HTTP event at 23:35:15 | Confirmed |
| Splunk investigation of HTTP logs | Defensive activity | N/A | 09_training_detection.png | Confirmed |

The demonstration is a benign educational approximation
of a link-based phishing scenario.

The HTTP events confirm local web activity, not malicious
intent, phishing delivery, credential theft, or compromise.

## Final Evidence Reconciliation

### Reproduced Email Metadata Analysis

The two selected redacted email samples were analyzed again
using scripts/analyze_eml.py.

The reproduced results matched the documented counts:

| Metric | Email 1 | Email 2 |
|---|---:|---:|
| HTML hyperlinks | 7 | 5 |
| Unique URL values | 7 | 5 |
| URLs with fragments | 7 | 5 |
| URLs with query parameters | 0 | 0 |

The reproduced results are recorded in
results/week6_email_reproduced.csv.

This confirms repeatability for the selected samples,
but does not establish malicious intent or common attribution.

### Controlled Local Navigation Evidence

A benign training-message demonstration was performed locally.

The HTTP server recorded:

| Method | Path | Status |
|---|---|---|
| GET | /index.html | 304 |
| GET | /index.html | 200 |

Splunk identified one successful GET request with HTTP 200.

Evidence:
- screenshots/08_training_link_visit.png
- screenshots/09_training_detection.png
- results/training_http_server.log

The HTTP logs demonstrate local page access.
They do not independently prove the referring document,
real phishing delivery, credential theft, or compromise.

### Final ATT&CK Assessment

- Tactic: Initial Access
- Technique: T1566 — Phishing
- Sub-technique: T1566.002 — Spearphishing Link

T1566.002 describes the technique investigated and
represented by the educational scenario.

The observed network evidence confirms a benign local
page request, not an actual adversary intrusion.

Therefore, the activity should be classified as a
controlled, partial educational demonstration rather
than a confirmed real-world phishing attack.
