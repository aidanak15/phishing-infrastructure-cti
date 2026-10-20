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
