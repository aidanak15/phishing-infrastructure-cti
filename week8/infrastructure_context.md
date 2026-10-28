# Infrastructure Context — Phishing CTI

**Status:** analytical extension to the Week 8 plan, not an executed infrastructure setup.

## Why infrastructure matters

Our project concerns the indicators surrounding phishing links: DNS queries, HTTP destinations, URL structure, and related hosting context. Week 6 demonstrated navigation to an authorized training link. It did **not** demonstrate registering a deceptive domain, delivering an email, credential collection, or endpoint compromise.

## ATT&CK context (pre-attack)

| Technique | Adversary behavior in ATT&CK | Safe representation in this project | Status |
|---|---|---|---|
| T1583.001 — Acquire Infrastructure: Domains | Obtaining a domain for an operation | Describe domain-related indicators (registration dates, RDAP, passive DNS) using an illustrative example or public defensive dataset; no domain acquisition | Context only; **not emulated** |
| T1608.005 — Stage Capabilities: Link Target | Preparing the webpage a link points to | Refer to the authorized training webpage already used in Week 6 | Related training page observed; full adversary technique **not demonstrated** |
| T1566.002 — Phishing: Spearphishing Link | Delivering a phishing link to a target | Reuse the Week 6 training-link visit as partial browser/HTTP evidence | Partial observation; delivery and compromise **not demonstrated** |

## CTI signals and limits

- **DNS:** queried domain, timestamp, resolved IP if available; an unusual domain is an indicator, not proof of maliciousness.
- **HTTP/proxy:** destination host, path, status code, timestamp, user agent if logged; a `200` response confirms server response, not compromise.
- **RDAP/WHOIS and certificate transparency:** useful *external* context when actual domain identifiers are available; do not fabricate registration age or certificate history.
- **Correlation:** tie DNS and HTTP on a common time window and network identity only when both fields exist in the source data.

## Safe visual evidence

A neutral mock webpage can illustrate a *training link target* with a visible `TRAINING / NO LOGIN` label and **no credential input or collection**. Such a mockup is illustrative and must not be described as a captured phishing kit.

## References

- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1608/005/
- https://attack.mitre.org/techniques/T1566/002/
