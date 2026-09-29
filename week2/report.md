# Week 2 — Data Collection Process

**Applied to:** Cyber Threat Intelligence Analysis of Phishing Infrastructure

**Recap of Week 1:**  
Week 1 established the theoretical CTI foundation for the project by defining key CTI terms, classifying phishing-related threats, identifying relevant indicators of compromise, and selecting public threat-intelligence sources.

---

## Research Questions

**RQ1:** Which open-source threat intelligence sources provide the most useful information for phishing infrastructure analysis?

**RQ2:** Can different OSINT platforms provide different or conflicting results for the same phishing indicator?

**RQ3:** Does combining URL, domain, IP, registration, certificate, and reputation data provide stronger evidence than relying on a single source?

---

## 1. Open-Source vs. Closed-Source Data

Threat intelligence can be collected from both open and closed sources.

| Data Type | Examples Used / Considered | Why It Matters |
|---|---|---|
| Open-source (OSINT) | VirusTotal, URLhaus, PhishTank, AbuseIPDB, ICANN Lookup, crt.sh, AlienVault OTX | Publicly accessible, reproducible, and suitable for this academic project |
| Closed-source / Commercial | Enterprise SIEM logs, EDR telemetry, private SOC data, paid threat-intelligence feeds | Can provide deeper internal context, but are unavailable for this project |

**Decision:**  
This project is based mainly on open-source and freemium threat-intelligence platforms because they can be accessed without enterprise infrastructure and allow the methodology to be reproduced.

---

## 2. Data Source Selection

The following sources were selected for phishing infrastructure analysis.

| Source | Data Provided | Role in the Project |
|---|---|---|
| URLhaus | Malicious URLs and related infrastructure | Source of malicious or suspicious URLs |
| PhishTank | Reported phishing URLs | Source of phishing samples |
| VirusTotal | URL, domain, IP, and file reputation | Reputation and multi-vendor validation |
| AbuseIPDB | IP reputation and abuse reports | Investigation of suspicious IP addresses |
| ICANN Lookup | Domain registration data | Registrar and registration information |
| crt.sh | Certificate Transparency records | Identification of certificates and related domains |
| AlienVault OTX | Threat intelligence indicators and pulses | Search for related indicators and campaign context |

---

## 3. Sample Selection

A verified and currently online phishing URL was selected from PhishTank for further investigation.

**Source:** PhishTank  
**Phish ID:** 9534755  
**URL:** `https://google.documentspartage.com/`  
**Registered domain:** `documentspartage.com`  
**Subdomain:** `google`  
**Submitted:** September 29, 2026, 6:33 PM  
**Verification status:** Verified — Is a phish  
**Online status:** Online  

The sample was selected because it uses `google` as a subdomain, which may make the URL appear related to Google at first glance. However, the actual registered domain is `documentspartage.com`.

### Evidence

![PhishTank verified sample](images/sample-source-ph.png)

---

## 4. VirusTotal Investigation

The selected phishing subdomain was checked using VirusTotal.

**Indicator checked:** `google.documentspartage.com`

**Detection result:** 0/91 security vendors flagged the domain as malicious.

**Additional information:**

- Registrar: Hosting Concepts B.V. d/b/a Registrar.eu
- Creation date: 4 days before the analysis
- Last analysis date: 4 days before the analysis
- Fortinet classification: Spam

### Evidence

![VirusTotal result](images/virustotal-subdomain.png)

### Interpretation

VirusTotal did not classify the domain as malicious at the time of analysis, even though PhishTank had already verified the URL as a valid phishing site.

This demonstrates an important limitation of relying on a single threat-intelligence source. A newly created phishing domain may not yet be detected by most reputation engines.

The very recent domain creation date also provides additional suspicious context, although domain age alone is not sufficient to classify a site as malicious.

---

## 5. Infrastructure Relations

VirusTotal passive DNS data showed that the phishing subdomain `google.documentspartage.com` resolved to the following IP address:

**Resolved IP:** `45.74.61.11`  
**Date resolved:** September 25, 2026  
**VirusTotal detections for the IP:** 5/91

VirusTotal also identified a sibling subdomain:

**Sibling:** `microsoft.documentspartage.com`  
**Resolved IP:** `141.11.185.74`  
**Detections:** 0/91

This is an important infrastructure finding because the same parent domain contains multiple brand-themed subdomains, including `google` and `microsoft`. This may indicate that the infrastructure is being reused for impersonation or phishing-related activity.

VirusTotal also recorded a historical SSL certificate associated with `google.documentspartage.com`.

### Evidence

![VirusTotal relations](images/virustotal-relations.png)

---
## 6. IP Reputation Investigation

The IP address associated with `google.documentspartage.com` was checked using AbuseIPDB.

**IP address:** `45.74.61.11`

**Abuse Confidence Score:** 0% — Low Risk  
**Total reports:** 8  
**Distinct reporters:** 7  
**Most recent report:** approximately 3 years ago  
**ISP:** MICFO-CA  
**Usage type:** Data Center/Web Hosting/Transit  
**ASN:** AS205397  
**Domain name:** virtualine.org  
**Country:** Germany  
**City:** Frankfurt am Main, Hesse

Historical reports included categories such as DDoS attacks, bad web bots, brute-force activity, email spam, hacking, and web application attacks.

### Evidence

![AbuseIPDB result](images/abuseipdb-result.png)

### Interpretation

AbuseIPDB currently assigns the IP address an Abuse Confidence Score of 0%, indicating low current risk according to its scoring model.

However, the IP has been reported eight times historically, and the previous reports include several types of malicious or suspicious activity.

This result differs from VirusTotal, where the same IP had 5/91 detections. It also differs from PhishTank, which had already verified the associated URL as phishing.

The comparison demonstrates that reputation scores depend heavily on the source, update time, and type of data being analyzed. A low current AbuseIPDB score does not necessarily mean that the infrastructure is safe.

---

## 7. Domain Registration Investigation

The registered domain `documentspartage.com` was checked using the ICANN Registration Data Lookup Tool.

**Domain:** `documentspartage.com`  
**Registrar:** Hosting Concepts B.V. d/b/a Registrar.eu  
**Created:** September 25, 2026  
**Updated:** September 25, 2026  
**Expiration:** September 25, 2027  

**Nameservers:**

- NS1.OPENPROVIDER.NL
- NS2.OPENPROVIDER.BE
- NS3.OPENPROVIDER.EU

The registrant information was redacted by the RDAP service.

### Evidence

![icann result](images/icann-result.png)

### Interpretation

The domain was created only a few days before the phishing sample was submitted to PhishTank.

This recent registration date provides additional suspicious context when combined with the verified phishing status from PhishTank.

However, domain age alone is not sufficient to classify a domain as malicious. In this investigation, it is used together with reputation, passive DNS, and other OSINT evidence.

---

## 7. Certificate Transparency Investigation

Certificate Transparency data was checked using crt.sh.

**Domain:**  
`[INSERT DOMAIN]`

**Certificates found:**  
`[INSERT NUMBER]`

**Related subdomains:**  
`[INSERT RELATED SUBDOMAINS]`

**Issuer:**  
`[INSERT ISSUER]`

### Screenshot

![crt.sh result](images/crtsh-result.png)

### Interpretation

Certificate Transparency data can help identify additional infrastructure associated with the same domain.

In this case, `[INSERT FINDING]`.

---

## 8. AlienVault OTX Investigation

The indicator was searched in AlienVault OTX to identify related indicators or threat-intelligence pulses.

**Indicator:**  
`[INSERT DOMAIN/IP/URL]`

**Pulses found:**  
`[INSERT NUMBER]`

**Related indicators:**  
`[INSERT RESULTS]`

### Screenshot

![OTX result](images/otx-result.png)

### Interpretation

AlienVault OTX provided `[INSERT CONTEXT]`.

This type of threat-intelligence platform can reveal relationships between individual indicators and larger campaigns.

---

## 9. Cross-Source Comparison

The same indicator was compared across multiple sources.

| Source | Indicator | Result |
|---|---|---|
| URLhaus / PhishTank | `[INSERT]` | `[INSERT RESULT]` |
| VirusTotal | `[INSERT]` | `[INSERT RESULT]` |
| AbuseIPDB | `[INSERT IP]` | `[INSERT RESULT]` |
| ICANN Lookup | `[INSERT DOMAIN]` | `[INSERT RESULT]` |
| crt.sh | `[INSERT DOMAIN]` | `[INSERT RESULT]` |
| AlienVault OTX | `[INSERT]` | `[INSERT RESULT]` |

### Key Observation

The most important finding from the comparison was:

`[WRITE YOUR MAIN FINDING HERE]`

Example:

Different intelligence sources provided different levels of context. One source identified the URL as malicious, while another source had limited or no detections. Infrastructure-level sources such as WHOIS and AbuseIPDB provided additional context that was not visible from URL reputation alone.

---

## 10. Data Source Mapping

| Investigation Task | Primary Source | Secondary Source |
|---|---|---|
| Identify phishing URLs | URLhaus / PhishTank | AlienVault OTX |
| Check URL/domain reputation | VirusTotal | AlienVault OTX |
| Analyze IP reputation | AbuseIPDB | VirusTotal |
| Check registration data | ICANN Lookup | WHOIS |
| Identify certificates | crt.sh | — |
| Find related indicators | AlienVault OTX | VirusTotal |

This mapping defines which source should be used for each stage of phishing infrastructure analysis.

---

## 11. Research Findings

### RQ1 — Which sources provide the most useful information?

The most useful sources were `[INSERT SOURCES]` because they provided `[INSERT REASON]`.

No single platform provided all the required information.

---

### RQ2 — Can different OSINT sources disagree?

Yes.

For the selected sample, `[INSERT EXAMPLE OF DIFFERENCE]`.

This demonstrates that threat-intelligence analysis should not rely on a single reputation platform.

---

### RQ3 — Does combining multiple indicators improve analysis?

Yes.

Combining URL, domain, IP, registration, certificate, and reputation data provided more context than analyzing only one indicator.

The combined analysis showed `[INSERT CONCLUSION]`.

---

## 12. Limitations

The Week 2 investigation has several limitations:

- public intelligence sources can contain outdated information;
- reputation results may change over time;
- some services have API or request limits;
- not every malicious domain appears in every threat feed;
- WHOIS information may be privacy-protected;
- shared hosting can make IP-based conclusions unreliable;
- this investigation uses a limited number of real samples;
- the results represent the state of the sources at the time of analysis.

---

## 13. Connection to the Final Project

Week 2 establishes the data-collection layer of the phishing infrastructure analysis workflow.

The results show that phishing infrastructure should be analyzed using multiple sources rather than a single reputation service.

The collected indicators from this week will be used in Week 3 for:

- filtering;
- normalization;
- deduplication;
- enrichment;
- correlation;
- preparation for structured CTI analysis.

---

## References

1. URLhaus  
   https://urlhaus.abuse.ch/

2. PhishTank  
   https://phishtank.org/

3. VirusTotal  
   https://www.virustotal.com/

4. AbuseIPDB  
   https://www.abuseipdb.com/

5. ICANN Registration Data Lookup  
   https://lookup.icann.org/

6. Certificate Transparency Search — crt.sh  
   https://crt.sh/

7. AlienVault Open Threat Exchange  
   https://otx.alienvault.com/

8. OSINT Framework  
   https://osintframework.com/

9. SANS Institute — Cyber Security Whitepapers  
   https://www.sans.org/white-papers/

10. MISP Project  
    https://www.misp-project.org/

---

## Week 2 Deliverables Checklist

- [x] Open-source and closed-source intelligence sources identified
- [x] Relevant OSINT platforms selected
- [ ] Real phishing sample collected from a public source
- [ ] VirusTotal investigation completed
- [ ] IP reputation investigation completed
- [ ] WHOIS / ICANN investigation completed
- [ ] Certificate Transparency investigation completed
- [ ] AlienVault OTX investigation completed
- [ ] Cross-source comparison completed
- [x] Data source mapping prepared
- [ ] Research questions answered using real evidence
- [x] Limitations documented
