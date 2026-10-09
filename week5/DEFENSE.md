# Week 5 — 7–8 minute defense guide

**Topic:** Cyber Threat Intelligence Analysis of Phishing Infrastructure

| Time | Presenter talking points | Evidence |
|---|---|---|
| 0:00–0:50 | Project goal and definition of phishing infrastructure | README §1 |
| 0:50–1:40 | Intel-driven vs hypothesis-driven hunting; explain why behavior-based hypotheses were chosen | README §2 |
| 1:40–2:30 | Fictional `asterpay`/`cityparcel` hypotheses, telemetry and dataset provenance | README §§3–4 |
| 2:30–3:20 | Confirm 943 DNS + 60 proxy events in Splunk | Figures 1 & 4 |
| 3:20–4:25 | Keyword hunt: 249 events; contrast two normal domains vs three review candidates | Figure 2 |
| 4:25–5:20 | Shared IP group correlation: two IPs, four domains | Figure 3 |
| 5:20–6:20 | Proxy hunt: five candidate requests and one POST; 420 bytes do not reveal credential content | Figures 5–6 |
| 6:20–7:10 | DNS/proxy co-occurrence: four host-domain pairs; no time-order proof | Figure 7 |
| 7:10–7:40 | Limitations, next steps, repository commits | README §6 and GitHub |

**Defend these distinctions:** student-run queries and screenshots are real; input events are synthetic; `.example` and TEST-NET IPs are reserved; POST is not equivalent to password theft; shared hosting is not proof of maliciousness; keyword rules have both false positives and coverage gaps.

**Before defense:** Put team names and group ID in README; inspect each screenshot for legibility; push files to your own GitHub repository and show commit history. No remote commit has been performed on your behalf.
