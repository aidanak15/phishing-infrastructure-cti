# Project Overview

## Cyber Threat Intelligence Analysis of Phishing Infrastructure

**Topic:** Analysis of phishing infrastructure using Cyber Threat Intelligence (CTI), OSINT sources, and indicator processing techniques.

This project focuses on analyzing phishing-related infrastructure using publicly available threat intelligence and OSINT sources.

The work for Assignment 1 covers Weeks 1–3 of the course syllabus. Each week is stored in a separate folder and applies the weekly tasks directly to the selected project topic.

## What Was Produced

| Week | Folder / File | What it covers |
| --- | --- | --- |
| 1 | `week1/report.md` | CTI fundamentals applied to phishing infrastructure: key terminology, phishing threat classification, indicators of compromise, and relevant threat intelligence sources. |
| 2 | `week2/report.md` | Data collection process: open and closed sources, OSINT platforms, and data-source mapping for phishing investigations. |
| 3 | `week3/report.md` + `raw_iocs.csv` + `normalized_iocs.csv` + `scripts/normalize_iocs.py` | Processing and exploitation of phishing indicators: filtering, normalization, deduplication, and preparation of IOC data for further analysis. |

## Project Scope

The project focuses on phishing-related indicators such as:

- malicious URLs;
- suspicious domains;
- IP addresses;
- domain registration data;
- reputation information;
- relationships between indicators.

The goal is to build a simple CTI workflow that transforms raw phishing intelligence into structured and usable threat data.

## Weekly Workflow

- **Week 1 — Cyber Threat Intelligence Fundamentals:** define CTI concepts, classify phishing threats, and identify relevant indicators.
- **Week 2 — Data Collection Process:** identify and compare data sources used for phishing investigation.
- **Week 3 — Data Processing and Exploitation:** clean, normalize, deduplicate, and organize collected indicators.

## Data Sources

The project uses or evaluates sources such as:

- VirusTotal
- PhishTank
- URLhaus
- AlienVault OTX
- AbuseIPDB
- WHOIS
- crt.sh
- MISP

## Expected Outcome

By the end of Weeks 1–3, the project should provide a basic phishing threat intelligence workflow for:

1. collecting phishing-related indicators;
2. organizing indicators by type and source;
3. processing and normalizing the data;
4. removing duplicates;
5. preparing the data for further analysis and correlation.

## AI Usage Disclosure

AI tools were used only as a supporting assistant for structuring documentation, improving explanations, and helping with Markdown formatting.

The project topic, selected sources, analysis process, and conclusions remain the responsibility of the project authors.
