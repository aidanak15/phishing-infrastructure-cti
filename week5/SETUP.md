# Run and verify Week 5

## Local generation and checks

Requires Python 3.9+; no third-party packages are required for generator/tests.

```bash
python3 scripts/generate_data.py
python3 scripts/hunt.py
python3 scripts/test_hunt.py
```

Check `results/hunt_results.json`; compare it with actual SIEM results after import. The local script checks logic but **does not execute Splunk or ELK**.

## Option A — Splunk (recommended if already installed)

1. Open Splunk Web → **Settings → Add Data → Upload**.
2. Upload `data/dns.csv`, select CSV as the data format, choose `main` index and set sourcetype **`phish_dns`**. Map `timestamp` to event time if desired. Avoid repeated upload of the same file.
3. Upload `data/proxy.csv` to `main` with sourcetype **`phish_proxy`**.
4. Open **Search & Reporting**, set time range **All time**, paste **one query block at a time** from `queries/splunk_hunts.spl` (do not paste `//` comments).
5. Execute Q0, Q1, Q2, Q3, Q4. Check Q0 gives **943** DNS events and **12** hosts; if not, verify selected index/sourcetypes, timestamp extraction and duplicate ingestion.
6. Capture unedited screenshots showing each search and its output in the SIEM. Save as `screenshots/01_import_check.png` ... `screenshots/05_shared_ips.png`.

## Option B — Elastic/Kibana

1. Import `data/dns.csv` and `data/proxy.csv` into indices `phish-dns` and `phish-proxy` (Kibana file upload or your Elastic data ingestion workflow).
2. Ensure `domain`, `hostname`, `event_id`, and `answer_ip` are **keyword** fields. `timestamp` should be mapped as date; `bytes_out` can be a numeric type.
3. In Kibana ES|QL run each block in `queries/elastic_hunts.esql` separately. Query language / import mapping depend on installed Elastic version; modify mappings if required, and document deviations.
4. Capture actual output as described above.

## GitHub commits (run in your own repository)

```bash
mkdir -p screenshots
# put screenshots from your actual SIEM run into screenshots/
git add week5/
git commit -m "Week 5: hypothesis-driven phishing infrastructure hunt"
git push
```

If the project files are in repository root rather than `week5/`, adjust `git add`. Commit incremental improvements throughout the week instead of a single retrospective commit. Verify `git status` and the commit history before defense.

**Do not upload any credentials, confidential logs, or sensitive user information.**
