#!/usr/bin/env python3
"""Offline, non-networking summary of locally supplied redacted .eml files."""
import argparse
import csv
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self.hrefs.extend(value for key, value in attrs if key.lower() == "href" and value)

def inspect(path):
    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    links = []
    for part in msg.walk():
        if part.get_content_type() != "text/html":
            continue
        try:
            html = part.get_content()
            parser = LinkParser()
            parser.feed(html)
            links.extend(parser.hrefs)
        except (UnicodeError, LookupError, ValueError, TypeError) as exc:
            print(f"Note: skipped unreadable HTML part in {path.name}: {type(exc).__name__}")
    hosts = set()
    fragments = queries = 0
    for href in links:
        # Normalize only in memory for parsing; never visit or emit full URLs.
        normalized = href.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
        parsed = urlsplit(normalized)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
        fragments += bool(parsed.fragment)
        queries += bool(parsed.query)
    def defang(host):
        return host.replace(".", "[.]")
    return {
        "email_id": path.stem[:12],
        "source_type": "real_redacted_email",
        "domain": ";".join(defang(host) for host in sorted(hosts)),
        "html_links": len(links),
        "unique_url_count": len(set(links)),
        "fragment_links": fragments,
        "query_links": queries,
        "attack_technique": "T1566.002 (candidate)",
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("eml", nargs="+", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    results = [inspect(p) for p in args.eml]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    print(f"Wrote {len(results)} aggregate row(s) to {args.output}")

if __name__ == "__main__":
    main()
