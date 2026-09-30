import csv
from collections import OrderedDict

INPUT_FILE = "raw_iocs.csv"
OUTPUT_FILE = "normalized_iocs.csv"

SUPPORTED_TYPES = {"url", "domain", "ip"}

processed = OrderedDict()

with open(INPUT_FILE, newline="", encoding="utf-8") as infile:
    reader = csv.DictReader(infile)

    for row in reader:
        value = row["value"].strip()
        ioc_type = row["type"].strip().lower()

        if not value:
            continue

        if ioc_type not in SUPPORTED_TYPES:
            continue

        if ioc_type in {"domain", "url"}:
            value = value.lower()

        key = (value, ioc_type)

        if key not in processed:
            processed[key] = row.copy()
            processed[key]["value"] = value
            processed[key]["type"] = ioc_type
        else:
            existing = processed[key]

            if row["source"] not in existing["source"]:
                existing["source"] += f"; {row['source']}"

            if row["tags"] not in existing["tags"]:
                existing["tags"] += f"; {row['tags']}"

            if row["notes"] not in existing["notes"]:
                existing["notes"] += f"; {row['notes']}"

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as outfile:
    fieldnames = [
        "value",
        "type",
        "source",
        "confidence",
        "status",
        "tags",
        "notes"
    ]

    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(processed.values())

print(f"Processed {len(processed)} unique IOC values.")
