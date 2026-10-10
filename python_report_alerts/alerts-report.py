import json
import glob
import os
from collections import defaultdict

# Resolve the directory of this script so paths don't depend on where it's executed from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Locate the correlated JSON produced by the previous pipeline step
CORRELATED_FILES = glob.glob(os.path.join(BASE_DIR, "..", "RESULTS", "*", "correlated.json"))
if not CORRELATED_FILES:
    raise SystemExit("No correlated.json files found. Run the correlation step first.")
INPUT_JSON = max(CORRELATED_FILES, key=os.path.getmtime)  # Refer to the most recent one

# Define the output Markdown report location
PCAP_NAME = os.path.basename(os.path.dirname(INPUT_JSON))
OUTPUT_DIR = os.path.join(BASE_DIR, "..", "RESULTS", PCAP_NAME)
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_MD = os.path.join(OUTPUT_DIR, "alerts_report.md")

# ------------------------------------------
# Helpers
# ------------------------------------------

def geo_str(g):
    # Convert geo-enrichment data into a short, human-readable string
    if not g:
        return "Unknown"
    return f"LOCATION: {g.get('country')}, {g.get('city')} / ASN: {g.get('asn')}, {g.get('asn_org')}"

def zeek_summary(zeek_events):
    # Return a default message when no Zeek application-layer data exists
    if not zeek_events:
        return ["No application-layer activity observed"]

    summary = []

    # Summarize HTTP activity by response status
    if "http.log" in zeek_events:
        for ev in zeek_events["http.log"]:
            summary.append(
                f"HTTP: status {ev.get('status_code')} {ev.get('status_msg')}"
            )

    # Summarize TLS behavior based on whether the handshake completed
    if "ssl.log" in zeek_events:
        for ev in zeek_events["ssl.log"]:
            if ev.get("established"):
                summary.append("TLS: handshake established")
            else:
                summary.append("TLS: handshake attempted but not established")

    # Summarize any files observed during the connection
    if "files.log" in zeek_events:
        for ev in zeek_events["files.log"]:
            summary.append(
                f"File: {ev.get('mime_type')} ({ev.get('seen_bytes')} bytes)"
            )

    # Collect and summarize unusual or anomalous protocol behavior
    if "weird.log" in zeek_events:
        names = {ev.get("name") for ev in zeek_events["weird.log"]}
        summary.append("Anomalies: " + ", ".join(sorted(names)))

    return summary


# ------------------------------------------
# Load correlated data
# ------------------------------------------

# Load the full list of correlated Suricata and Zeek events
with open(INPUT_JSON, "r") as f:
    alerts = json.load(f)

# Group alerts by severity to structure the report
by_severity = defaultdict(list)
for entry in alerts:
    sev = entry["suricata_alert"]["alert"]["severity"]
    by_severity[sev].append(entry)

# ------------------------------------------
# Render Markdown
# ------------------------------------------

# Build the Markdown report incrementally as a list of lines
md = []
md.append("# Consolidated PCAP Alert Report\n")

# Iterate through severities in order to group alerts logically
for severity in sorted(by_severity.keys()):
    md.append(f"## Severity {severity}\n")

    for idx, entry in enumerate(by_severity[severity], start=1):
        a = entry["suricata_alert"]

        # Start a new section for each individual alert (fixed to H3 hierarchy)
        md.append(f"### Alert {idx}\n")

        # Add core alert metadata for quick identification
        md.append(f"- **Timestamp:** {a.get('timestamp')}")
        md.append(f"- **Signature:** {a['alert']['signature']}")
        md.append(f"- **Category:** {a['alert']['category']}")
        md.append(f"- **Community ID:** `{entry['community_id']}`\n")

        # Describe the network flow and include geo-enrichment
        md.append("- **Flow:**")
        md.append(f"  - Source: {a['src_ip']}:{a['src_port']} ({geo_str(a.get('src_ip_geo'))})")
        md.append(f"  - Destination: {a['dest_ip']}:{a['dest_port']} ({geo_str(a.get('dest_ip_geo'))})")
        md.append(f"  - Protocol: {a.get('proto')}\n")

        # Add a concise summary of related Zeek application layer context
        md.append("- **Zeek Context Summary:**")
        md.append(f"  - Zeek UID: `{entry['zeek_uid']}`")
        for line in zeek_summary(entry.get("zeek_events", {})):
            md.append(f"  - {line}")
        md.append("") # Add spacing between alerts

# ------------------------------------------
# Write Report to File
# ------------------------------------------

with open(OUTPUT_MD, "w") as f:
    f.write("\n".join(md))

print(f"[+] Markdown report written successfully to {OUTPUT_MD}")