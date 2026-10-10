import json
import glob
import os
from collections import Counter

# ------------------------------------------
# Paths
# ------------------------------------------

# Resolve the directory of this script to build reliable relative paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Input: correlated alerts produced by the correlation step
CORRELATED_FILES = glob.glob(os.path.join(BASE_DIR, "..", "RESULTS", "*", "correlated.json"))
if not CORRELATED_FILES:
    raise SystemExit("No correlated.json files found. Run the correlation step first.")
INPUT_JSON = max(CORRELATED_FILES, key=os.path.getmtime)  # Refer to the most recent one

# Output: Markdown file containing aggregated alert statistics
PCAP_NAME = os.path.basename(os.path.dirname(INPUT_JSON))
OUTPUT_DIR = os.path.join(BASE_DIR, "..", "RESULTS", PCAP_NAME)
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_MD = os.path.join(OUTPUT_DIR, "stats_report.md")

# ------------------------------------------
# Load correlated alerts
# ------------------------------------------

# Load all correlated alert records into memory
with open(INPUT_JSON, "r") as f:
    data = json.load(f)

# Record the total number of alerts for global context
total_alerts = len(data)

# ------------------------------------------
# Counters
# ------------------------------------------

# Counters used to aggregate alerts across different dimensions
severity_count = Counter()
country_count = Counter()
asn_count = Counter()
asn_org_map = {}
src_ip_count = Counter()
dest_port_count = Counter()
protocol_count = Counter()

# ------------------------------------------
# Process alerts
# ------------------------------------------

# Iterate over each correlated alert and extract fields for statistics
for entry in data:
    alert = entry.get("suricata_alert", {})
    alert_info = alert.get("alert", {})

    # Core alert attributes
    severity = alert_info.get("severity")
    src_ip = alert.get("src_ip")
    dest_port = alert.get("dest_port")
    proto = alert.get("proto")

    # Geo and ASN information derived from source IP
    src_geo = alert.get("src_ip_geo", {})
    country = src_geo.get("country")
    asn = src_geo.get("asn")
    asn_org = src_geo.get("asn_org")

    # Count alerts by severity level
    if severity is not None:
        severity_count[severity] += 1

    # Count alerts by network protocol
    if proto:
        protocol_count[proto] += 1

    # Count alerts by source IP address
    if src_ip:
        src_ip_count[src_ip] += 1

    # Count alerts by source country
    if country:
        country_count[country] += 1

    # Count alerts by source ASN and remember the ASN organization
    if asn:
        asn_count[asn] += 1
        asn_org_map[asn] = asn_org

    # Count alerts by targeted destination port
    if dest_port:
        dest_port_count[dest_port] += 1

# ------------------------------------------
# Helpers
# ------------------------------------------

# Return the top 10 most common values from a Counter
def top_10(counter):
    return counter.most_common(10)

# ------------------------------------------
# Build Markdown
# ------------------------------------------

# Build the Markdown report incrementally as a list of lines
md = []
md.append("# Threat Overview Summary\n")

# Global statistics section
md.append("## Global Statistics\n")
md.append(f"- **Total alerts:** {total_alerts}\n")

# Alerts grouped by severity
md.append("### Alerts by Severity")
for sev, count in sorted(severity_count.items()):
    md.append(f"- Severity {sev}: {count}")
md.append("")

# Alerts grouped by source country (top 10)
md.append("### Alerts by Source Country")
for country, count in top_10(country_count):
    md.append(f"- {country}: {count}")
md.append("")

# Alerts grouped by source ASN (top 10)
md.append("### Alerts by Source ASN")
for asn, count in top_10(asn_count):
    org = asn_org_map.get(asn, "Unknown")
    md.append(f"- AS{asn} ({org}): {count}")
md.append("")

# Alerts grouped by source IP (top 10)
md.append("### Alerts by Source IP")
for ip, count in top_10(src_ip_count):
    md.append(f"- {ip}: {count}")
md.append("")

# Alerts grouped by targeted destination port (top 10)
md.append("### Alerts by Targeted Destination Port")
for port, count in top_10(dest_port_count):
    md.append(f"- Port {port}: {count}")
md.append("")

# Alerts grouped by protocol
md.append("### Alerts by Protocol")
for proto, count in protocol_count.items():
    md.append(f"- {proto}: {count}")

# ------------------------------------------
# Write output
# ------------------------------------------

# Write the assembled Markdown statistics report to disk
with open(OUTPUT_MD, "w") as f:
    f.write("\n".join(md))

# Confirm successful report generation
print(f"[+] Threat statistics written to {OUTPUT_MD}")