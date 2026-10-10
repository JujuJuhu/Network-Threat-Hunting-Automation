import json
import glob
import os

# Resolve the absolute path of this script so all file paths are predictable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Locate the enriched Suricata eve file produced by the latest PCAP run
EVE_JSONS = glob.glob(os.path.join(BASE_DIR, "..", "LOGS", "suricata", "*", "eve_extra.json"))
if not EVE_JSONS:
    raise SystemExit("No enriched Suricata eve_extra.json files found.")
EVE_JSON = max(EVE_JSONS, key=os.path.getmtime)

# Derive PCAP name from Suricata output directory
PCAP_NAME = os.path.basename(os.path.dirname(EVE_JSON))

# Create a dedicated output directory for this PCAP run under PCAPS/RESULTS
OUTPUT_DIR = os.path.join(BASE_DIR, "..", "RESULTS", PCAP_NAME)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Locate the directory containing Zeek logs for the same PCAP
ZEEK_DIRS = glob.glob(os.path.join(BASE_DIR, "..", "LOGS", "zeek", "*"))
if not ZEEK_DIRS:
    raise SystemExit("No Zeek log directories found.")
ZEEK_DIR = max(ZEEK_DIRS, key=os.path.getmtime)

# Define where the final correlation output will be written
OUTPUT_JSON = os.path.join(OUTPUT_DIR, "correlated.json")

# Explicit list of Zeek logs that provide protocol and anomaly context
ZEEK_LOGS = [
    "dns.log",
    "http.log",
    "ssl.log",
    "files.log",
    "sip.log",
    "weird.log",
    "snmp.log",
    "ntp.log",
    "quic.log",
    "tunnel.log",
    "kerberos.log",
    "ldap_search.log",
]

# --------------------------------
# Load Suricata alerts
# --------------------------------

alerts = []

# Read the Suricata event stream line by line (JSON Lines format)
with open(EVE_JSON, "r") as f:
    for line in f:
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        # Keep only alert events that include a Community ID for correlation
        if ev.get("event_type") == "alert" and ev.get("community_id"):
            alerts.append(ev)

# --------------------------------
# Load Zeek conn.log
# --------------------------------

cid_to_uid = {}
conn_log_path = os.path.join(ZEEK_DIR, "conn.log")

if os.path.exists(conn_log_path):
    with open(conn_log_path, "r") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
                
            cid = ev.get("community_id")
            uid = ev.get("uid")

            # Only store mappings where both identifiers exist
            if cid and uid:
                cid_to_uid[cid] = uid
else:
    print(f"[-] Warning: conn.log not found in {ZEEK_DIR}")

# --------------------------------
# Load other Zeek logs (indexed by uid)
# --------------------------------

zeek_by_uid = {}

# Iterate through each Zeek log we care about
for log in ZEEK_LOGS:
    path = os.path.join(ZEEK_DIR, log)

    # Skip logs that were not generated for this PCAP
    if not os.path.exists(path):
        continue

    with open(path, "r") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
                
            uid = ev.get("uid")

            # Ignore events that cannot be tied to a connection
            if not uid:
                continue

            # Group Zeek events by connection UID and log type
            zeek_by_uid.setdefault(uid, {}).setdefault(log, []).append(ev)

# --------------------------------
# Correlate
# --------------------------------

results = []

# Correlate each Suricata alert with its corresponding Zeek context
for alert in alerts:
    cid = alert.get("community_id")
    if not cid:
        continue

    # Use Community ID to pivot from Suricata into Zeek connections
    uid = cid_to_uid.get(cid)

    # Assemble a single correlated record per alert
    results.append({
        "community_id": cid,
        "suricata_alert": alert,
        "zeek_uid": uid,
        # Attach Zeek protocol events if a matching connection exists
        "zeek_events": zeek_by_uid.get(uid, {}) if uid else {},
    })

# --------------------------------
# Output
# --------------------------------

# Write the full correlation result to disk as structured JSON
with open(OUTPUT_JSON, "w") as f:
    json.dump(results, f, indent=2)

# Simple confirmation that the script completed successfully
print(f"[+] Correlated output written to {OUTPUT_JSON}")