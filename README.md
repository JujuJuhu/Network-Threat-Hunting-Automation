# Network Threat Hunting Pipeline

Automated PCAP analysis pipeline using Ansible, Suricata, Zeek, and Python.  
Feed it a PCAP. Get back enriched alerts, geo-ASN attribution, Zeek protocol context, and a structured Markdown report.

---

## Pipeline Overview

PCAP
│
├─► [suricata_run] Eve.json alert stream
├─► [zeek_run] Protocol logs (conn, dns, http, ssl, files, weird …)
├─► [python_asngeo] GeoIP2 + ASN enrichment → eve_extra.json
├─► [python_correlate] Community-ID join → correlated.json
├─► [python_report_alerts] Per-alert Markdown report
├─► [python_report_stats] Aggregated statistics report
├─► [report_final] Combined FINAL_REPORT.md
└─► [cleanup] Temp file removal


---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Ansible | ≥ 2.17 | Controller node |
| Suricata | ≥ 8.0 | Must be installed on `analysis` host |
| Zeek | ≥ 9.0 | Requires JSON log output mode |
| Python | ≥ 3.10 | With `geoip2` package |
| MaxMind GeoLite2 | Any | ASN, Country, City `.mmdb` at `/opt/geoip/` |

---

## Directory Structure

PCAPS/
├── ansible/
│ ├── playbook.yml
│ ├── inventory/
│ │ └── hosts.yml
│ └── roles/
│ ├── initial/
│ ├── suricata_run/
│ ├── zeek_run/
│ ├── python_asngeo/
│ ├── python_correlate/
│ ├── python_report_alerts/
│ ├── python_report_stats/
│ ├── report_final/
│ └── cleanup/
├── python_asngeo/
│ └── geo-asn.py
├── python_correlate/
│ └── correlate.py
├── python_report_alerts/
│ └── alerts-report.py
├── python_report_stats/
│ └── stats-report.py
├── report_final/
│ └── join-reports.py
├── LOGS/
│ ├── suricata/<pcap_name>/
│ │ ├── eve.json
│ │ └── eve_extra.json ← enriched
│ └── zeek/<pcap_name>/
│ ├── conn.log
│ ├── dns.log
│ ├── http.log
│ └── …
├── RESULTS/<pcap_name>/
│ ├── correlated.json
│ ├── alerts_report.md
│ ├── stats_report.md
│ └── FINAL_REPORT.md
└── PCAPS/
└── *.pcap


---

## Installation

```bash
# Clone
git clone https://github.com/<your-username>/pcap-threat-hunting.git
cd pcap-threat-hunting

# Install Python dependency (system or venv)
pip3 install geoip2

# Download MaxMind GeoLite2 databases (free account required)
# https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Place at:
#   /opt/geoip/GeoLite2-ASN.mmdb
#   /opt/geoip/GeoLite2-Country.mmdb
#   /opt/geoip/GeoLite2-City.mmdb
```

---

## Usage

```bash
# Drop a PCAP in the PCAPS/ folder, then:
cd ansible
ansible-playbook playbook.yml -i inventory/hosts.yml

# Output lands in:
#   RESULTS/<pcap_name>/FINAL_REPORT.md
```

---

## Outputs

| File | Contents |
|------|----------|
| `eve_extra.json` | Suricata events with GeoIP/ASN fields added |
| `correlated.json` | Suricata alerts joined to Zeek events via Community ID |
| `alerts_report.md` | Every alert, severity-grouped, with geo and flow details |
| `stats_report.md` | Top-10 tables: countries, ASNs, IPs, ports, protocols |
| `FINAL_REPORT.md` | stats + alerts combined into one report |

---

## Python Scripts

| Script | Input | Output |
|--------|-------|--------|
| `geo-asn.py` | `eve.json` | `eve_extra.json` |
| `correlate.py` | `eve_extra.json` + Zeek logs | `correlated.json` |
| `alerts-report.py` | `eve_extra.json` | `alerts_report.md` |
| `stats-report.py` | `correlated.json` | `stats_report.md` |
| `join-reports.py` | `stats_report.md` + `alerts_report.md` | `FINAL_REPORT.md` |

---

## Tool Versions (tested)

```json
{ "zeek": "9.0.0", "suricata": "8.0.7", "ansible": "2.17.14" }
```

---

## License

MIT
