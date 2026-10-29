[![Watch the video](https://img.youtube.com/vi/maXVewChcpA/0.jpg)](https://youtu.be/maXVewChcpA)

# Network Threat Hunting Pipeline

Automated PCAP analysis pipeline using Ansible, Suricata, Zeek, and Python.  
Feed it a PCAP. Get back enriched alerts, geo-ASN attribution, Zeek protocol context, and a structured Markdown report.

---

## Pipeline Overview

```
PCAP
 │
 ├──► [initial]                 Setup and pre-run checks
 ├──► [suricata_run]            Generate eve.json alert stream
 ├──► [zeek_run]                Generate protocol logs (conn, dns, http, ssl, files, weird …)
 ├──► [python_asngeo]           GeoIP2 + ASN enrichment → eve_extra.json
 ├──► [python_correlate]        Community-ID join → correlated.json
 ├──► [python_report_alerts]    Per-alert Markdown report → alerts_report.md
 ├──► [python_report_stats]     Aggregated statistics → stats_report.md
 ├──► [report_final]            Merge into FINAL_REPORT.md
 └──► [cleanup]                 Remove temporary files
```

## Directory Structure

```
PCAPS/
├── ansible/
│   ├── playbook.yml
│   ├── inventory/
│   │   └── hosts.yml
│   └── roles/
│       ├── initial/
│       ├── suricata_run/
│       ├── zeek_run/
│       ├── python_asngeo/
│       ├── python_correlate/
│       ├── python_report_alerts/
│       ├── python_report_stats/
│       ├── report_final/
│       └── cleanup/
├── python_asngeo/
│   └── geo-asn.py
├── python_correlate/
│   └── correlate.py
├── python_report_alerts/
│   └── alerts-report.py
├── python_report_stats/
│   └── stats-report.py
├── report_final/
│   └── join-reports.py
├── LOGS/                          ← gitignored
│   ├── suricata/<pcap_name>/
│   │   ├── eve.json
│   │   └── eve_extra.json         ← enriched
│   └── zeek/<pcap_name>/
│       ├── conn.log
│       ├── dns.log
│       ├── http.log
│       └── ...
├── RESULTS/<pcap_name>/           ← gitignored
│   ├── correlated.json
│   ├── alerts_report.md
│   ├── stats_report.md
│   └── FINAL_REPORT.md
└── TODO/
    └── *.pcap                     ← gitignored
```

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

## Installation
Install dependencies in this order before running the pipeline.

```bash
# Suricata v8.0+
Suricata is the IDS engine that reads PCAP files and produces eve.json alert events.
# Add OISF stable PPA (Ubuntu/Debian)
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install suricata -y

# Update rulesets (ET Open is included by default)
sudo suricata-update

# Enable service
sudo systemctl enable suricata

# Verify
suricata -V
# Expected: Suricata version 8.x.x RELEASE
```

```bash
# Zeek v9.0+
Zeek is the Network Security Monitor that captures full protocol context — conn, dns, http, ssl, files, and weird logs — alongside Suricata alerts.
# Add Zeek repository (Ubuntu 22.04 — adjust xUbuntu_XX.04 for your version)
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
  | sudo tee /etc/apt/sources.list.d/zeek.list

# Import GPG key
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null

sudo apt update
sudo apt install zeek -y

# Add Zeek to PATH
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
zeek --version
# Expected: Zeek version 9.x.x
```

```bash
# Ansible v2.17+
Ansible orchestrates the full 9-role pipeline.

sudo apt update
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:ansible/ansible -y
sudo apt install ansible -y

# Verify
ansible --version
# Expected: ansible [core 2.17.x]
```

```bash
# Python 3.10+ and geoip2
# Confirm Python version
python3 --version

# Install geoip2
pip3 install geoip2

# Verify
python3 -c "import geoip2; print(geoip2.__version__)"
```
```bash
# GeoLite2 Databases (MaxMind)
Two offline databases map IPs to country, city, ASN, and organization. Free account required: https://www.maxmind.com/en/geolite2/signup
# Create the directory the pipeline expects
sudo mkdir -p /opt/geoip

# Download from MaxMind (My Account → Download Files):
#   GeoLite2-ASN.mmdb
#   GeoLite2-City.mmdb

sudo mv GeoLite2-ASN.mmdb  /opt/geoip/
sudo mv GeoLite2-City.mmdb /opt/geoip/

# Verify
ls /opt/geoip/
```

```bash
# Clone
git clone https://github.com/JujuJuhu/Network-Threat-Hunting-Automation.git
cd PCAPS/

# Create required directories
mkdir -p PCAPS/TODO PCAPS/DONE PCAPS/LOGS PCAPS/RESULTS
```

---

## Usage

```bash
# Drop a PCAP in the PCAPS/TODO folder, then:
cd ansible
ansible-playbook playbook.yml

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
