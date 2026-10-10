import json
import glob
import os
import geoip2.database

# Resolve the location of this script so file discovery is execution-location independent
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Locate all Suricata eve.log files and select the most recent run
EVE_FILES = glob.glob(os.path.join(BASE_DIR, "..", "LOGS", "suricata", "*", "eve.json"))

# Stop early if no Suricata output was found
if not EVE_FILES:
    raise SystemExit("No eve.log file found")

# Select the latest eve.log and write an enriched eve_extra.json next to it
OLD_EVE = max(EVE_FILES, key=os.path.getmtime)
NEW_EVE = os.path.join(os.path.dirname(OLD_EVE), "eve_extra.json")

# Paths to GeoIP databases used for enrichment
ASN_DB = "/opt/geoip/GeoLite2-ASN.mmdb"
COUNTRY_DB = "/opt/geoip/GeoLite2-Country.mmdb"
CITY_DB = "/opt/geoip/GeoLite2-City.mmdb"

# Open GeoIP database readers once for reuse
asn_reader = geoip2.database.Reader(ASN_DB)
country_reader = geoip2.database.Reader(COUNTRY_DB)
city_reader = geoip2.database.Reader(CITY_DB)

# Simple in-memory cache to avoid repeating GeoIP lookups for the same IP
cache = {}

def enrich_ip(ip):
    # Return cached enrichment data if we've already seen this IP
    if ip in cache:
        return cache[ip]

    # Container for geo and ASN enrichment fields
    data = {}

    # Attempt to resolve country information
    try:
        country = country_reader.country(ip)
        data["country"] = country.country.iso_code
    except Exception:
        pass

    # Attempt to resolve city information
    try:
        city = city_reader.city(ip)
        data["city"] = city.city.name
    except Exception:
        pass

    # Attempt to resolve ASN and organization information
    try:
        asn = asn_reader.asn(ip)
        data["asn"] = asn.autonomous_system_number
        data["asn_org"] = asn.autonomous_system_organization
    except Exception:
        pass

    # Store the result so future lookups for this IP are instant
    cache[ip] = data
    return data

# Read the original eve log and write a new enriched version side-by-side
with open(OLD_EVE, "r") as old_eve, open(NEW_EVE, "w") as new_eve:
    for line in old_eve:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Enrich both source and destination IPs when present
        for field in ("src_ip", "dest_ip"):
            ip = alert.get(field)
            if ip:
                alert[field + "_geo"] = enrich_ip(ip)

        # Write the enriched event as a JSON line
        new_eve.write(json.dumps(alert) + "\n")

# Explicitly close GeoIP database readers
asn_reader.close()
country_reader.close()
city_reader.close()