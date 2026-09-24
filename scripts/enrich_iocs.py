import os
import csv
import time
import requests
from dotenv import load_dotenv

# --- Config ---
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
INPUT_CSV = "evidence/iocs-raw-export.csv"
OUTPUT_CSV = "evidence/iocs-enriched.csv"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

if not API_KEY:
    raise SystemExit("ERROR: ABUSEIPDB_API_KEY not found. Check your .env file.")


def load_iocs(path):
    """Read the Splunk-exported CSV and return a list of dicts (src_ip, failed_attempts)."""
    iocs = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            iocs.append(row)
    return iocs


def check_ip(ip):
    """Query AbuseIPDB for a single IP and return the relevant fields as a dict."""
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]

        return {
            "src_ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "domain": data.get("domain"),
            "lookup_status": "success"
        }

    except requests.exceptions.RequestException as e:
        print(f"  [!] Lookup failed for {ip}: {e}")
        return {
            "src_ip": ip,
            "abuse_score": None,
            "country": None,
            "isp": None,
            "total_reports": None,
            "domain": None,
            "lookup_status": "failed"
        }


if __name__ == "__main__":
    iocs = load_iocs(INPUT_CSV)
    print(f"Loaded {len(iocs)} unique IOCs from {INPUT_CSV}")

    for ioc in iocs:
        ip = ioc["src_ip"]
        print(f"Checking {ip}...")
        result = check_ip(ip)
        print(f"  -> score={result['abuse_score']} country={result['country']} reports={result['total_reports']}")
        time.sleep(1)
