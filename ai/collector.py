"""
collector.py — Phase 1a
Fetches all findings from DefectDojo, enriches with EPSS scores, saves to JSON.

Usage:
    python collector.py
"""

import os
import json
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DEFECTDOJO_URL  = os.getenv("DEFECTDOJO_URL", "http://localhost:8080")
API_TOKEN       = os.getenv("DEFECTDOJO_API_TOKEN", "")
USE_EPSS        = os.getenv("USE_EPSS", "true").lower() == "true"
OUTPUT_PATH     = "data/raw_findings.json"
PAGE_SIZE       = 100

if not API_TOKEN:
    raise SystemExit("ERROR: DEFECTDOJO_API_TOKEN is not set in your .env file.")

headers = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
}

# ---------------------------------------------------------------------------
# 1. Fetch all findings from DefectDojo (paginated)
# ---------------------------------------------------------------------------
print("Fetching findings from DefectDojo...")

findings = []
url = f"{DEFECTDOJO_URL}/api/v2/findings/?limit={PAGE_SIZE}&offset=0"

while url:
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    findings.extend(data.get("results", []))
    url = data.get("next")          # DefectDojo returns the full next-page URL
    print(f"  Fetched {len(findings)} / {data.get('count', '?')} findings...")
    time.sleep(0.1)

print(f"Done. {len(findings)} findings collected.")

# ---------------------------------------------------------------------------
# 2. Enrich with EPSS scores (FIRST.org public API, no auth needed)
# ---------------------------------------------------------------------------
if USE_EPSS:
    print("Fetching EPSS scores from FIRST.org...")

    # Extract unique CVE IDs
    cve_ids = list({
        f.get("cve_id", "")
        for f in findings
        if str(f.get("cve_id", "")).upper().startswith("CVE-")
    })
    print(f"  {len(cve_ids)} unique CVE IDs found.")

    epss_map = {}
    for i in range(0, len(cve_ids), 30):     # API max: 30 CVEs per call
        batch = ",".join(cve_ids[i:i+30])
        try:
            r = requests.get("https://api.first.org/data/v1/epss",
                             params={"cve": batch}, timeout=10)
            r.raise_for_status()
            for entry in r.json().get("data", []):
                epss_map[entry["cve"].upper()] = {
                    "epss":       float(entry.get("epss", 0.0)),
                    "percentile": float(entry.get("percentile", 0.0)),
                }
            time.sleep(0.2)
        except Exception as e:
            print(f"  EPSS batch {i//30 + 1} failed: {e}")

    for f in findings:
        cve = str(f.get("cve_id", "")).upper()
        scores = epss_map.get(cve, {"epss": 0.0, "percentile": 0.0})
        f["_epss_score"]       = scores["epss"]
        f["_epss_percentile"]  = scores["percentile"]

    print(f"  EPSS enrichment complete ({len(epss_map)} scores fetched).")
else:
    for f in findings:
        f["_epss_score"]      = 0.0
        f["_epss_percentile"] = 0.0

# ---------------------------------------------------------------------------
# 3. Save to disk
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)

output = {
    "collected_at":   datetime.utcnow().isoformat() + "Z",
    "source_url":     DEFECTDOJO_URL,
    "total_findings": len(findings),
    "epss_enriched":  USE_EPSS,
    "findings":       findings,
}

with open(OUTPUT_PATH, "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\nSaved {len(findings)} findings → {OUTPUT_PATH}")