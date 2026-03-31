import os
import json
import time
import requests
from datetime import datetime, date
from dotenv import load_dotenv

load_dotenv()

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080")
API_TOKEN      = os.getenv("DEFECTDOJO_API_TOKEN", "")
USE_EPSS       = os.getenv("USE_EPSS", "true").lower() == "true"
OUTPUT_PATH    = "data/raw_findings.json"
PAGE_SIZE      = 100

if not API_TOKEN:
    raise SystemExit("ERROR: DEFECTDOJO_API_TOKEN is not set.")

headers = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
}

print("Fetching findings from DefectDojo...")

findings: list[dict] = []
url = f"{DEFECTDOJO_URL}/api/v2/findings/?limit={PAGE_SIZE}&offset=0&duplicate=false"

while url:
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    findings.extend(data.get("results", []))
    url = data.get("next")
    print(f"  Fetched {len(findings)} / {data.get('count', '?')} findings...")
    time.sleep(0.1)

print(f"Done. {len(findings)} findings collected.")


def extract_cve_ids(finding: dict) -> list[str]:
    """Return all CVE IDs found in a finding, in priority order."""
    cves: list[str] = []

    # a) vulnerability_ids list (API response)
    for item in finding.get("vulnerability_ids") or []:
        if isinstance(item, dict):
            vid = str(item.get("vulnerability_id") or "").strip().upper()
        else:
            vid = str(item).strip().upper()
        if vid.startswith("CVE-"):
            cves.append(vid)

    # b) top-level cve field (legacy / some parsers)
    cve = str(finding.get("cve") or "").strip().upper()
    if cve.startswith("CVE-") and cve not in cves:
        cves.append(cve)

    return cves


def compute_sla(finding: dict) -> int:
    """Return SLA days remaining, preferring API-provided values when available."""
    sla_days_remaining = finding.get("sla_days_remaining")
    if sla_days_remaining is not None:
        try:
            return int(float(sla_days_remaining))
        except (TypeError, ValueError):
            pass

    sla_expiration_date = finding.get("sla_expiration_date")
    if not sla_expiration_date:
        return 0

    try:
        expiration = date.fromisoformat(str(sla_expiration_date)[:10])
        return (expiration - datetime.utcnow().date()).days
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# 3. EPSS enrichment
# ---------------------------------------------------------------------------
if USE_EPSS:
    print("Checking for existing EPSS scores and fetching missing ones...")

    cve_ids_to_fetch: set[str] = set()
    for f in findings:
        # Re-use EPSS already written by defectdojo-epss-patch.py
        if f.get("epss_score") is not None and float(f.get("epss_score", 0)) > 0:
            f["_epss_score"]      = float(f["epss_score"])
            f["_epss_percentile"] = float(f.get("epss_percentile", 0))
            continue

        for cve in extract_cve_ids(f):
            cve_ids_to_fetch.add(cve)

    cve_list = list(cve_ids_to_fetch)
    print(f"  {len(cve_list)} unique CVE IDs need EPSS fetching.")

    epss_map: dict[str, dict] = {}
    for i in range(0, len(cve_list), 30):
        batch = ",".join(cve_list[i : i + 30])
        try:
            r = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": batch},
                timeout=10,
            )
            r.raise_for_status()
            for entry in r.json().get("data", []):
                epss_map[entry["cve"].upper()] = {
                    "epss":       float(entry.get("epss", 0.0)),
                    "percentile": float(entry.get("percentile", 0.0)),
                }
            time.sleep(0.2)
        except Exception as exc:
            print(f"  EPSS batch {i // 30 + 1} failed: {exc}")

    # Attach EPSS to findings that were missing it
    for f in findings:
        if "_epss_score" in f:
            continue
        score = {"epss": 0.0, "percentile": 0.0}
        for cve in extract_cve_ids(f):
            if cve in epss_map:
                score = epss_map[cve]
                break
        f["_epss_score"]      = score["epss"]
        f["_epss_percentile"] = score["percentile"]

    print(f"  EPSS enrichment complete ({len(epss_map)} new scores fetched).")

else:
    for f in findings:
        f["_epss_score"]      = 0.0
        f["_epss_percentile"] = 0.0

for finding in findings:
    finding["_component_name"] = finding.get("component_name") or ""
    finding["_component_version"] = finding.get("component_version") or ""
    finding["_found_by_count"] = len(finding.get("found_by") or [])
    finding["_endpoints_count"] = len(finding.get("endpoints") or [])
    finding["_nb_occurrences"] = finding.get("nb_occurrences", 1)
    finding["_sla_days_remaining"] = compute_sla(finding)

# ---------------------------------------------------------------------------
# 4. Save
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)

output = {
    "collected_at":   datetime.utcnow().isoformat() + "Z",
    "source_url":     DEFECTDOJO_URL,
    "total_findings": len(findings),
    "epss_enriched":  USE_EPSS,
    "findings":       findings,
}

with open(OUTPUT_PATH, "w") as fh:
    json.dump(output, fh, indent=2, default=str)

print(f"\nSaved {len(findings)} findings → {OUTPUT_PATH}")