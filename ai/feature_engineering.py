"""
feature_engineering.py — Phase 1b
Loads raw findings, builds a feature matrix, computes AI risk scores, saves to CSV.

Usage:
    python feature_engineering.py
"""

import os
import json
import pandas as pd
from datetime import datetime, timezone

INPUT_PATH  = "data/raw_findings.json"
OUTPUT_PATH = "data/features.csv"

# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------

SEVERITY_SCORE = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0
}

SEVERITY_TO_CVSS = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5, "informational": 0.5
}

SCANNER_MAP = {
    "semgrep": "SAST", "bandit": "SAST", "sonarqube": "SAST",
    "zap": "DAST", "zaproxy": "DAST", "owasp zap": "DAST",
    "trivy": "SCA", "dependency-check": "SCA", "dependency check": "SCA",
    "snyk": "SCA", "npm audit": "SCA",
}

CWE_CATEGORY_MAP = {
    **{c: "injection"      for c in [89,77,78,79,80,611,918]},
    **{c: "auth"           for c in [287,306,307,384,521,522,640]},
    **{c: "crypto"         for c in [310,311,312,319,326,327,328,338]},
    **{c: "access_control" for c in [22,269,276,284,732,862,863]},
    **{c: "data_exposure"  for c in [200,201,209,359,540]},
    **{c: "memory"         for c in [119,120,121,122,125,401,416,476]},
    **{c: "config"         for c in [16,358,547,614,1004]},
}

# ---------------------------------------------------------------------------
# 1. Load raw findings
# ---------------------------------------------------------------------------
print(f"Loading {INPUT_PATH}...")

with open(INPUT_PATH) as f:
    raw = json.load(f)

findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
print(f"  {len(findings)} findings loaded.")

# ---------------------------------------------------------------------------
# 2. Build feature rows
# ---------------------------------------------------------------------------
print("Building feature matrix...")

rows = []
for f in findings:

    # Severity
    severity = (f.get("severity") or "info").lower().strip()
    if severity not in SEVERITY_SCORE:
        severity = "info"

    # CVSS score — try v3, v2, fallback to severity
    cvss = None
    for field in ("cvssv3_score", "cvssv2_score", "cvss_score"):
        val = f.get(field)
        if val is not None:
            try:
                cvss = float(val)
                break
            except (ValueError, TypeError):
                pass
    if cvss is None or not (0.0 <= cvss <= 10.0):
        cvss = SEVERITY_TO_CVSS.get(severity, 0.5)

    # Scanner category
    test_type = ""
    if isinstance(f.get("test"), dict):
        test_type = f["test"].get("type", "") or ""
    test_type_lower = test_type.lower()
    scanner = next((cat for key, cat in SCANNER_MAP.items() if key in test_type_lower), "OTHER")

    # CWE category
    try:
        cwe_id   = int(str(f.get("cwe", "0")).replace("CWE-", "").strip())
        cwe_cat  = CWE_CATEGORY_MAP.get(cwe_id, "other")
    except (ValueError, TypeError):
        cwe_cat  = "unknown"

    # EPSS (already attached by collector.py)
    epss     = float(f.get("_epss_score", 0.0))
    epss_pct = float(f.get("_epss_percentile", 0.0))

    # Has a CVE?
    has_cve = 1 if str(f.get("cve_id", "")).upper().startswith("CVE-") else 0

    # Age in days
    date_str = f.get("date") or f.get("created") or ""
    try:
        dt      = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
        age     = max((datetime.now(timezone.utc) - dt).days, 0)
    except (ValueError, TypeError):
        age     = -1

    rows.append({
        "finding_id":      f.get("id", -1),
        "title":           f.get("title", ""),
        "severity":        severity,
        "scanner":         scanner,
        "cwe_category":    cwe_cat,
        "cvss_score":      cvss,
        "epss_score":      epss,
        "epss_percentile": epss_pct,
        "severity_score":  SEVERITY_SCORE.get(severity, 0),
        "age_days":        age,
        "is_verified":     int(bool(f.get("verified", False))),
        "is_active":       int(bool(f.get("active", True))),
        "has_cve":         has_cve,
    })

df = pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# 3. Compute synthetic AI risk score (ground truth for training)
#
#   Formula (weighted, scaled to 1–10):
#     CVSS      40%  — base vulnerability severity
#     EPSS      30%  — real-world exploit probability
#     Severity  20%  — normalised label
#     Freshness 10%  — newer findings = higher urgency
# ---------------------------------------------------------------------------
cvss_norm = df["cvss_score"] / 10.0
epss_norm = df["epss_score"]
sev_norm  = df["severity_score"] / 4.0
freshness = df["age_days"].apply(lambda d: 0.5 if d < 0 else max(0.0, 1.0 - d / 365.0))

df["ai_risk_score"] = (1.0 + (0.40 * cvss_norm + 0.30 * epss_norm + 0.20 * sev_norm + 0.10 * freshness) * 9.0).round(2)

df["ai_severity"] = pd.cut(
    df["ai_risk_score"],
    bins=[0, 2, 4, 6.5, 8.5, 10],
    labels=["Info", "Low", "Medium", "High", "Critical"],
    right=True,
)

# One-hot encode categorical columns
df = pd.get_dummies(df, columns=["scanner", "cwe_category"], prefix=["scanner", "cwe"], dtype=int)

# ---------------------------------------------------------------------------
# 4. Save
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)
df.to_csv(OUTPUT_PATH, index=False)

print(f"  Feature matrix: {df.shape[0]} rows × {df.shape[1]} columns")
print(f"\nAI Risk Score summary:\n{df['ai_risk_score'].describe().round(2).to_string()}")
print(f"\nAI Severity distribution:\n{df['ai_severity'].value_counts().to_string()}")
print(f"\nSaved → {OUTPUT_PATH}")