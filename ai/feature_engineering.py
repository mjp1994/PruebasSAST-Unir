import os
import re
import json
import pandas as pd
from datetime import datetime, date, timezone

INPUT_PATH  = "data/raw_findings.json"
OUTPUT_PATH = os.getenv("OUTPUT_PATH", "data/features.csv")

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
    # SAST
    "semgrep":          "SAST",
    "bandit":           "SAST",
    "sonarqube":        "SAST",
    # DAST
    "zap scan":         "DAST",
    "zap":              "DAST",
    # SCA
    "trivy scan":       "SCA",
    "trivy":            "SCA",
    "dependency check": "SCA",
    "snyk":             "SCA",
    "npm audit":        "SCA",
}

CWE_CATEGORY_MAP = {
    # ------------------------------------------------------------------ injection
    # SQL, OS command, code, prototype pollution, format string, encoding abuse
    **{c: "injection" for c in [
        74,    # Improper Neutralisation (generic injection)
        77,    # Command Injection
        78,    # OS Command Injection
        79,    # Cross-site Scripting (XSS)
        80,    # Basic XSS
        89,    # SQL Injection
        94,    # Code Injection
        95,    # Eval Injection
        96,    # OS Command Injection via environment variable
        134,   # Use of Externally-Controlled Format String
        176,   # Improper Handling of Unicode Encoding
        193,   # Off-by-one (commonly enables buffer/injection exploits)
        611,   # XML External Entity (XXE)
        918,   # Server-Side Request Forgery (SSRF)
        1321,  # Prototype Pollution
    ]},

    # ------------------------------------------------------------------ auth
    # Authentication, authorisation bypass, hardcoded credentials, protection failures
    **{c: "auth" for c in [
        285,   # Improper Authorization
        287,   # Improper Authentication
        306,   # Missing Authentication for Critical Function
        307,   # Improper Restriction of Excessive Authentication Attempts
        384,   # Session Fixation
        521,   # Weak Password Requirements
        522,   # Insufficiently Protected Credentials
        640,   # Weak Password Recovery Mechanism
        693,   # Protection Mechanism Failure
        798,   # Use of Hard-coded Credentials
        939,   # Improper Authorization in Handler for Custom URL Scheme
    ]},

    # ------------------------------------------------------------------ crypto
    # Weak algorithms, insufficient randomness, missing integrity checks, hard-coded keys
    **{c: "crypto" for c in [
        310,   # Cryptographic Issues (generic)
        311,   # Missing Encryption of Sensitive Data
        312,   # Cleartext Storage of Sensitive Information
        319,   # Cleartext Transmission of Sensitive Information
        321,   # Use of Hard-coded Cryptographic Key
        326,   # Inadequate Encryption Strength
        327,   # Use of a Broken or Risky Cryptographic Algorithm
        328,   # Use of Weak Hash
        330,   # Use of Insufficiently Random Values
        338,   # Use of Cryptographically Weak PRNG
        347,   # Improper Verification of Cryptographic Signature
        353,   # Missing Support for Integrity Check
        385,   # Covert Timing Channel
        1240,  # Use of Risky Cryptographic Primitive
    ]},

    # ------------------------------------------------------------------ access_control
    # Path traversal, privilege misuse, open redirect, clickjacking, unsafe reflection
    **{c: "access_control" for c in [
        22,    # Path Traversal
        73,    # External Control of File Name / Path
        264,   # Permissions, Privileges, and Access Controls (generic)
        269,   # Improper Privilege Management
        276,   # Incorrect Default Permissions
        284,   # Improper Access Control
        471,   # Modification of Assumed-Immutable Data (MAID)
        601,   # URL Redirection to Untrusted Site (Open Redirect)
        732,   # Incorrect Permission Assignment for Critical Resource
        749,   # Exposed Dangerous Method or Function
        829,   # Inclusion of Functionality from Untrusted Control Sphere
        862,   # Missing Authorisation
        863,   # Incorrect Authorisation
        913,   # Improper Control of Dynamically-Managed Code Resources
        915,   # Improperly Controlled Modification of Dynamically-Determined Object Attributes
        1021,  # Improper Restriction of Rendered UI Layers (Clickjacking)
    ]},

    # ------------------------------------------------------------------ data_exposure
    # Info leaks, sensitive data in cache/logs/responses, directory listing
    **{c: "data_exposure" for c in [
        200,   # Exposure of Sensitive Information to an Unauthorized Actor
        201,   # Insertion of Sensitive Information into Sent Data
        209,   # Generation of Error Message Containing Sensitive Information
        359,   # Exposure of Private Personal Information
        497,   # Exposure of Sensitive System Information to an Unauthorized Control Sphere
        524,   # Use of Cache Containing Sensitive Information
        538,   # File and Directory Information Exposure
        540,   # Inclusion of Sensitive Information in Source Code
        548,   # Exposure of Information Through Directory Listing
        598,   # Use of GET Request Method with Sensitive Query Strings
    ]},

    # ------------------------------------------------------------------ memory
    # Buffer issues, use-after-free, null dereference, memory leaks
    **{c: "memory" for c in [
        119,   # Improper Restriction of Operations within Bounds of a Memory Buffer
        120,   # Buffer Copy without Checking Size of Input
        121,   # Stack-based Buffer Overflow
        122,   # Heap-based Buffer Overflow
        125,   # Out-of-bounds Read
        401,   # Missing Release of Memory after Effective Lifetime
        416,   # Use After Free
        476,   # NULL Pointer Dereference
    ]},

    # ------------------------------------------------------------------ config
    # Misconfiguration, unmaintained dependencies, type errors
    **{c: "config" for c in [
        16,    # Configuration
        358,   # Improperly Implemented Security Check for Standard
        547,   # Use of Hard-coded, Security-relevant Constants
        614,   # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        704,   # Incorrect Type Conversion or Cast
        843,   # Type Confusion
        1004,  # Sensitive Cookie Without 'HttpOnly' Flag
        1104,  # Use of Unmaintained Third-Party Components
    ]},

    # ------------------------------------------------------------------ resource_mgmt  (NEW)
    # Recursion, ReDoS, uninitialized resources, exhaustion, loops, leaks, TOCTOU
    **{c: "resource_mgmt" for c in [
        367,   # Time-of-check Time-of-use (TOCTOU) Race Condition
        399,   # Resource Management Errors (generic)
        400,   # Uncontrolled Resource Consumption
        407,   # Algorithmic Complexity (ReDoS-class)
        459,   # Incomplete Cleanup
        674,   # Uncontrolled Recursion
        770,   # Allocation of Resources Without Limits or Throttling
        772,   # Missing Release of Resource after Effective Lifetime
        835,   # Loop with Unreachable Exit Condition (Infinite Loop)
        908,   # Use of Uninitialized Resource
        1050,  # Excessive Platform Resource Consumption within a Loop
        1333,  # Inefficient Regular Expression Complexity (ReDoS)
    ]},

    # ------------------------------------------------------------------ input_validation  (NEW)
    # Integer overflow, bad validation, uncaught exceptions, unusual conditions
    **{c: "input_validation" for c in [
        20,    # Improper Input Validation
        190,   # Integer Overflow or Wraparound
        248,   # Uncaught Exception
        705,   # Incorrect Control Flow Scoping
        754,   # Improper Check for Unusual or Exceptional Conditions
        1035,  # OWASP Top Ten 2017: A9 - Using Components with Known Vulnerabilities
    ]},
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_scanner(test_field) -> str:
    """
    FIX 1 — resolve scanner category from the test string.

    DefectDojo returns test as either:
      • a plain string: "trivy-image-results.json (Trivy Scan)"
      • a dict:         {"id": 45, "title": "trivy-image-results.json",
                         "test_type": {"name": "Trivy Scan"}, ...}

    We prefer the parenthesised name in the string representation because it is
    always present.  If test is a dict we fall back to test_type.name.
    """
    if isinstance(test_field, str):
        m = re.search(r"\(([^)]+)\)\s*$", test_field)
        label = m.group(1).lower() if m else test_field.lower()
    elif isinstance(test_field, dict):
        tt = test_field.get("test_type") or {}
        label = (
            tt.get("name") or test_field.get("title") or ""
        ).lower()
    else:
        label = ""

    for key, cat in SCANNER_MAP.items():
        if key in label:
            return cat
    return "OTHER"


def extract_cve(f: dict) -> bool:
    """
    FIX 3 — detect presence of a CVE from any of the locations DefectDojo
    might store it.
    """
    vids = f.get("vulnerability_ids")
    if isinstance(vids, str) and _CVE_RE.search(vids):
        return True
    if isinstance(vids, list):
        for item in vids:
            vid = item.get("vulnerability_id", "") if isinstance(item, dict) else str(item)
            if _CVE_RE.search(vid):
                return True

    cve = f.get("cve") or ""
    if isinstance(cve, str) and cve.upper().startswith("CVE-"):
        return True

    if _CVE_RE.search(f.get("title") or ""):
        return True

    return False


def parse_age(date_val) -> int:
    """
    FIX 2 — handle both datetime.date objects and ISO-string dates.
    Returns age in days (≥0) or -1 if unparseable.
    """
    if date_val is None:
        return -1

    if isinstance(date_val, datetime):
        dt = date_val.replace(tzinfo=timezone.utc) if date_val.tzinfo is None else date_val
        return max((datetime.now(timezone.utc) - dt).days, 0)
    if isinstance(date_val, date):
        dt = datetime(date_val.year, date_val.month, date_val.day, tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - dt).days, 0)

    try:
        dt = datetime.fromisoformat(str(date_val).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - dt).days, 0)
    except (ValueError, TypeError):
        return -1

# ---------------------------------------------------------------------------
# 1. Load raw findings
# ---------------------------------------------------------------------------
print(f"Loading {INPUT_PATH}...")

with open(INPUT_PATH) as fh:
    raw = json.load(fh)

findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
print(f"  {len(findings)} findings loaded.")

# FIX 4 — skip duplicates
before = len(findings)
findings = [f for f in findings if not f.get("duplicate", False)]
skipped = before - len(findings)
if skipped:
    print(f"  Skipped {skipped} duplicate findings ({len(findings)} remaining).")

# ---------------------------------------------------------------------------
# 2. Build feature rows
# ---------------------------------------------------------------------------
print("Building feature matrix...")

rows = []
for f in findings:

    severity = (f.get("severity") or "info").lower().strip()
    if severity not in SEVERITY_SCORE:
        severity = "info"

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

    scanner = extract_scanner(f.get("test"))

    try:
        cwe_id  = int(str(f.get("cwe", "0")).replace("CWE-", "").strip())
        cwe_cat = CWE_CATEGORY_MAP.get(cwe_id, "other")
    except (ValueError, TypeError):
        cwe_cat = "unknown"

    epss     = float(f.get("_epss_score", 0.0))
    epss_pct = float(f.get("_epss_percentile", 0.0))

    has_cve = 1 if extract_cve(f) else 0

    age = parse_age(f.get("date") or f.get("created"))

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
        "nb_occurrences":  f.get("_nb_occurrences", 1),
        "endpoints_count": f.get("_endpoints_count", 0),
        "found_by_count":  f.get("_found_by_count", 1),
        "has_component":   1 if f.get("_component_name") else 0,
    })

df = pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# 3. Compute AI risk score
# ---------------------------------------------------------------------------
cvss_norm = df["cvss_score"] / 10.0
epss_norm = df["epss_score"]
sev_norm  = df["severity_score"] / 4.0
freshness = df["age_days"].apply(
    lambda d: 0.5 if d < 0 else max(0.0, 1.0 - d / 365.0)
)

df["ai_risk_score"] = (
    1.0 + (
        0.40 * cvss_norm
        + 0.30 * epss_norm
        + 0.20 * sev_norm
        + 0.10 * freshness
    ) * 9.0
).round(2)

df["ai_severity"] = pd.cut(
    df["ai_risk_score"],
    bins=[0, 2, 4, 6.5, 8.5, 10],
    labels=["Info", "Low", "Medium", "High", "Critical"],
    right=True,
)

df = pd.get_dummies(df, columns=["scanner", "cwe_category"], prefix=["scanner", "cwe"], dtype=int)

# ---------------------------------------------------------------------------
# 4. Save
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)
df.to_csv(OUTPUT_PATH, index=False)

print(f"  Feature matrix: {df.shape[0]} rows × {df.shape[1]} columns")
print(f"\nAI Risk Score summary:\n{df['ai_risk_score'].describe().round(2).to_string()}")
print(f"\nAI Severity distribution:\n{df['ai_severity'].value_counts().to_string()}")

scanner_cols = [c for c in df.columns if c.startswith("scanner_")]
print(f"\nScanner columns: {scanner_cols}")
for col in scanner_cols:
    print(f"  {col}: {df[col].sum()} findings")

cwe_cols = [c for c in df.columns if c.startswith("cwe_")]
print(f"\nCWE category columns:")
for col in sorted(cwe_cols):
    print(f"  {col}: {df[col].sum()} findings")

has_cve_count = df["has_cve"].sum() if "has_cve" in df.columns else 0
print(f"\nhas_cve=1: {has_cve_count} findings")

age_valid = (df["age_days"] >= 0).sum()
print(f"age_days >= 0: {age_valid} findings")

print(f"\nSaved → {OUTPUT_PATH}")