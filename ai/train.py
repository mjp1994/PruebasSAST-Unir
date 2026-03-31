"""
train.py — Phase 2: Model Training
Trains RandomForest (baseline) and XGBoost (final) on features.csv.

Ground truth (priority label) is synthesised from CVSS + EPSS + severity_score
since DefectDojo does not yet carry a labelled priority field.

Outputs
-------
data/model.pkl          — fitted XGBoost pipeline (the production model)
data/rf_model.pkl       — fitted RandomForest pipeline (baseline, kept for comparison)
data/model_metadata.json — feature list, label encoding, eval metrics
"""

import json
import os
import warnings
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

INPUT_PATH = "data/features.csv"
XGB_OUT    = "data/model.pkl"
RF_OUT     = "data/rf_model.pkl"
META_OUT   = "data/model_metadata.json"

RANDOM_STATE = 42

# ---------------------------------------------------------------------------
# 1. Load
# ---------------------------------------------------------------------------
print(f"Loading {INPUT_PATH}...")
df = pd.read_csv(INPUT_PATH)
print(f"  Shape: {df.shape}")

# ---------------------------------------------------------------------------
# 2. Synthetic ground-truth label
#    "priority" = integer class 0-3  (Low / Medium / High / Critical)
#
#    We combine three risk signals with weights chosen to give a realistic
#    distribution.  A finding is "Critical" only when BOTH CVSS is extreme
#    AND exploitation probability (EPSS) is non-trivial.
#
#    raw_priority = 0.50 * cvss_norm
#                 + 0.30 * epss_norm
#                 + 0.20 * sev_norm
#    Then discretised into 4 buckets by percentile so every class is
#    represented even in small datasets.
# ---------------------------------------------------------------------------
print("Generating synthetic priority labels...")

cvss_norm = df["cvss_score"].clip(0, 10) / 10.0
epss_norm = df["epss_score"].clip(0, 1)
sev_norm  = df["severity_score"].clip(0, 4) / 4.0

raw_priority = (
    0.50 * cvss_norm
    + 0.30 * epss_norm
    + 0.20 * sev_norm
)

# Percentile-based cuts → balanced-ish classes
p33 = np.percentile(raw_priority, 33)
p66 = np.percentile(raw_priority, 66)
p85 = np.percentile(raw_priority, 85)

def assign_label(v):
    if v >= p85:
        return 3   # Critical
    if v >= p66:
        return 2   # High
    if v >= p33:
        return 1   # Medium
    return 0       # Low

df["priority"] = raw_priority.apply(assign_label)
label_names = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
print("  Priority distribution:")
for k, name in label_names.items():
    n = (df["priority"] == k).sum()
    print(f"    {name:8s}: {n:4d}  ({100*n/len(df):.1f}%)")

# ---------------------------------------------------------------------------
# 3. Feature selection
#    Drop non-numeric / leaking / identifier columns.
#    ai_risk_score and ai_severity are also excluded — they are computed from
#    CVSS+EPSS and would trivially leak the label.
# ---------------------------------------------------------------------------
DROP_COLS = [
    "finding_id", "title",
    "severity",        # text; severity_score encodes this numerically
    "ai_risk_score",   # derived from same signals → leakage
    "ai_severity",     # ditto
    "priority",        # the label itself
]

feature_cols = [c for c in df.columns if c not in DROP_COLS and df[c].dtype != object]
print(f"\nFeatures selected ({len(feature_cols)}): {feature_cols}")

X = df[feature_cols].fillna(0).astype(float).values
y = df["priority"].values

# ---------------------------------------------------------------------------
# 4. Pipelines
# ---------------------------------------------------------------------------
rf_pipe = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )),
])

xgb_pipe = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbosity=0,
    )),
])

# ---------------------------------------------------------------------------
# 5. Cross-validation
# ---------------------------------------------------------------------------
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)

print("\nCross-validating RandomForest...")
rf_scores = cross_val_score(rf_pipe, X, y, cv=cv, scoring="f1_weighted", n_jobs=-1)
print(f"  F1-weighted (5-fold): {rf_scores.mean():.4f} ± {rf_scores.std():.4f}")

print("\nCross-validating XGBoost...")
xgb_scores = cross_val_score(xgb_pipe, X, y, cv=cv, scoring="f1_weighted", n_jobs=-1)
print(f"  F1-weighted (5-fold): {xgb_scores.mean():.4f} ± {xgb_scores.std():.4f}")

# ---------------------------------------------------------------------------
# 6. Final fit on full dataset
# ---------------------------------------------------------------------------
print("\nFitting final models on full dataset...")
rf_pipe.fit(X, y)
xgb_pipe.fit(X, y)

# In-sample metrics (informational only)
rf_pred  = rf_pipe.predict(X)
xgb_pred = xgb_pipe.predict(X)

rf_f1  = f1_score(y, rf_pred,  average="weighted")
xgb_f1 = f1_score(y, xgb_pred, average="weighted")
print(f"  RF  in-sample F1 (weighted): {rf_f1:.4f}")
print(f"  XGB in-sample F1 (weighted): {xgb_f1:.4f}")

# One-vs-rest AUC
try:
    rf_proba  = rf_pipe.predict_proba(X)
    xgb_proba = xgb_pipe.predict_proba(X)
    rf_auc  = roc_auc_score(y, rf_proba,  multi_class="ovr", average="weighted")
    xgb_auc = roc_auc_score(y, xgb_proba, multi_class="ovr", average="weighted")
    print(f"  RF  OvR AUC: {rf_auc:.4f}")
    print(f"  XGB OvR AUC: {xgb_auc:.4f}")
except Exception as e:
    rf_auc = xgb_auc = None
    print(f"  AUC calculation skipped: {e}")

print("\nXGBoost classification report (in-sample):")
print(classification_report(y, xgb_pred,
      target_names=[label_names[i] for i in range(4)]))

# Feature importances (XGB)
importances = xgb_pipe.named_steps["clf"].feature_importances_
fi = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
print("Top 10 feature importances (XGBoost):")
for feat, imp in fi[:10]:
    print(f"  {feat:35s}: {imp:.4f}")

# ---------------------------------------------------------------------------
# 7. Save models and metadata
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)

joblib.dump(xgb_pipe, XGB_OUT)
joblib.dump(rf_pipe,  RF_OUT)
print(f"\nSaved XGBoost model  → {XGB_OUT}")
print(f"Saved RandomForest   → {RF_OUT}")

metadata = {
    "trained_at":      pd.Timestamp.utcnow().isoformat() + "Z",
    "n_samples":       int(len(df)),
    "feature_columns": feature_cols,
    "label_encoding":  label_names,
    "label_thresholds": {
        "p33": float(p33),
        "p66": float(p66),
        "p85": float(p85),
    },
    "cv_folds": 5,
    "rf": {
        "cv_f1_mean":  float(rf_scores.mean()),
        "cv_f1_std":   float(rf_scores.std()),
        "insample_f1": float(rf_f1),
        "insample_auc": float(rf_auc) if rf_auc else None,
    },
    "xgb": {
        "cv_f1_mean":  float(xgb_scores.mean()),
        "cv_f1_std":   float(xgb_scores.std()),
        "insample_f1": float(xgb_f1),
        "insample_auc": float(xgb_auc) if xgb_auc else None,
    },
    "feature_importances": {f: float(i) for f, i in fi},
}

with open(META_OUT, "w") as fh:
    json.dump(metadata, fh, indent=2)
print(f"Saved metadata       → {META_OUT}")
print("\nPhase 2 complete.")