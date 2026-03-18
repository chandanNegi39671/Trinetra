"""
train_model.py — Train XGBoost on UCI Phishing Dataset
Shield Squad | Run once before starting app.py

Steps:
  1. Download dataset from Kaggle/UCI:
       https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector
     OR UCI ML Repo (same dataset, 11k rows, ~30 features, balanced)
  2. Place the CSV as  phishing_data.csv  in this folder
  3. Run:  python train_model.py
  4. Output: scam_model.pkl  → app.py auto-loads it

The features we extract in app.py (build_feature_vector) must stay
in sync with the 10 columns selected below (SELECTED_FEATURES).
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

# ── 1. Load dataset ───────────────────────────────────────────────────────────
print("Loading UCI Phishing dataset …")
df = pd.read_csv("phishing_data.csv")
print(f"  Shape: {df.shape}")
print(f"  Columns: {list(df.columns)}")

# ── 2. The UCI dataset label column is usually 'Result'
#       -1 = phishing, 1 = legitimate  → convert to 0/1 ─────────────────────
LABEL_COL = "Result"   # ← change if your CSV uses a different name

if df[LABEL_COL].min() == -1:
    df[LABEL_COL] = df[LABEL_COL].map({1: 0, -1: 1})   # 1 = phishing, 0 = legit

print(f"  Class balance:\n{df[LABEL_COL].value_counts()}")

# ── 3. Feature selection ──────────────────────────────────────────────────────
#
#  UCI dataset has 30 features. We pick the 10 that best mirror our
#  rule-based pipeline so the model generalises to our live feature vector.
#
#  Full UCI feature list:
#    having_IP_Address, URL_Length, Shortining_Service, having_At_Symbol,
#    double_slash_redirecting, Prefix_Suffix, having_Sub_Domain, SSLfinal_State,
#    Domain_registeration_length, Favicon, port, HTTPS_token, Request_URL,
#    URL_of_Anchor, Links_in_tags, SFH, Submitting_to_email, Abnormal_URL,
#    Redirect, on_mouseover, RightClick, popUpWidnow, Iframe, age_of_domain,
#    DNSRecord, web_traffic, Page_Rank, Google_Index, Links_pointing_to_page,
#    Statistical_report, Result

SELECTED_FEATURES = [
    "age_of_domain",          # → age_days proxy
    "DNSRecord",              # → age_score proxy
    "web_traffic",            # → geo_risk_score proxy
    "Statistical_report",     # → is_hosting proxy
    "SSLfinal_State",         # → ssl_risk_score
    "HTTPS_token",            # → has_ssl
    "Domain_registeration_length",  # → ssl_days_left proxy
    "URL_Length",             # → url_pattern_score proxy
    "having_Sub_Domain",      # → num_flags proxy
    "Prefix_Suffix",          # → domain_length proxy
]

# Filter to only columns that exist in this CSV
available = [c for c in SELECTED_FEATURES if c in df.columns]
print(f"\nUsing {len(available)}/{len(SELECTED_FEATURES)} selected features: {available}")

X = df[available].fillna(0)
y = df[LABEL_COL]

# ── 4. Train / Test split ─────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain: {len(X_train)} | Test: {len(X_test)}")

# ── 5. Train XGBoost ──────────────────────────────────────────────────────────
print("\nTraining XGBoost …")
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
)
model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=50,
)

# ── 6. Evaluate ───────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print("\n── Classification Report ─────────────────────────")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

print("── Confusion Matrix ──────────────────────────────")
print(confusion_matrix(y_test, y_pred))

cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
print(f"\n5-fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# ── 7. Feature importance ─────────────────────────────────────────────────────
importance = pd.Series(model.feature_importances_, index=available)
print("\n── Feature Importance ────────────────────────────")
print(importance.sort_values(ascending=False).to_string())

# ── 8. Save model ─────────────────────────────────────────────────────────────
joblib.dump(model, "scam_model.pkl")
print("\n✅  Model saved to scam_model.pkl")
print("   Now start app.py — it will auto-load this model.\n")
