"""Compare v1 vs v2 model predictions on the same test emails."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# These imports must happen before joblib.load() so the functions are findable
from phishlab.preprocess import clean_texts, structural_features_transformer  # noqa: F401

import joblib

v1 = joblib.load(ROOT / "model" / "artifacts" / "model_v1.pkl")
v2 = joblib.load(ROOT / "model" / "artifacts" / "model_v2.pkl")

test_emails = [
    # Obvious phishing
    "URGENT! Your account has been suspended. Click here to verify your "
    "identity immediately: http://secure-paypa1.com/verify. Act now or your "
    "account will be closed permanently.",

    # Obvious safe
    "Hi team, attaching the Q3 report we discussed in yesterday's meeting. "
    "Let me know if you have any questions before Friday. Thanks!",

    # Subtle phishing
    "Dear customer, we noticed unusual activity on your account. Please "
    "confirm your login details at the link below to keep your account active.",

    # Legitimate 2026 email - no Enron/SpamAssassin vocabulary
    "Hey, just wanted to confirm our meeting on Tuesday at 2pm. I'll send "
    "the agenda ahead of time. Looking forward to catching up!",

    # Modern phishing - no vintage tokens
    "Microsoft Security Alert: Unusual sign-in activity detected from a new "
    "device. If this wasn't you, verify your identity at the link below "
    "within 24 hours or your account will be locked. http://ms-login-verify.net",
]

for i, email in enumerate(test_emails, 1):
    p1 = v1.predict_proba([email])[0, 1]
    p2 = v2.predict_proba([email])[0, 1]
    v1_label = "PHISH" if p1 >= 0.5 else "SAFE "
    v2_label = "PHISH" if p2 >= 0.5 else "SAFE "
    print(f"\n--- Email {i} ---")
    print(email[:90] + "...")
    print(f"  v1: {v1_label}  ({p1:.3f})")
    print(f"  v2: {v2_label}  ({p2:.3f})")