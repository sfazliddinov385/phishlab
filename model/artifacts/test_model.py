"""Quick smoke test - score a couple of example emails."""
import joblib

model = joblib.load("model/artifacts/model_v1.pkl")

test_emails = [
    # Obvious phishing
    "URGENT! Your account has been suspended. Click here to verify your "
    "identity immediately: http://secure-paypa1.com/verify. Act now or your "
    "account will be closed permanently.",

    # Obvious safe
    "Hi team, attaching the Q3 report we discussed in yesterday's meeting. "
    "Let me know if you have any questions before Friday. Thanks!",

    # Trickier phishing - no obvious keywords
    "Dear customer, we noticed unusual activity on your account. Please "
    "confirm your login details at the link below to keep your account active.",
]

for i, email in enumerate(test_emails, 1):
    prob_phish = model.predict_proba([email])[0, 1]
    verdict = "PHISHING" if prob_phish >= 0.5 else "SAFE"
    print(f"\n--- Email {i} ---")
    print(email[:80] + "...")
    print(f"Verdict: {verdict}  (confidence: {prob_phish:.3f})")