"""
Diagnostic: examine what the v1 model actually learned.
I want to see if top features are real phishing signals or dataset artifacts.
"""
import joblib
import pandas as pd

MODEL_PATH = "model/artifacts/model_v1.pkl"

pipeline = joblib.load(MODEL_PATH)
vectorizer = pipeline.named_steps["tfidf"]
classifier = pipeline.named_steps["clf"]

feature_names = vectorizer.get_feature_names_out()
coefs = classifier.coef_[0]

# Build a sorted dataframe of features by coefficient
df = pd.DataFrame({"feature": feature_names, "coef": coefs})
df = df.sort_values("coef")

print("=" * 60)
print("TOP 25 SAFE INDICATORS (most negative coefficients)")
print("=" * 60)
for _, row in df.head(25).iterrows():
    print(f"  {row['coef']:+.3f}  {row['feature']}")

print("\n" + "=" * 60)
print("TOP 25 PHISHING INDICATORS (most positive coefficients)")
print("=" * 60)
for _, row in df.tail(25).iloc[::-1].iterrows():
    print(f"  {row['coef']:+.3f}  {row['feature']}")

# Flag suspicious features - these are signs of dataset bias
print("\n" + "=" * 60)
print("SUSPICIOUS FEATURES (dataset-specific, not phishing signals)")
print("=" * 60)
suspect_patterns = [
    "enron", "vince", "louise", "linguistics", "edu",
    "2001", "2002", "2003", "2004", "2005", "2006",
    "spamassassin", "url", "wrote",
]
flagged = df[df["feature"].str.contains("|".join(suspect_patterns), case=False, na=False)]
flagged = flagged.sort_values("coef", key=abs, ascending=False).head(20)
for _, row in flagged.iterrows():
    print(f"  {row['coef']:+.3f}  {row['feature']}")
