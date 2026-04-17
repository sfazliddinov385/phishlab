"""
Phishing email classifier - v1
Trains a TF-IDF + Logistic Regression model on the Kaggle phishing email dataset.
"""

import pandas as pd
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

# --- Config ---
DATA_PATH = Path("Phishing_Email.csv")
MODEL_OUT = Path("model/artifacts/model_v1.pkl")
RANDOM_STATE = 42


def load_data(path: Path) -> pd.DataFrame:
    """Load the Kaggle phishing email CSV and clean it up."""
    df = pd.read_csv(path)

    # Drop the junk index column
    if "Unnamed: 0" in df.columns:
        df = df.drop(columns=["Unnamed: 0"])

    # Drop any rows with missing email text
    before = len(df)
    df = df.dropna(subset=["Email Text"])
    after = len(df)
    if before != after:
        print(f"Dropped {before - after} rows with missing email text")

    # Make sure text is string type
    df["Email Text"] = df["Email Text"].astype(str)

    # Convert labels to 0/1: phishing = 1, safe = 0
    df["label"] = (df["Email Type"] == "Phishing Email").astype(int)

    print(f"Loaded {len(df)} emails")
    print(f"  Phishing: {df['label'].sum()} ({df['label'].mean():.1%})")
    print(f"  Safe:     {(df['label'] == 0).sum()} ({(df['label'] == 0).mean():.1%})")

    return df


def build_pipeline() -> Pipeline:
    """TF-IDF vectorizer + Logistic Regression classifier."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=10_000,      # top 10k words only
            ngram_range=(1, 2),       # single words and 2-word phrases
            stop_words="english",     # drop common words like "the", "is"
            min_df=2,                 # word must appear in at least 2 emails
            max_df=0.95,              # drop words that appear in 95%+ of emails
            sublinear_tf=True,        # log-scale term frequencies
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",  # handles any class imbalance
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])


def evaluate(pipeline: Pipeline, X_test, y_test) -> None:
    """Print standard classification metrics."""
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)[:, 1]

    print("\n=== Classification Report ===")
    print(classification_report(y_test, preds, target_names=["Safe", "Phishing"]))

    print("=== Confusion Matrix ===")
    print("                Predicted")
    print("              Safe   Phish")
    cm = confusion_matrix(y_test, preds)
    print(f"Actual Safe   {cm[0][0]:>5}  {cm[0][1]:>5}")
    print(f"Actual Phish  {cm[1][0]:>5}  {cm[1][1]:>5}")

    print(f"\nROC-AUC: {roc_auc_score(y_test, probs):.4f}")


def show_top_features(pipeline: Pipeline, n: int = 15) -> None:
    """Print the words most strongly associated with each class."""
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]
    feature_names = vectorizer.get_feature_names_out()
    coefs = classifier.coef_[0]

    top_phish = sorted(zip(coefs, feature_names), reverse=True)[:n]
    top_safe = sorted(zip(coefs, feature_names))[:n]

    print(f"\n=== Top {n} Phishing Indicators ===")
    for coef, word in top_phish:
        print(f"  {coef:+.3f}  {word}")

    print(f"\n=== Top {n} Safe-Email Indicators ===")
    for coef, word in top_safe:
        print(f"  {coef:+.3f}  {word}")


def main() -> None:
    df = load_data(DATA_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        df["Email Text"],
        df["label"],
        test_size=0.2,
        stratify=df["label"],
        random_state=RANDOM_STATE,
    )

    print(f"\nTraining set: {len(X_train)} emails")
    print(f"Test set:     {len(X_test)} emails")

    pipeline = build_pipeline()

    print("\nTraining model...")
    pipeline.fit(X_train, y_train)
    print("Done.")

    evaluate(pipeline, X_test, y_test)
    show_top_features(pipeline)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_OUT)
    print(f"\nModel saved to {MODEL_OUT}")


if __name__ == "__main__":
    main()