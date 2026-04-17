"""
Phishing email classifier - v2
Fixes v1 dataset bias by:
  1. Preprocessing text to strip dataset-specific tokens
  2. Combining cleaned TF-IDF with hand-crafted structural features
  3. Using an extended stopword list
"""
import sys
from pathlib import Path

# Make 'phishlab' importable when running this script directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

from phishlab.preprocess import (
    clean_texts,
    structural_features_transformer,
    EXTRA_STOPWORDS,
    STRUCTURAL_FEATURE_NAMES,
)

# Resolve paths relative to this file, so the script works from any cwd
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "data" / "Phishing_Email.csv"
MODEL_OUT = PROJECT_ROOT / "model" / "artifacts" / "model_v2.pkl"
RANDOM_STATE = 42


def load_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "Unnamed: 0" in df.columns:
        df = df.drop(columns=["Unnamed: 0"])
    df = df.dropna(subset=["Email Text"])
    df["Email Text"] = df["Email Text"].astype(str)
    df["label"] = (df["Email Type"] == "Phishing Email").astype(int)

    print(f"Loaded {len(df)} emails")
    print(f"  Phishing: {df['label'].sum()} ({df['label'].mean():.1%})")
    print(f"  Safe:     {(df['label']==0).sum()} ({(df['label']==0).mean():.1%})")
    return df


def build_pipeline() -> Pipeline:
    stopwords = list(ENGLISH_STOP_WORDS) + EXTRA_STOPWORDS

    text_branch = Pipeline([
        ("cleaner", FunctionTransformer(clean_texts)),
        ("tfidf", TfidfVectorizer(
            max_features=10_000,
            ngram_range=(1, 2),
            stop_words=stopwords,
            min_df=3,
            max_df=0.90,
            sublinear_tf=True,
        )),
    ])

    structural_branch = Pipeline([
        ("features", FunctionTransformer(structural_features_transformer)),
        ("scaler", StandardScaler()),
    ])

    return Pipeline([
        ("features", FeatureUnion([
            ("text", text_branch),
            ("structural", structural_branch),
        ])),
        ("clf", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        )),
    ])


def evaluate(pipeline, X_test, y_test):
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


def show_top_features(pipeline, n=20):
    feature_union = pipeline.named_steps["features"]
    tfidf = feature_union.transformer_list[0][1].named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]

    text_names = list(tfidf.get_feature_names_out())
    all_names = text_names + STRUCTURAL_FEATURE_NAMES
    coefs = classifier.coef_[0]

    df = pd.DataFrame({"feature": all_names, "coef": coefs}).sort_values("coef")

    print(f"\n=== Top {n} Phishing Indicators (v2) ===")
    for _, row in df.tail(n).iloc[::-1].iterrows():
        print(f"  {row['coef']:+.3f}  {row['feature']}")

    print(f"\n=== Top {n} Safe Indicators (v2) ===")
    for _, row in df.head(n).iterrows():
        print(f"  {row['coef']:+.3f}  {row['feature']}")

    print("\n=== Structural Feature Coefficients ===")
    structural = df[df["feature"].isin(STRUCTURAL_FEATURE_NAMES)]
    for _, row in structural.sort_values("coef", key=abs, ascending=False).iterrows():
        print(f"  {row['coef']:+.3f}  {row['feature']}")


def main():
    df = load_data(DATA_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        df["Email Text"].tolist(),
        df["label"].tolist(),
        test_size=0.2,
        stratify=df["label"],
        random_state=RANDOM_STATE,
    )

    print(f"\nTraining set: {len(X_train)} emails")
    print(f"Test set:     {len(X_test)} emails")

    pipeline = build_pipeline()

    print("\nTraining v2 model (this takes ~1-2 min)...")
    pipeline.fit(X_train, y_train)
    print("Done.")

    evaluate(pipeline, X_test, y_test)
    show_top_features(pipeline)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_OUT)
    print(f"\nModel saved to {MODEL_OUT}")


if __name__ == "__main__":
    main()