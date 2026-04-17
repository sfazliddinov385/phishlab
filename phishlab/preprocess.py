"""
Text preprocessing to strip dataset-specific tokens and normalize patterns.
This is what separates a model that learned *phishing* from a model that
learned *Enron-vs-SpamAssassin*.
"""
import re
import numpy as np


# Dataset-specific tokens we saw dominating the v1 model's top features.
# These are not phishing signals - they're corpus artifacts.
DATASET_STOPWORDS = {
    # Enron corpus proper nouns and artifacts
    "enron", "vince", "vinces", "louise", "kaminski",
    "skilling", "lay", "houston", "ect", "hou", "hpl",
    # Academic linguistics listserv
    "linguistics", "linguistic", "linguist", "linguists",
    "language", "languages", "english", "grammar",
    "university", "dept", "department", "professor",
    "conference", "paper", "research", "edu",
    # SpamAssassin corpus artifacts
    "spamassassin", "sightings", "sighting",
    "sa", "spamd", "razor",
    # Common email reply/forward artifacts
    "wrote", "subject", "sent", "cc", "bcc",
    "original", "forwarded", "reply", "replied",
    # Enron phone area codes
    "713", "281",
}

# Combine with sklearn's built-in English stopwords later
EXTRA_STOPWORDS = list(DATASET_STOPWORDS)


# Names of the hand-crafted structural features. Ordering here defines
# the column order of the numpy array produced by structural_features_transformer.
STRUCTURAL_FEATURE_NAMES = [
    "url_count", "shortener_count", "ip_url_count",
    "exclamation_count", "question_count", "uppercase_ratio",
    "urgency_hits", "text_length",
]


def preprocess_email_text(text: str) -> str:
    """Clean email text to remove dataset-specific noise.

    Goal: strip information that the model could memorize as shortcuts,
    leaving behind genuine phishing patterns.
    """
    if not isinstance(text, str):
        return ""

    # Lowercase for consistency
    text = text.lower()

    # Replace URLs with a generic token - we keep that URLs exist (useful
    # signal) without exposing specific domains the model could overfit to
    text = re.sub(r"https?://\S+", " <url> ", text)
    text = re.sub(r"www\.\S+", " <url> ", text)

    # Replace email addresses
    text = re.sub(r"\S+@\S+\.\S+", " <email> ", text)

    # Replace 4-digit years (1900-2099) entirely - dates are not phishing signals
    text = re.sub(r"\b(19|20)\d{2}\b", " ", text)

    # Replace phone numbers with a generic token
    text = re.sub(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", " <phone> ", text)

    # Replace standalone numbers with <num>
    text = re.sub(r"\b\d+\b", " <num> ", text)

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


def extract_structural_features(text: str) -> dict:
    """Hand-crafted features that capture phishing *structure*, not vocabulary.

    These are intentionally simple and robust - they work even on emails
    the model has never seen before, because they measure patterns not words.
    """
    if not isinstance(text, str):
        text = ""

    urls = re.findall(r"https?://\S+", text)
    url_shorteners = {"bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"}
    ip_url_pattern = re.compile(r"https?://\d+\.\d+\.\d+\.\d+")

    url_count = len(urls)
    shortener_count = sum(1 for u in urls if any(s in u.lower() for s in url_shorteners))
    ip_url_count = len(ip_url_pattern.findall(text))

    exclamation_count = text.count("!")
    question_count = text.count("?")

    letters = [c for c in text if c.isalpha()]
    uppercase_ratio = (
        sum(1 for c in letters if c.isupper()) / len(letters)
        if letters else 0
    )

    urgency_phrases = [
        "urgent", "verify", "suspended", "act now", "click here",
        "confirm your", "update your", "account locked", "expire",
        "limited time", "immediately", "final notice",
    ]
    lower_text = text.lower()
    urgency_hits = sum(1 for p in urgency_phrases if p in lower_text)

    return {
        "url_count": url_count,
        "shortener_count": shortener_count,
        "ip_url_count": ip_url_count,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "uppercase_ratio": uppercase_ratio,
        "urgency_hits": urgency_hits,
        "text_length": len(text),
    }


# --- Pipeline transformer functions ---
# These must live at module level (not nested or as lambdas) so that
# scikit-learn pipelines using them can be saved and loaded with joblib.
# When the saved model references these functions, it records the path
# `phishlab.preprocess.clean_texts` - stable across any script that imports
# from this module.

def clean_texts(texts):
    """Apply email preprocessing to a list of texts."""
    return [preprocess_email_text(t) for t in texts]


def structural_features_transformer(texts):
    """Convert a list of emails into a numpy array of structural features."""
    rows = [extract_structural_features(t) for t in texts]
    return np.array([[r[k] for k in STRUCTURAL_FEATURE_NAMES] for r in rows])