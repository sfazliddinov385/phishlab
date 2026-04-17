"""
IMAP poller - the core triage loop.

Connects to the abuse inbox, fetches unread emails, scores each one with the
trained v2 model, extracts IOCs, and saves results to SQLite.

Run: python -m phishlab.poller
"""
import sys
from pathlib import Path

# Make 'phishlab' importable when run via `python -m phishlab.poller`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
from imap_tools import MailBox, AND

# These imports must happen before joblib.load() so the pickled pipeline
# can resolve its function references (clean_texts, structural_features_transformer)
from phishlab.preprocess import clean_texts, structural_features_transformer  # noqa: F401

from phishlab import config
from phishlab.db import (
    init_db,
    get_conn,
    email_exists,
    save_email,
    save_verdict,
    save_ioc,
)
from phishlab.ioc_extractor import extract_all_iocs


def score_email(model, subject: str, body: str) -> tuple[str, float]:
    """Run the v2 model on an email. Returns (verdict, confidence)."""
    # Combine subject and body - the model was trained on email text
    text = f"{subject}\n\n{body}"
    prob_phish = float(model.predict_proba([text])[0, 1])
    verdict = "phishing" if prob_phish >= 0.5 else "safe"
    return verdict, prob_phish


def triage_inbox() -> None:
    """Pull unread emails, score each one, save results."""
    print(f"Loading model from {config.MODEL_PATH}...")
    model = joblib.load(config.MODEL_PATH)
    print("Model loaded.")

    print(f"Ensuring database at {config.DB_PATH}...")
    init_db(config.DB_PATH)

    print(f"Connecting to {config.IMAP_HOST}:{config.IMAP_PORT} as {config.IMAP_USER}...")
    with MailBox(config.IMAP_HOST, port=config.IMAP_PORT).login(
        config.IMAP_USER, config.IMAP_PASSWORD, initial_folder=config.IMAP_FOLDER
    ) as mailbox:
        print("Connected.\n")

        # Fetch unread emails. mark_seen=False so we control flagging ourselves.
        unread = list(mailbox.fetch(AND(seen=False), mark_seen=False))

        if not unread:
            print("No unread emails found. Send a test email to the inbox and re-run.")
            return

        print(f"Found {len(unread)} unread email(s). Triaging...\n")

        with get_conn(config.DB_PATH) as conn:
            for msg in unread:
                uid = msg.uid
                sender = msg.from_ or "<unknown>"
                subject = msg.subject or "<no subject>"
                date = str(msg.date) if msg.date else ""
                body = msg.text or msg.html or ""
                raw_size = len(msg.obj.as_bytes()) if msg.obj else 0

                # Skip if we've already triaged this UID (idempotency)
                if email_exists(conn, uid):
                    print(f"  [skip] UID {uid} already triaged")
                    continue

                verdict, confidence = score_email(model, subject, body)

                save_email(conn, uid, sender, subject, date, body, raw_size)
                save_verdict(conn, uid, verdict, confidence)

                # Extract IOCs and save
                iocs = extract_all_iocs(
                    sender=msg.from_ or "",
                    subject=subject,
                    body=body,
                    attachments=msg.attachments or [],
                )
                for ioc in iocs:
                    save_ioc(conn, uid, ioc.ioc_type, ioc.value, ioc.context)

                # Flag as seen so we don't re-process
                mailbox.flag(uid, "\\Seen", True)

                marker = "[PHISH]" if verdict == "phishing" else "[SAFE] "
                print(f"  {marker} {confidence:.3f}  from {sender}")
                print(f"           subject: {subject[:70]}")
                print(f"           {len(iocs)} IOC(s) extracted")

        print(f"\nDone. Results saved to {config.DB_PATH}")


if __name__ == "__main__":
    try:
        triage_inbox()
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)