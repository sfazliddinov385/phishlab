"""Quick script to inspect the phishlab database."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "phishlab.db"

with sqlite3.connect(DB_PATH) as conn:
    conn.row_factory = sqlite3.Row

    # Summary stats
    total = conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
    phish = conn.execute("SELECT COUNT(*) FROM verdicts WHERE verdict = 'phishing'").fetchone()[0]
    safe = conn.execute("SELECT COUNT(*) FROM verdicts WHERE verdict = 'safe'").fetchone()[0]

    print(f"Total emails triaged: {total}")
    print(f"  Phishing: {phish}")
    print(f"  Safe:     {safe}")
    print()

    # Full triage log, most recent first
    query = """
    SELECT
        e.fetched_at,
        v.verdict,
        v.confidence,
        e.sender,
        e.subject
    FROM emails e
    JOIN verdicts v ON e.uid = v.email_uid
    ORDER BY e.fetched_at DESC
    """

    print(f"{'TIME':<20} {'VERDICT':<10} {'CONF':>6}  {'SENDER':<35} {'SUBJECT'}")
    print("-" * 120)
    for row in conn.execute(query):
        time = row["fetched_at"]
        verdict = row["verdict"].upper()
        conf = f"{row['confidence']:.3f}"
        sender = (row["sender"] or "")[:33]
        subject = (row["subject"] or "")[:50]
        print(f"{time:<20} {verdict:<10} {conf:>6}  {sender:<35} {subject}")