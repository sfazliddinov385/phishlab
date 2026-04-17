"""
SQLite database for storing triaged emails.
Three tables:
  - emails: raw email metadata and body
  - verdicts: model's phishing/safe classification per email
  - iocs: indicators of compromise extracted from each email
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    uid           TEXT PRIMARY KEY,
    sender        TEXT,
    subject       TEXT,
    date          TEXT,
    body          TEXT,
    raw_size      INTEGER,
    fetched_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS verdicts (
    email_uid     TEXT PRIMARY KEY,
    verdict       TEXT NOT NULL,
    confidence    REAL NOT NULL,
    scored_at     TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (email_uid) REFERENCES emails(uid)
);

CREATE TABLE IF NOT EXISTS iocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email_uid     TEXT NOT NULL,
    ioc_type      TEXT NOT NULL,
    value         TEXT NOT NULL,
    context       TEXT,
    extracted_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(email_uid, ioc_type, value),
    FOREIGN KEY (email_uid) REFERENCES emails(uid)
);

CREATE TABLE IF NOT EXISTS analyst_reviews (
    email_uid     TEXT PRIMARY KEY,
    decision      TEXT NOT NULL CHECK (decision IN ('confirmed_phishing', 'false_positive')),
    reviewed_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (email_uid) REFERENCES emails(uid)
);

CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON verdicts(verdict);
CREATE INDEX IF NOT EXISTS idx_verdicts_confidence ON verdicts(confidence);
CREATE INDEX IF NOT EXISTS idx_iocs_email_uid ON iocs(email_uid);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_reviews_decision ON analyst_reviews(decision);
"""


def init_db(db_path: Path) -> None:
    """Create tables if they don't exist."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_conn(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Context-managed connection with row factory set for dict-like access."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def email_exists(conn: sqlite3.Connection, uid: str) -> bool:
    """Check if we've already triaged this UID."""
    cur = conn.execute("SELECT 1 FROM emails WHERE uid = ?", (uid,))
    return cur.fetchone() is not None


def save_email(
    conn: sqlite3.Connection,
    uid: str,
    sender: str,
    subject: str,
    date: str,
    body: str,
    raw_size: int,
) -> None:
    """Insert a triaged email."""
    conn.execute(
        """
        INSERT INTO emails (uid, sender, subject, date, body, raw_size)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (uid, sender, subject, date, body, raw_size),
    )


def save_verdict(
    conn: sqlite3.Connection,
    email_uid: str,
    verdict: str,
    confidence: float,
) -> None:
    """Insert the model's verdict for an email."""
    conn.execute(
        """
        INSERT INTO verdicts (email_uid, verdict, confidence)
        VALUES (?, ?, ?)
        """,
        (email_uid, verdict, confidence),
    )


def save_ioc(
    conn: sqlite3.Connection,
    email_uid: str,
    ioc_type: str,
    value: str,
    context: str = "",
) -> None:
    """Insert an IOC. UNIQUE constraint prevents duplicates silently."""
    conn.execute(
        """
        INSERT OR IGNORE INTO iocs (email_uid, ioc_type, value, context)
        VALUES (?, ?, ?, ?)
        """,
        (email_uid, ioc_type, value, context),
    )


def get_iocs_for_email(
    conn: sqlite3.Connection,
    email_uid: str,
) -> list[sqlite3.Row]:
    """Fetch all IOCs for a given email, ordered by type then value."""
    cur = conn.execute(
        """
        SELECT ioc_type, value, context, extracted_at
        FROM iocs
        WHERE email_uid = ?
        ORDER BY
            CASE ioc_type
                WHEN 'sender' THEN 1
                WHEN 'sender_domain' THEN 2
                WHEN 'url' THEN 3
                WHEN 'url_domain' THEN 4
                WHEN 'ip' THEN 5
                WHEN 'attachment_name' THEN 6
                WHEN 'attachment_hash' THEN 7
                ELSE 99
            END,
            value
        """,
        (email_uid,),
    )
    return cur.fetchall()


def save_review(
    conn: sqlite3.Connection,
    email_uid: str,
    decision: str,
) -> None:
    """Insert or replace an analyst's review for an email.
    Uses UPSERT so changing a decision overwrites the previous one.
    """
    conn.execute(
        """
        INSERT INTO analyst_reviews (email_uid, decision, reviewed_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(email_uid) DO UPDATE SET
            decision = excluded.decision,
            reviewed_at = excluded.reviewed_at
        """,
        (email_uid, decision),
    )


def delete_review(
    conn: sqlite3.Connection,
    email_uid: str,
) -> None:
    """Clear an analyst's review (reset button)."""
    conn.execute(
        "DELETE FROM analyst_reviews WHERE email_uid = ?",
        (email_uid,),
    )


def get_review(
    conn: sqlite3.Connection,
    email_uid: str,
) -> sqlite3.Row | None:
    """Fetch the current review for an email, or None if not yet reviewed."""
    cur = conn.execute(
        "SELECT decision, reviewed_at FROM analyst_reviews WHERE email_uid = ?",
        (email_uid,),
    )
    return cur.fetchone()