"""
Flask dashboard for the phishing triage queue.

Reads from the SQLite database populated by poller.py and renders a
web UI showing triaged emails, verdicts, confidence scores, extracted IOCs,
and analyst review decisions.

Run: python -m phishlab.dashboard
Then open: http://127.0.0.1:5000
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
from itertools import groupby
from flask import Flask, render_template, abort, request, redirect, url_for

from phishlab import config
from phishlab.db import (
    get_iocs_for_email,
    get_review,
    save_review,
    delete_review,
)

app = Flask(__name__)


# Human-friendly labels for IOC types in the dashboard
IOC_TYPE_LABELS = {
    "sender": "Sender",
    "sender_domain": "Sender Domain",
    "url": "URLs",
    "url_domain": "URL Domains",
    "ip": "IP Addresses",
    "attachment_name": "Attachment Names",
    "attachment_hash": "Attachment Hashes (SHA-256)",
}

# Valid analyst decisions - the DB has a CHECK constraint, but we validate
# here too so the user gets a clean 400 instead of a DB integrity error
VALID_DECISIONS = {"confirmed_phishing", "false_positive"}


def get_connection():
    """Open a new SQLite connection with dict-like row access."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    """Triage queue - list all emails with their verdicts and review status."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
        model_phish = conn.execute(
            "SELECT COUNT(*) FROM verdicts WHERE verdict = 'phishing'"
        ).fetchone()[0]
        model_safe = conn.execute(
            "SELECT COUNT(*) FROM verdicts WHERE verdict = 'safe'"
        ).fetchone()[0]
        total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        confirmed_phish = conn.execute(
            "SELECT COUNT(*) FROM analyst_reviews WHERE decision = 'confirmed_phishing'"
        ).fetchone()[0]
        false_positives = conn.execute(
            "SELECT COUNT(*) FROM analyst_reviews WHERE decision = 'false_positive'"
        ).fetchone()[0]
        # A disagreement: model said one thing, analyst said the opposite
        disagreements = conn.execute("""
            SELECT COUNT(*) FROM verdicts v
            JOIN analyst_reviews a ON v.email_uid = a.email_uid
            WHERE (v.verdict = 'phishing' AND a.decision = 'false_positive')
               OR (v.verdict = 'safe'     AND a.decision = 'confirmed_phishing')
        """).fetchone()[0]

        rows = conn.execute("""
            SELECT
                e.uid,
                e.sender,
                e.subject,
                e.fetched_at,
                v.verdict,
                v.confidence,
                (SELECT COUNT(*) FROM iocs WHERE email_uid = e.uid) AS ioc_count,
                (SELECT decision FROM analyst_reviews WHERE email_uid = e.uid) AS review
            FROM emails e
            LEFT JOIN verdicts v ON e.uid = v.email_uid
            ORDER BY e.fetched_at DESC
        """).fetchall()

    return render_template(
        "index.html",
        rows=rows,
        total=total,
        model_phish=model_phish,
        model_safe=model_safe,
        total_iocs=total_iocs,
        confirmed_phish=confirmed_phish,
        false_positives=false_positives,
        disagreements=disagreements,
    )


@app.route("/email/<uid>")
def email_detail(uid):
    """Detail view for a single triaged email - shows metadata, body, IOCs, review."""
    with get_connection() as conn:
        row = conn.execute("""
            SELECT
                e.uid,
                e.sender,
                e.subject,
                e.date,
                e.body,
                e.fetched_at,
                v.verdict,
                v.confidence
            FROM emails e
            LEFT JOIN verdicts v ON e.uid = v.email_uid
            WHERE e.uid = ?
        """, (uid,)).fetchone()

        if row is None:
            abort(404)

        ioc_rows = get_iocs_for_email(conn, uid)
        review = get_review(conn, uid)

    # Group IOCs by type for display
    ioc_groups = []
    for ioc_type, items_iter in groupby(ioc_rows, key=lambda r: r["ioc_type"]):
        entries = list(items_iter)
        ioc_groups.append({
            "type": ioc_type,
            "label": IOC_TYPE_LABELS.get(ioc_type, ioc_type.replace("_", " ").title()),
            "entries": entries,
            "count": len(entries),
        })

    total_iocs = sum(g["count"] for g in ioc_groups)

    return render_template(
        "email_detail.html",
        email=row,
        ioc_groups=ioc_groups,
        total_iocs=total_iocs,
        review=review,
    )


@app.route("/email/<uid>/review", methods=["POST"])
def submit_review(uid):
    """Record an analyst's decision for an email."""
    decision = request.form.get("decision", "").strip()

    if decision == "reset":
        with get_connection() as conn:
            delete_review(conn, uid)
            conn.commit()
        return redirect(url_for("email_detail", uid=uid))

    if decision not in VALID_DECISIONS:
        abort(400, description=f"Invalid decision: {decision}")

    with get_connection() as conn:
        # Verify the email exists before saving a review
        existing = conn.execute(
            "SELECT 1 FROM emails WHERE uid = ?", (uid,)
        ).fetchone()
        if not existing:
            abort(404)

        save_review(conn, uid, decision)
        conn.commit()

    return redirect(url_for("email_detail", uid=uid))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)