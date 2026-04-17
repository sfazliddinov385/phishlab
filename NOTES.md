# Phishlab Build Notes

## How to restart
1. Open VS Code -> File -> Open Folder -> C:\Users\sfazl\OneDrive\Desktop\CyberProject
2. Open terminal (Ctrl + `)
3. Run: .venv\Scripts\activate
4. Verify: python --version  (should show 3.12.10)

## Weekend 1 - April 16, 2026 - DONE
- Set up Python 3.12 venv, installed pandas/numpy/scikit-learn/joblib
- Trained TF-IDF + Logistic Regression on Kaggle phishing dataset (18,650 emails)
- Results: 97% accuracy, 0.9953 ROC-AUC, 98% phishing recall
- Model saved to model/artifacts/model_v1.pkl
- Smoke test passes on all 3 custom emails

## Known issues to address in v2
- Dataset bias: model learned Enron-specific tokens (enron, vince, louise) as "safe"
- n_jobs=-1 deprecation warning in LogisticRegression

## Weekend 2 plan
1. Fix dataset bias - strip named entities and dates, retrain, compare features
2. Start IMAP poller for abuse inbox triage



## Weekend 2 - April 17, 2026 - Dataset Bias Fix

**Problem:** v1 model scored 97% accuracy but diagnostic showed top features
were dataset-specific artifacts, not phishing signals:
- Top "safe" features: enron (-7.2), vince (-3.4), louise (-2.9), 2001/2002,
  713 (Houston area code), linguistics, edu
- Top "phishing" features: 2004, 2005, spamassassin sightings

Model had learned "Enron/academic corpus vs SpamAssassin 2004-5 corpus"
instead of "legitimate vs phishing".

**Fix:**
1. Text preprocessing to strip corpus-specific signal:
   - URLs -> <url>, emails -> <email>, years removed, numbers -> <num>
2. Extended stopword list (enron, vince, louise, spamassassin, sightings,
   713, linguistics, edu, etc.)
3. Added 8 hand-crafted structural features alongside TF-IDF:
   url_count, shortener_count, ip_url_count, exclamation_count,
   question_count, uppercase_ratio, urgency_hits, text_length

**Results:**
- v2 accuracy: 96% (-1 point vs v1)
- v2 ROC-AUC: 0.9941 (vs v1 0.9953)
- Top v2 phishing features are now real phishing vocabulary:
  click, free, money, remove, info, viagra, plus exclamation_count
- Top v2 safe features are generic work/email vocabulary:
  thanks, attached, meeting, questions, employees, plus text_length
- Named entities (enron, vince) no longer appear in top 20

**Generalization test (5 custom emails, v1 vs v2):**
- All 5 correct on both models
- v2 more confident on 4/5 (including the edge case: legitimate 2026
  meeting-confirm email that v1 nearly flagged at 0.485 probability,
  v2 correctly at 0.378)
- The trade: -1% raw accuracy for meaningfully better generalization
  to realistic emails outside the training distribution

**Interview talking point:**
"My initial model got 97% accuracy but I inspected feature importances
and realized it was overfitting to corpus-specific tokens like 'enron'
and '2002'. I added text preprocessing, structural features, and an
expanded stopword list. Accuracy dropped 1 point but the model now
generalizes to modern emails — the top features became actual phishing
signals like 'click', 'free', 'verify', and exclamation count."







## Weekend 2 Afternoon - April 17, 2026 - IMAP Poller

**Goal:** Build the abuse inbox triage pipeline.

**What got done:**
- Created throwaway Gmail (cyberproject2131@gmail.com) with 2FA + app password
- Set up .env with IMAP credentials (gitignored)
- Installed imap-tools + python-dotenv
- Built phishlab/config.py - reads .env, exposes settings
- Built phishlab/db.py - SQLite schema (emails + verdicts tables)
- Built phishlab/poller.py - IMAP poller that fetches unread emails,
  scores with v2 model, saves verdicts to SQLite, marks as seen
- Built view_db.py - CLI dashboard for triage history

**First real triage:**
- 4 Google security notifications correctly classified as safe (conf 0.33-0.50)
- 1 "Microsoft Security Alert" phishing email from hamzsus2007@gmail.com
  correctly flagged as phishing at 0.789 confidence
- End-to-end pipeline working: Gmail -> IMAP -> parse -> score -> SQLite

**Observations:**
- Google's own security emails score in the 0.33-0.50 range because they use
  the same structural language as phishing. In production this is where
  sender reputation (SPF/DKIM/DMARC) would downweight them. Future work.
- Idempotency via email_exists() check means restarts don't reprocess.
- Gmail web UI auto-marks emails as "seen" if you view the inbox, which
  is why testing requires either signing out or using a second browser.

**Next session (Sunday):**
- Flask web dashboard (replace view_db.py with browser UI)
- IOC extraction (sender domain, URLs, IP addresses, attachment hashes)
- Analyst override buttons (Confirm Phish / False Positive)
- Retraining loop using analyst overrides

## Commands to restart

1. Open VS Code -> Open Folder -> CyberProject
2. Open terminal (Ctrl+`)
3. Activate venv: .venv\Scripts\activate
4. Run poller: python -m phishlab.poller
5. View DB: python view_db.pys




## Weekend 2 Evening - April 17, 2026 - Flask Dashboard

**Goal:** Replace view_db.py with a browser-based analyst dashboard.

**What got done:**
- Installed Flask
- Built phishlab/dashboard.py with two routes (/ and /email/<uid>)
- Created phishlab/templates/ with base.html, index.html, email_detail.html
- Dashboard shows triage queue with stats (total, phishing, safe counts)
- Clickable subjects open detail view showing full email body, verdict,
  confidence, sender, date, fetched timestamp
- Color-coded badges (red PHISHING, green SAFE)
- Inline CSS - no framework, intentionally minimal

**Screenshot moment:**
- Dashboard correctly shows the phishing email from hamzsus2007@gmail.com
  at 0.7892 confidence with full metadata and rendered body content

**Next session (Weekend 3):**
- IOC extraction (sender domain, URLs, IP addresses, attachment hashes)
  stored in a new iocs table
- Display IOCs in email detail view
- Analyst override buttons (Confirm Phish / False Positive)
- Store overrides in a new feedback table
- Retraining script that uses overrides to improve v3 model
- README.md polish with architecture diagram and screenshots
- Push to GitHub