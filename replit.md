# QR Attendance System

A smart classroom QR-code-based attendance system with AI/ML anomaly detection, detention risk prediction, and a teacher dashboard.

## Run & Operate

- **Run**: `python app.py`
- **Required env vars**: None (core features work without secrets)
- **Optional secrets**: `XAI_API_KEY` (Grok AI reports), `GMAIL_USER` + `GMAIL_APP_PASS` (email reports), `SECRET_KEY` (session security)

## Stack

- Python 3.12
- Flask 3.x (web framework)
- SQLite (via `database.py`, stored in `data/attendance.db`)
- Pillow + qrcode (QR image generation)
- Gunicorn (production server)
- Grok (xAI) via OpenAI-compatible API (optional AI analysis)
- Gmail SMTP (optional email delivery via app password)
- APScheduler (weekly automated email job)

## Where things live

- `app.py` — all Flask routes
- `database.py` — all DB access functions and `SUBJECTS` dict
- `ml_engine.py` — risk scoring, detention prediction, heatmap
- `qr_generator.py` — QR image encoding
- `templates/` — Jinja2 HTML templates
- `static/qrcodes/` — generated QR PNGs (auto-created)
- `data/attendance.db` — SQLite database (auto-created)

## Architecture decisions

- SQLite chosen for simplicity; no migration tool needed — `init_db()` handles schema on startup
- Device fingerprinting via IP + User-Agent + Accept-Language hash to prevent attendance sharing
- ML anomaly detection is local/pure-Python (no external ML service)
- Email delivery uses Gmail SMTP via Python's built-in `smtplib` with an app password
- Secret key falls back to a hardcoded default if `SECRET_KEY` env var not set

## Product

- Teachers generate QR codes per subject/session; students scan and submit name + roll number
- Anti-sharing: one device per session, one roll number per session
- AI flags suspicious scans; risk scores predict detention likelihood
- PDF reports with optional AI-written student analysis (requires XAI_API_KEY)
- Weekly email reports to students via Gmail SMTP (requires GMAIL_USER + GMAIL_APP_PASS)
- CSV export of attendance per subject or all subjects

## User preferences

- Uses Gmail SMTP with app password for email delivery
- Uses Grok (xAI) for AI features via OpenAI-compatible API (`grok-3` model)

## Gotchas

- App runs on `0.0.0.0:5000` so Replit preview works
- `init_db()` is called at import time in `app.py` — safe for both dev and gunicorn
- QR codes embed the public Replit dev domain so students can scan from their phones
- APScheduler must not double-start: guarded with `if not scheduler.running`
- Failed email sends print the full SMTP error to console and show it in the flash message

## Pointers

- Skills: `workflows`, `package-management`, `deployment`, `environment-secrets`
