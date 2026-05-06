# QR Attendance System

A smart classroom QR-code-based attendance system with AI/ML anomaly detection, detention risk prediction, and a teacher dashboard.

## Run & Operate

- **Run**: `python app.py`
- **Required env vars**: None (core features work without secrets)
- **Optional secrets**: `ANTHROPIC_API_KEY` (AI reports), `MAILGUN_API_KEY` + `MAILGUN_DOMAIN` (email reports), `SECRET_KEY` (session security)

## Stack

- Python 3.12
- Flask 3.x (web framework)
- SQLite (via `database.py`, stored in `data/attendance.db`)
- Pillow + qrcode (QR image generation)
- Gunicorn (production server)
- Anthropic Claude (optional AI analysis)
- Mailgun (optional email delivery)
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
- Email delivery uses Mailgun HTTP API (no SMTP library needed)
- Secret key falls back to a hardcoded default if `SECRET_KEY` env var not set

## Product

- Teachers generate QR codes per subject/session; students scan and submit name + roll number
- Anti-sharing: one device per session, one roll number per session
- AI flags suspicious scans; risk scores predict detention likelihood
- PDF reports with optional AI-written student analysis (requires Anthropic key)
- Weekly email reports to students via Mailgun (requires MAILGUN_API_KEY + MAILGUN_DOMAIN)
- CSV export of attendance per subject or all subjects

## User preferences

- Uses Mailgun for email delivery
- Uses Anthropic Claude for AI features

## Gotchas

- App runs on `0.0.0.0:5000` so Replit preview works
- `init_db()` is called at import time in `app.py` — safe for both dev and gunicorn
- QR codes embed the public Replit dev domain so students can scan from their phones
- APScheduler must not double-start: guarded with `if not scheduler.running`
- Failed email sends now print the full Mailgun error to console for debugging

## Pointers

- Skills: `workflows`, `package-management`, `deployment`, `environment-secrets`
