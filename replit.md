# QR Attendance System

A smart classroom QR-code-based attendance system with AI/ML anomaly detection, detention risk prediction, and a teacher dashboard.

## Run & Operate

- **Run**: `python app.py`
- **Required env vars**: None (uses SQLite, no external services)

## Stack

- Python 3.12
- Flask 3.x (web framework)
- SQLite (via `database.py`, stored in `data/attendance.db`)
- Pillow + qrcode (QR image generation)
- Gunicorn (production server)

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
- Secret key is hardcoded (acceptable for a classroom tool; change for production)

## Product

- Teachers generate QR codes per subject/session; students scan and submit name + roll number
- Anti-sharing: one device per session, one roll number per session
- AI flags suspicious scans; risk scores predict detention likelihood
- CSV export of attendance per subject or all subjects
- Student self-service stats at `/mystats`

## User preferences

_Populate as you build_

## Gotchas

- App runs on `0.0.0.0:5000` so Replit preview works
- `init_db()` is called at startup in `__main__` block only — not in gunicorn; wrap in `with app.app_context()` if switching to gunicorn entrypoint
- QR codes embed the local LAN IP — in Replit, use the public dev domain for student scanning

## Pointers

- Skills: `workflows`, `package-management`, `deployment`
