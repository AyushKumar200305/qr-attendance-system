# QR Attendance System

A smart classroom attendance system built with Python and Flask.

## How It Works

1. Teacher opens the app and generates a QR code for a subject
2. Teacher shows QR on projector/board
3. Students scan QR with phone camera
4. A form opens on their phone — enter Name and Roll No
5. Attendance is marked instantly

## Features

- QR code based attendance — no manual register
- Anti-sharing protection — each phone can only mark once per session
- AI/ML anomaly detection — flags suspicious scans automatically
- Detention risk prediction — warns students before it's too late
- Teacher dashboard with live insights
- Export attendance as CSV
- Security alerts page

## Tech Stack

- Python 3
- Flask (web framework)
- SQLite (database)
- HTML / CSS (frontend)

## Project Structure

```
qr_attendance/
├── app.py              # Main Flask app — all routes
├── database.py         # All database functions
├── ml_engine.py        # AI/ML analytics engine
├── qr_generator.py     # QR code generation
├── requirements.txt    # Python libraries needed
├── data/               # SQLite database (auto created)
├── static/
│   └── qrcodes/        # Generated QR images
└── templates/          # All HTML pages
    ├── base.html
    ├── home.html
    ├── attend_form.html
    ├── attend_result.html
    ├── attend_error.html
    ├── teacher_gate.html
    ├── teacher_dashboard.html
    ├── generate_qr.html
    ├── session_detail.html
    ├── student_stats.html
    ├── all_students.html
    ├── anomalies.html
    └── my_stats_lookup.html
```

## How to Run

**Step 1 — Install libraries**
```
pip install -r requirements.txt
```

**Step 2 — Run the app**
```
python app.py
```

**Step 3 — Open in browser**
```
http://127.0.0.1:5000
```

**Step 4 — Teacher setup**

Go to `http://127.0.0.1:5000/teacher` and set your name and PIN once.

## Important Note

Students and teacher must be on the **same WiFi network**.
The terminal will show a phone URL like `http://192.168.x.x:5000` — students use this on their phones.

## Built By

NIT Delhi — B.Tech CSE 2nd Semester Project(Team Swastik)