"""
database.py — Industry-Grade QR Attendance System
Features:
- Device fingerprinting (anti-sharing)
- IP-based network validation
- ML risk scoring schema
- Anomaly logging
- Full audit trail
- Dynamic subject management
- Advanced analytics
"""
import sqlite3, hashlib, os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'attendance.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

SUBJECTS = {
    'SP': 'System Programming',
    'DS': 'Data Structures',
    'DM': 'Discrete Mathematics',
}

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_conn(); c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS teacher_config (
        id INTEGER PRIMARY KEY CHECK(id=1),
        name TEXT NOT NULL, pin_hash TEXT NOT NULL,
        setup_at TEXT NOT NULL)""")

    c.execute("""CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_no TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        risk_score REAL DEFAULT 0.0)""")

    # Add email column if it doesn't exist (migration for existing DBs)
    try:
        c.execute("ALTER TABLE students ADD COLUMN email TEXT DEFAULT ''")
    except Exception:
        pass

    c.execute("""CREATE TABLE IF NOT EXISTS subjects (
        code TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')))""")

    c.execute("""CREATE TABLE IF NOT EXISTS qr_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        subject TEXT NOT NULL,
        label TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        expires_at TEXT,
        created_by TEXT NOT NULL,
        class_start TEXT,
        class_end TEXT,
        allowed_ip_prefix TEXT DEFAULT '',
        max_scans INTEGER DEFAULT 999,
        notes TEXT DEFAULT '',
        is_active INTEGER DEFAULT 1)""")

    # Add notes column if it doesn't exist
    try:
        c.execute("ALTER TABLE qr_sessions ADD COLUMN notes TEXT DEFAULT ''")
    except Exception:
        pass

    c.execute("""CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        session_id INTEGER NOT NULL,
        marked_at TEXT NOT NULL,
        ip_address TEXT DEFAULT '',
        device_hash TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        risk_score REAL DEFAULT 0.0,
        flagged INTEGER DEFAULT 0,
        flag_reason TEXT DEFAULT '',
        UNIQUE(student_id, session_id),
        FOREIGN KEY(student_id) REFERENCES students(id),
        FOREIGN KEY(session_id) REFERENCES qr_sessions(id))""")

    c.execute("""CREATE TABLE IF NOT EXISTS scan_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        device_hash TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        roll_no TEXT DEFAULT '',
        scanned_at TEXT NOT NULL,
        was_blocked INTEGER DEFAULT 0,
        block_reason TEXT DEFAULT '')""")

    c.execute("""CREATE TABLE IF NOT EXISTS total_classes (
        subject TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0)""")

    c.execute("""CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detected_at TEXT NOT NULL,
        anomaly_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        student_id INTEGER,
        session_id INTEGER,
        resolved INTEGER DEFAULT 0)""")

    # Seed default subjects
    for code, name in SUBJECTS.items():
        c.execute("INSERT OR IGNORE INTO subjects (code, name) VALUES (?,?)", (code, name))
        c.execute("INSERT OR IGNORE INTO total_classes VALUES (?,0)", (code,))

    conn.commit(); conn.close()


# ── Subject Management ────────────────────────────────────────────────────────
def get_all_subjects():
    """Returns dict of {code: name} — from DB, falling back to hardcoded."""
    conn = get_conn()
    rows = conn.execute("SELECT code, name FROM subjects ORDER BY code").fetchall()
    conn.close()
    if rows:
        return {r['code']: r['name'] for r in rows}
    return dict(SUBJECTS)

def add_subject(code, name):
    code = code.strip().upper()
    conn = get_conn()
    try:
        conn.execute("INSERT INTO subjects (code, name) VALUES (?,?)", (code, name))
        conn.execute("INSERT OR IGNORE INTO total_classes VALUES (?,0)", (code,))
        conn.commit()
        conn.close()
        return True, 'Subject added.'
    except sqlite3.IntegrityError:
        conn.close()
        return False, 'Subject code already exists.'

def delete_subject(code):
    conn = get_conn()
    has_att = conn.execute(
        "SELECT COUNT(*) as cnt FROM attendance WHERE subject=?", (code,)).fetchone()['cnt']
    if has_att > 0:
        conn.close()
        return False, f'Cannot delete: {has_att} attendance records exist for this subject.'
    conn.execute("DELETE FROM subjects WHERE code=?", (code,))
    conn.execute("DELETE FROM total_classes WHERE subject=?", (code,))
    conn.commit(); conn.close()
    return True, 'Subject deleted.'


# ── Device Fingerprinting ─────────────────────────────────────────────────────
def make_device_hash(ip, user_agent, accept_lang=''):
    raw = f"{ip}|{user_agent}|{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def device_already_scanned(session_id, device_hash, conn):
    row = conn.execute(
        "SELECT id FROM scan_log WHERE session_id=? AND device_hash=? AND was_blocked=0",
        (session_id, device_hash)).fetchone()
    return row is not None

def log_scan(session_id, device_hash, ip, roll_no, blocked, reason=''):
    conn = get_conn()
    conn.execute("""INSERT INTO scan_log
        (session_id, device_hash, ip_address, roll_no, scanned_at, was_blocked, block_reason)
        VALUES (?,?,?,?,?,?,?)""",
        (session_id, device_hash, ip, roll_no,
         datetime.now().isoformat(), 1 if blocked else 0, reason))
    conn.commit(); conn.close()


# ── Teacher ───────────────────────────────────────────────────────────────────
def teacher_exists():
    conn = get_conn()
    row = conn.execute("SELECT id FROM teacher_config WHERE id=1").fetchone()
    conn.close()
    return row is not None

def setup_teacher(name, pin):
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO teacher_config VALUES (1,?,?,?)",
                 (name, pin_hash, datetime.now().isoformat()))
    conn.commit(); conn.close()

def verify_teacher_pin(pin):
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    conn = get_conn()
    row = conn.execute(
        "SELECT name FROM teacher_config WHERE id=1 AND pin_hash=?",
        (pin_hash,)).fetchone()
    conn.close()
    return row['name'] if row else None

def get_teacher():
    conn = get_conn()
    row = conn.execute("SELECT * FROM teacher_config WHERE id=1").fetchone()
    conn.close()
    return dict(row) if row else None


# ── Students ──────────────────────────────────────────────────────────────────
def get_or_create_student(roll_no, name='', phone='', email=''):
    roll_no = roll_no.strip().upper()
    conn = get_conn()
    row = conn.execute("SELECT * FROM students WHERE roll_no=?", (roll_no,)).fetchone()
    if row:
        conn.close()
        return dict(row), False
    conn.execute("INSERT INTO students (roll_no, name, phone, email) VALUES (?,?,?,?)",
                 (roll_no, name or roll_no, phone, email))
    conn.commit()
    row = conn.execute("SELECT * FROM students WHERE roll_no=?", (roll_no,)).fetchone()
    conn.close()
    return dict(row), True

def get_student_by_roll(roll_no):
    conn = get_conn()
    row = conn.execute("SELECT * FROM students WHERE roll_no=?",
                       (roll_no.strip().upper(),)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_student_by_id(student_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def update_student_name(roll_no, name):
    conn = get_conn()
    conn.execute("UPDATE students SET name=? WHERE roll_no=?",
                 (name.strip(), roll_no.upper()))
    conn.commit(); conn.close()

def delete_student(student_id):
    conn = get_conn()
    conn.execute("DELETE FROM attendance WHERE student_id=?", (student_id,))
    conn.execute("DELETE FROM scan_log WHERE roll_no=(SELECT roll_no FROM students WHERE id=?)", (student_id,))
    conn.execute("DELETE FROM students WHERE id=?", (student_id,))
    conn.commit()
    conn.close()

def bulk_delete_students(student_ids):
    conn = get_conn()
    for sid in student_ids:
        conn.execute("DELETE FROM attendance WHERE student_id=?", (sid,))
        conn.execute("DELETE FROM scan_log WHERE roll_no=(SELECT roll_no FROM students WHERE id=?)", (sid,))
        conn.execute("DELETE FROM students WHERE id=?", (sid,))
    conn.commit(); conn.close()


# ── QR Sessions ───────────────────────────────────────────────────────────────
def create_qr_session(token, subject, label, expires_at, teacher_name,
                      allowed_ip_prefix='', class_start=None, class_end=None,
                      max_scans=999, notes=''):
    conn = get_conn()
    conn.execute("""INSERT INTO qr_sessions
        (token, subject, label, created_at, expires_at, created_by,
         allowed_ip_prefix, class_start, class_end, max_scans, notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (token, subject, label, datetime.now().isoformat(),
         expires_at, teacher_name, allowed_ip_prefix,
         class_start, class_end, max_scans, notes))
    conn.execute("INSERT OR IGNORE INTO total_classes VALUES (?,0)", (subject,))
    conn.execute("UPDATE total_classes SET count=count+1 WHERE subject=?", (subject,))
    conn.commit()
    sid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return sid

def get_session_by_token(token):
    conn = get_conn()
    row = conn.execute("SELECT * FROM qr_sessions WHERE token=?", (token,)).fetchone()
    conn.close()
    return dict(row) if row else None

def is_session_active(session_row):
    if not session_row.get('is_active', 1):
        return False
    if session_row['expires_at'] is None:
        return True
    return datetime.now().isoformat() <= session_row['expires_at']

def get_all_sessions():
    conn = get_conn()
    rows = conn.execute("""
        SELECT qs.*, COUNT(a.id) as att_count,
               COUNT(CASE WHEN a.flagged=1 THEN 1 END) as flag_count
        FROM qr_sessions qs
        LEFT JOIN attendance a ON a.session_id=qs.id
        GROUP BY qs.id ORDER BY qs.created_at DESC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def deactivate_session(session_id):
    conn = get_conn()
    conn.execute("UPDATE qr_sessions SET is_active=0 WHERE id=?", (session_id,))
    conn.commit(); conn.close()

def delete_session(session_id):
    conn = get_conn()
    row = conn.execute("SELECT subject FROM qr_sessions WHERE id=?", (session_id,)).fetchone()
    if row:
        conn.execute("UPDATE total_classes SET count=MAX(0,count-1) WHERE subject=?",
                     (row['subject'],))
    conn.execute("DELETE FROM attendance WHERE session_id=?", (session_id,))
    conn.execute("DELETE FROM scan_log WHERE session_id=?", (session_id,))
    conn.execute("DELETE FROM qr_sessions WHERE id=?", (session_id,))
    conn.commit(); conn.close()


# ── Attendance ────────────────────────────────────────────────────────────────
def mark_attendance(student_id, session_id, subject,
                    ip='', device_hash='', user_agent='', risk_score=0.0, flag_reason=''):
    conn = get_conn()
    flagged = 1 if risk_score > 0.5 else 0
    try:
        conn.execute("""INSERT INTO attendance
            (student_id, subject, session_id, marked_at,
             ip_address, device_hash, user_agent, risk_score, flagged, flag_reason)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (student_id, subject, session_id, datetime.now().isoformat(),
             ip, device_hash, user_agent, risk_score, flagged, flag_reason))
        conn.commit(); conn.close()
        return True, "Attendance marked successfully!"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Already marked for this session."

def remove_attendance(student_id, session_id):
    conn = get_conn()
    conn.execute("DELETE FROM attendance WHERE student_id=? AND session_id=?",
                 (student_id, session_id))
    conn.commit(); conn.close()

def add_manual_attendance(roll_no, session_id):
    """Manually add attendance for a student to a session."""
    conn = get_conn()
    sess = conn.execute("SELECT * FROM qr_sessions WHERE id=?", (session_id,)).fetchone()
    if not sess:
        conn.close()
        return False, "Session not found."
    student = conn.execute("SELECT * FROM students WHERE roll_no=?",
                           (roll_no.strip().upper(),)).fetchone()
    if not student:
        conn.close()
        return False, "Student not found. Add them first."
    subject = sess['subject']
    try:
        conn.execute("""INSERT INTO attendance
            (student_id, subject, session_id, marked_at, ip_address, device_hash)
            VALUES (?,?,?,?,?,?)""",
            (student['id'], subject, session_id,
             datetime.now().isoformat(), 'manual', 'manual'))
        conn.commit(); conn.close()
        return True, f"Attendance added for {student['name']}."
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Student already marked in this session."

def get_student_stats(student_id):
    conn = get_conn()
    subjects = get_all_subjects()
    totals = {r['subject']: r['count'] for r in
              conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    attended = {r['subject']: r['cnt'] for r in
                conn.execute("""SELECT subject, COUNT(*) as cnt FROM attendance
                    WHERE student_id=? GROUP BY subject""", (student_id,)).fetchall()}
    log = conn.execute("""
        SELECT a.subject, a.marked_at, qs.label, a.flagged, a.flag_reason
        FROM attendance a JOIN qr_sessions qs ON qs.id=a.session_id
        WHERE a.student_id=? ORDER BY a.marked_at DESC""", (student_id,)).fetchall()
    conn.close()
    records = []
    for code, name in subjects.items():
        att = attended.get(code, 0)
        tot = totals.get(code, 0)
        pct = round(att/tot*100, 1) if tot else 0.0
        status = 'safe' if pct >= 75 else ('warning' if pct >= 50 else 'danger')
        records.append({'code': code, 'name': name, 'attended': att,
                        'total': tot, 'percentage': pct, 'status': status})
    return records, [dict(r) for r in log]

def get_session_attendees(session_id):
    conn = get_conn()
    rows = conn.execute("""
        SELECT s.id as student_id, s.roll_no, s.name, a.marked_at,
               a.ip_address, a.risk_score, a.flagged, a.flag_reason
        FROM attendance a JOIN students s ON s.id=a.student_id
        WHERE a.session_id=? ORDER BY a.marked_at""", (session_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_students_report():
    conn = get_conn()
    subjects = get_all_subjects()
    students = conn.execute("SELECT * FROM students ORDER BY roll_no").fetchall()
    totals   = {r['subject']: r['count'] for r in
                conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    result = []
    for s in students:
        s = dict(s)
        attended = {r['subject']: r['cnt'] for r in
                    conn.execute("""SELECT subject, COUNT(*) as cnt FROM attendance
                        WHERE student_id=? GROUP BY subject""", (s['id'],)).fetchall()}
        summary = []
        for code, name in subjects.items():
            att = attended.get(code, 0)
            tot = totals.get(code, 0)
            pct = round(att/tot*100,1) if tot else 0.0
            summary.append({'code': code, 'name': name, 'att': att, 'tot': tot, 'pct': pct,
                             'status': 'safe' if pct>=75 else ('warn' if pct>=50 else 'danger')})
        result.append({'student': s, 'summary': summary})
    conn.close()
    return result

def get_selected_students_report(student_ids):
    conn = get_conn()
    subjects = get_all_subjects()
    placeholders = ','.join('?' * len(student_ids))
    students = conn.execute(
        f"SELECT * FROM students WHERE id IN ({placeholders}) ORDER BY roll_no",
        student_ids).fetchall()
    totals = {r['subject']: r['count'] for r in
              conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    result = []
    for s in students:
        s = dict(s)
        attended = {r['subject']: r['cnt'] for r in
                    conn.execute("""SELECT subject, COUNT(*) as cnt FROM attendance
                        WHERE student_id=? GROUP BY subject""", (s['id'],)).fetchall()}
        summary = []
        for code, name in subjects.items():
            att = attended.get(code, 0)
            tot = totals.get(code, 0)
            pct = round(att/tot*100,1) if tot else 0.0
            summary.append({'code': code, 'name': name, 'att': att, 'tot': tot, 'pct': pct})
        result.append({'student': s, 'summary': summary})
    conn.close()
    return result


# ── Anomalies ─────────────────────────────────────────────────────────────────
def log_anomaly(anomaly_type, severity, description, student_id=None, session_id=None):
    conn = get_conn()
    conn.execute("""INSERT INTO anomalies
        (detected_at, anomaly_type, severity, description, student_id, session_id)
        VALUES (?,?,?,?,?,?)""",
        (datetime.now().isoformat(), anomaly_type, severity,
         description, student_id, session_id))
    conn.commit(); conn.close()

def get_anomalies(limit=50):
    conn = get_conn()
    rows = conn.execute("""
        SELECT an.*, s.name as student_name, s.roll_no
        FROM anomalies an
        LEFT JOIN students s ON s.id=an.student_id
        ORDER BY an.detected_at DESC LIMIT ?""", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_flagged_attendance():
    conn = get_conn()
    rows = conn.execute("""
        SELECT a.*, s.name, s.roll_no, qs.label, qs.subject
        FROM attendance a
        JOIN students s ON s.id=a.student_id
        JOIN qr_sessions qs ON qs.id=a.session_id
        WHERE a.flagged=1 ORDER BY a.marked_at DESC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Advanced Analytics ────────────────────────────────────────────────────────
def get_advanced_analytics():
    from datetime import timedelta
    conn = get_conn()
    subjects = get_all_subjects()
    today = datetime.now()

    # Per-subject attendance trend last 30 days
    trend = {}
    for code in subjects:
        daily = {}
        for i in range(29, -1, -1):
            d = (today - timedelta(days=i)).strftime('%Y-%m-%d')
            cnt = conn.execute("""
                SELECT COUNT(*) as cnt FROM attendance
                WHERE subject=? AND marked_at LIKE ?
            """, (code, f'{d}%')).fetchone()['cnt']
            daily[d] = cnt
        trend[code] = daily

    # Top 5 most absent students
    totals = {r['subject']: r['count'] for r in
              conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    total_classes = sum(totals.values()) or 1
    students = conn.execute("SELECT * FROM students ORDER BY roll_no").fetchall()
    absent_list = []
    for s in students:
        s = dict(s)
        att = conn.execute(
            "SELECT COUNT(*) as cnt FROM attendance WHERE student_id=?",
            (s['id'],)).fetchone()['cnt']
        pct = round(att / total_classes * 100, 1) if total_classes else 0
        absent_list.append({**s, 'attended': att, 'pct': pct})
    absent_list.sort(key=lambda x: x['pct'])
    top_absent = absent_list[:5]

    # Attendance by day of week
    dow_counts = {}
    for i in range(7):
        dow_counts[i] = 0
    rows = conn.execute("SELECT marked_at FROM attendance").fetchall()
    for r in rows:
        try:
            d = datetime.fromisoformat(r['marked_at'])
            dow_counts[d.weekday()] = dow_counts.get(d.weekday(), 0) + 1
        except Exception:
            pass

    # Summary stats
    total_students = conn.execute("SELECT COUNT(*) as cnt FROM students").fetchone()['cnt']
    total_sessions = conn.execute("SELECT COUNT(*) as cnt FROM qr_sessions").fetchone()['cnt']
    total_att      = conn.execute("SELECT COUNT(*) as cnt FROM attendance").fetchone()['cnt']
    total_anomalies= conn.execute("SELECT COUNT(*) as cnt FROM anomalies").fetchone()['cnt']
    avg_session    = round(total_att / total_sessions, 1) if total_sessions else 0

    conn.close()
    return {
        'trend': trend,
        'subjects': subjects,
        'top_absent': top_absent,
        'dow_counts': dow_counts,
        'total_students': total_students,
        'total_sessions': total_sessions,
        'total_att': total_att,
        'total_anomalies': total_anomalies,
        'avg_session': avg_session,
    }
