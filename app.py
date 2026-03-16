"""
app.py — Industry-Grade QR Attendance System
Security: device fingerprinting, IP tracking, risk scoring
AI/ML:    anomaly detection, detention prediction, smart insights
"""
import os, io, base64, socket, csv
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, make_response)
from database import (
    init_db, teacher_exists, setup_teacher, verify_teacher_pin, get_teacher,
    get_or_create_student, get_student_by_roll, update_student_name,
    create_qr_session, get_session_by_token, is_session_active,
    get_all_sessions, delete_session, deactivate_session,
    mark_attendance, get_student_stats,
    get_session_attendees, get_all_students_report,
    log_scan, make_device_hash, device_already_scanned, get_conn,
    log_anomaly, get_anomalies, get_flagged_attendance, SUBJECTS
)
from ml_engine import (
    calculate_risk_score, predict_detention_risk,
    get_class_insights, get_attendance_heatmap, get_all_students_risk
)
from qr_generator import encode_qr
import secrets

app = Flask(__name__)
app.secret_key = 'qr-attend-industry-2024-xk9mP'
QR_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'qrcodes')
os.makedirs(QR_FOLDER, exist_ok=True)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.1.1", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def now_str():
    return datetime.now().strftime('%A, %d %B %Y')

def get_client_ip():
    return (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            or request.remote_addr or '0.0.0.0')

def teacher_required(f):
    from functools import wraps
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get('teacher_ok'):
            return redirect(url_for('teacher_gate'))
        return f(*a, **kw)
    return wrap


# ── HOME ──────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html', subjects=SUBJECTS, today=now_str())


# ══════════════════════════════════════════════════════════════════════════════
#  STUDENT ATTEND FLOW
#  /attend/<token>  ←  URL encoded in QR code
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/attend/<token>', methods=['GET', 'POST'])
def attend(token):
    ip         = get_client_ip()
    ua         = request.headers.get('User-Agent', '')
    lang       = request.headers.get('Accept-Language', '')
    dev_hash   = make_device_hash(ip, ua, lang)

    sess_row = get_session_by_token(token)

    # ── Invalid token ─────────────────────────────────────────────────────────
    if not sess_row:
        return render_template('attend_error.html', today=now_str(),
            icon='❌', title='Invalid QR Code',
            msg='This QR code is not recognised. Ask your teacher to show the correct one.')

    # ── Expired ───────────────────────────────────────────────────────────────
    if not is_session_active(sess_row):
        return render_template('attend_error.html', today=now_str(),
            icon='⏰', title='QR Code Expired',
            msg='This QR code has expired. Ask your teacher to generate a new one.')

    # ── Device already used for DIFFERENT student this session (sharing!) ─────
    conn = get_conn()
    prev_roll = conn.execute("""
        SELECT roll_no FROM scan_log
        WHERE session_id=? AND device_hash=? AND was_blocked=0 AND roll_no!=''
        LIMIT 1
    """, (sess_row['id'], dev_hash)).fetchone()
    conn.close()

    if prev_roll and request.method == 'GET':
        # Device was already used to mark attendance for someone else
        log_scan(sess_row['id'], dev_hash, ip, '', True, 'Device reuse detected')
        log_anomaly('DEVICE_SHARING', 'HIGH',
            f"Device {dev_hash[:8]} tried to mark for 2nd student. Already used for {prev_roll['roll_no']}",
            session_id=sess_row['id'])
        return render_template('attend_error.html', today=now_str(),
            icon='🚫', title='Device Already Used',
            msg='This device was already used to mark attendance in this session. Each phone can only be used once per class.')

    subject      = sess_row['subject']
    subject_name = SUBJECTS.get(subject, subject)
    label        = sess_row['label'] or subject_name

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        roll = request.form.get('roll_no', '').strip().upper()

        if not name:
            flash('Please enter your full name.', 'danger')
            return redirect(url_for('attend', token=token))
        if not roll:
            flash('Please enter your roll number.', 'danger')
            return redirect(url_for('attend', token=token))

        # ── Check if THIS roll already submitted from a DIFFERENT device ──────
        conn = get_conn()
        prev_device = conn.execute("""
            SELECT device_hash FROM scan_log
            WHERE session_id=? AND roll_no=? AND was_blocked=0
            LIMIT 1
        """, (sess_row['id'], roll)).fetchone()
        conn.close()

        if prev_device and prev_device['device_hash'] != dev_hash:
            log_scan(sess_row['id'], dev_hash, ip, roll, True, 'Roll no already marked from different device')
            log_anomaly('ROLL_REUSE', 'HIGH',
                f"{roll} tried to mark from 2nd device",
                session_id=sess_row['id'])
            return render_template('attend_error.html', today=now_str(),
                icon='🚫', title='Already Marked',
                msg=f'Roll number {roll} has already been marked present in this session from another device.')

        # ── Risk Score ────────────────────────────────────────────────────────
        risk_score, risk_reason = calculate_risk_score(
            sess_row['id'], dev_hash, ip, roll)

        # ── Get/create student ────────────────────────────────────────────────
        student, is_new = get_or_create_student(roll, name)
        if not is_new and name and student['name'] != name:
            update_student_name(roll, name)
            student['name'] = name

        # ── Mark attendance ───────────────────────────────────────────────────
        ok, msg = mark_attendance(
            student['id'], sess_row['id'], subject,
            ip=ip, device_hash=dev_hash, user_agent=ua,
            risk_score=risk_score, flag_reason=risk_reason)

        # Log the scan
        log_scan(sess_row['id'], dev_hash, ip, roll, not ok,
                 '' if ok else msg)

        # Log anomaly if high risk
        if ok and risk_score > 0.5:
            log_anomaly('HIGH_RISK_SCAN', 'MEDIUM',
                f"{roll} marked with risk {risk_score:.2f}: {risk_reason}",
                student_id=student['id'], session_id=sess_row['id'])

        return render_template('attend_result.html',
            ok=ok, msg=msg, student=student,
            subject=subject, subject_name=subject_name,
            label=label, token=token,
            risk_score=risk_score, today=now_str())

    # ── Log that this device opened the page ──────────────────────────────────
    log_scan(sess_row['id'], dev_hash, ip, '', False, 'page_open')

    return render_template('attend_form.html',
        token=token, subject=subject,
        subject_name=subject_name, label=label,
        today=now_str())


# ── STUDENT STATS ─────────────────────────────────────────────────────────────
@app.route('/mystats', methods=['GET', 'POST'])
def my_stats():
    if request.method == 'POST':
        roll = request.form.get('roll_no', '').strip().upper()
        if roll:
            return redirect(url_for('student_stats', roll=roll))
        flash('Enter your roll number.', 'danger')
    return render_template('my_stats_lookup.html', today=now_str())

@app.route('/stats/<roll>')
def student_stats(roll):
    student = get_student_by_roll(roll)
    if not student:
        flash('No record found. Mark attendance first.', 'danger')
        return redirect(url_for('my_stats'))
    records, log = get_student_stats(student['id'])
    risk_data = predict_detention_risk(student['id'])
    return render_template('student_stats.html',
        student=student, records=records, log=log,
        risk_data=risk_data, subjects=SUBJECTS, today=now_str())


# ── TEACHER GATE ──────────────────────────────────────────────────────────────
@app.route('/teacher', methods=['GET', 'POST'])
def teacher_gate():
    if session.get('teacher_ok'):
        return redirect(url_for('teacher_dashboard'))
    first_time = not teacher_exists()
    if request.method == 'POST':
        if first_time:
            name = request.form.get('name','').strip()
            pin  = request.form.get('pin','').strip()
            pin2 = request.form.get('pin2','').strip()
            if not name:      flash('Enter your name.','danger')
            elif len(pin)<4:  flash('PIN must be at least 4 digits.','danger')
            elif pin!=pin2:   flash('PINs do not match.','danger')
            else:
                setup_teacher(name, pin)
                session['teacher_ok']   = True
                session['teacher_name'] = name
                flash(f'Welcome {name}!','success')
                return redirect(url_for('teacher_dashboard'))
        else:
            pin  = request.form.get('pin','').strip()
            name = verify_teacher_pin(pin)
            if name:
                session['teacher_ok']   = True
                session['teacher_name'] = name
                return redirect(url_for('teacher_dashboard'))
            flash('Wrong PIN.','danger')
    return render_template('teacher_gate.html',
        first_time=first_time, today=now_str())

@app.route('/teacher/logout')
def teacher_logout():
    session.clear()
    return redirect(url_for('home'))


# ── TEACHER DASHBOARD ─────────────────────────────────────────────────────────
@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    sessions  = get_all_sessions()
    now_iso   = datetime.now().isoformat()
    for s in sessions:
        s['active'] = s['is_active'] and (
            s['expires_at'] is None or s['expires_at'] > now_iso)
    insights  = get_class_insights()
    heatmap   = get_attendance_heatmap(14)
    anomalies = get_anomalies(5)
    return render_template('teacher_dashboard.html',
        sessions=sessions, subjects=SUBJECTS,
        teacher=get_teacher(), today=now_str(),
        insights=insights, heatmap=heatmap,
        anomalies=anomalies)


# ── GENERATE QR ───────────────────────────────────────────────────────────────
@app.route('/teacher/generate', methods=['GET', 'POST'])
@teacher_required
def generate_qr():
    qr_data  = None
    local_ip = get_local_ip()

    if request.method == 'POST':
        subject = request.form.get('subject','')
        label   = request.form.get('label','').strip()
        expiry  = request.form.get('expiry','30')
        ip_lock = request.form.get('ip_lock','').strip()

        if subject not in SUBJECTS:
            flash('Select a valid subject.','danger')
            return redirect(url_for('generate_qr'))

        token = secrets.token_hex(4)

        if expiry == 'never':
            expires_at = None; expiry_label = 'Never expires'
        else:
            mins       = int(expiry)
            expires_at = (datetime.now() + timedelta(minutes=mins)).isoformat()
            expiry_label = f'Expires in {mins} min'

        sid = create_qr_session(
            token, subject, label or SUBJECTS[subject],
            expires_at, session.get('teacher_name','Teacher'),
            allowed_ip_prefix=ip_lock)

        att_url = f"http://{local_ip}:5000/attend/{token}"

        img = encode_qr(att_url)
        buf = io.BytesIO(); img.save(buf,'PNG'); buf.seek(0)
        b64 = base64.b64encode(buf.read()).decode()
        img.save(os.path.join(QR_FOLDER, f'{token}.png'))

        qr_data = dict(
            token=token, subject=subject,
            subject_name=SUBJECTS[subject],
            label=label or SUBJECTS[subject],
            b64=b64, session_id=sid,
            expiry_label=expiry_label,
            att_url=att_url, local_ip=local_ip)

    return render_template('generate_qr.html',
        subjects=SUBJECTS, qr_data=qr_data,
        today=now_str(), local_ip=local_ip)


# ── SESSION DETAIL ────────────────────────────────────────────────────────────
@app.route('/teacher/session/<int:sess_id>')
@teacher_required
def session_detail(sess_id):
    conn = get_conn()
    s = conn.execute("SELECT * FROM qr_sessions WHERE id=?", (sess_id,)).fetchone()
    conn.close()
    if not s:
        flash('Session not found.','danger')
        return redirect(url_for('teacher_dashboard'))
    rows   = get_session_attendees(sess_id)
    active = is_session_active(dict(s))
    return render_template('session_detail.html',
        sess=dict(s), rows=rows, active=active,
        subjects=SUBJECTS, today=now_str())

@app.route('/teacher/session/deactivate/<int:sess_id>', methods=['POST'])
@teacher_required
def deactivate_sess(sess_id):
    deactivate_session(sess_id)
    flash('Session deactivated — QR no longer scannable.','success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/session/delete/<int:sess_id>', methods=['POST'])
@teacher_required
def delete_sess(sess_id):
    delete_session(sess_id)
    flash('Session deleted.','success')
    return redirect(url_for('teacher_dashboard'))


# ── ALL STUDENTS ──────────────────────────────────────────────────────────────
@app.route('/teacher/students')
@teacher_required
def all_students():
    data      = get_all_students_report()
    risk_list = get_all_students_risk()
    return render_template('all_students.html',
        data=data, risk_list=risk_list,
        subjects=SUBJECTS, today=now_str())

@app.route('/teacher/students/add', methods=['POST'])
@teacher_required
def add_student():
    roll = request.form.get('roll_no','').strip().upper()
    name = request.form.get('name','').strip()
    if roll and name:
        get_or_create_student(roll, name)
        flash(f'{roll} — {name} added.','success')
    else:
        flash('Enter both roll number and name.','danger')
    return redirect(url_for('all_students'))

@app.route('/teacher/students/delete/<int:student_id>', methods=['POST'])
@teacher_required
def delete_student(student_id):
    from database import delete_student as db_delete_student
    db_delete_student(student_id)
    flash('Student deleted along with all their attendance records.','success')
    return redirect(url_for('all_students'))


# ── ANOMALIES ─────────────────────────────────────────────────────────────────
@app.route('/teacher/anomalies')
@teacher_required
def view_anomalies():
    anomalies = get_anomalies(100)
    flagged   = get_flagged_attendance()
    return render_template('anomalies.html',
        anomalies=anomalies, flagged=flagged,
        today=now_str())


# ── EXPORT CSV ────────────────────────────────────────────────────────────────
@app.route('/teacher/export/<subject>')
@teacher_required
def export_csv(subject):
    if subject not in SUBJECTS and subject != 'all':
        flash('Invalid subject.','danger')
        return redirect(url_for('all_students'))

    conn = get_conn()
    if subject == 'all':
        rows = conn.execute("""
            SELECT s.roll_no, s.name, a.subject, a.marked_at, qs.label
            FROM attendance a
            JOIN students s ON s.id=a.student_id
            JOIN qr_sessions qs ON qs.id=a.session_id
            ORDER BY s.roll_no, a.subject, a.marked_at
        """).fetchall()
        filename = 'attendance_all.csv'
        headers  = ['Roll No','Name','Subject','Date/Time','Session']
    else:
        rows = conn.execute("""
            SELECT s.roll_no, s.name, a.marked_at, qs.label
            FROM attendance a
            JOIN students s ON s.id=a.student_id
            JOIN qr_sessions qs ON qs.id=a.session_id
            WHERE a.subject=?
            ORDER BY s.roll_no, a.marked_at
        """, (subject,)).fetchall()
        filename = f'attendance_{subject}.csv'
        headers  = ['Roll No','Name','Date/Time','Session']
    conn.close()

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(headers)
    for r in rows: w.writerow(list(r))

    resp = make_response(buf.getvalue())
    resp.headers['Content-Type']        = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return resp


# ── API: real-time attendee count ─────────────────────────────────────────────
@app.route('/api/session/<int:sess_id>/count')
@teacher_required
def session_count(sess_id):
    conn = get_conn()
    cnt  = conn.execute(
        "SELECT COUNT(*) as cnt FROM attendance WHERE session_id=?",
        (sess_id,)).fetchone()['cnt']
    conn.close()
    return jsonify({'count': cnt})


if __name__ == '__main__':
    init_db()
    ip = get_local_ip()
    print("\n" + "="*55)
    print("  QR Attendance System — Industry Edition")
    print("="*55)
    print(f"  Laptop : http://127.0.0.1:5000")
    print(f"  Phones : http://{ip}:5000")
    print(f"\n  Laptop and phones must be on same WiFi!")
    t = get_teacher()
    if t: print(f"\n  Teacher: {t['name']}")
    else: print(f"\n  First run: visit /teacher to set PIN")
    print("="*55 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)