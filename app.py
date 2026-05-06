"""
app.py — Industry-Grade QR Attendance System
Security: device fingerprinting, IP tracking, risk scoring, PIN rate-limiting
AI/ML:    anomaly detection, detention prediction, smart insights
Features: PDF reports, weekly email, subject management, analytics
"""
import os, io, base64, socket, csv, requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, make_response)
from database import (
    init_db, teacher_exists, setup_teacher, verify_teacher_pin, get_teacher,
    get_or_create_student, get_student_by_roll, get_student_by_id,
    update_student_name,
    create_qr_session, get_session_by_token, is_session_active,
    get_all_sessions, delete_session, deactivate_session,
    mark_attendance, remove_attendance, add_manual_attendance,
    get_student_stats,
    get_session_attendees, get_all_students_report, get_selected_students_report,
    log_scan, make_device_hash, device_already_scanned, get_conn,
    log_anomaly, get_anomalies, get_flagged_attendance,
    get_all_subjects, add_subject, delete_subject,
    bulk_delete_students, get_advanced_analytics, delete_student,
    get_setting, set_setting, get_email_schedule
)
from ml_engine import (
    calculate_risk_score, predict_detention_risk,
    get_class_insights, get_attendance_heatmap, get_all_students_risk
)
from qr_generator import encode_qr
import secrets as secrets_module
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'qr-attend-industry-2024-xk9mP')
init_db()
QR_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'qrcodes')
os.makedirs(QR_FOLDER, exist_ok=True)

ANTHROPIC_API_KEY  = os.environ.get('ANTHROPIC_API_KEY', '')
SENDGRID_API_KEY   = os.environ.get('SENDGRID_API_KEY', '')
SENDGRID_FROM      = os.environ.get('SENDGRID_FROM', '')

# ── Helpers ───────────────────────────────────────────────────────────────────
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
            flash('Please login as teacher first.', 'danger')
            return redirect(url_for('teacher_gate'))
        return f(*a, **kw)
    return wrap

def _get_ai_client():
    if not ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    except Exception:
        return None

def _send_email(to_email, subject, html_body):
    """Send an HTML email via SendGrid HTTP API. Returns (ok, error_msg)."""
    if not SENDGRID_API_KEY or not SENDGRID_FROM:
        return False, 'SendGrid not configured. Set SENDGRID_API_KEY and SENDGRID_FROM secrets.'
    try:
        resp = requests.post(
            'https://api.sendgrid.com/v3/mail/send',
            headers={
                'Authorization': f'Bearer {SENDGRID_API_KEY}',
                'Content-Type':  'application/json',
            },
            json={
                'personalizations': [{'to': [{'email': to_email}]}],
                'from':    {'email': SENDGRID_FROM},
                'subject': subject,
                'content': [{'type': 'text/html', 'value': html_body}],
            },
            timeout=15
        )
        if resp.status_code in (200, 202):
            return True, ''
        return False, f'SendGrid error {resp.status_code}: {resp.text}'
    except Exception as e:
        return False, str(e)


# ── HOME ──────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html', subjects=get_all_subjects(), today=now_str())


# ══════════════════════════════════════════════════════════════════════════════
#  STUDENT ATTEND FLOW
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/attend/<token>', methods=['GET', 'POST'])
def attend(token):
    ip       = get_client_ip()
    ua       = request.headers.get('User-Agent', '')
    lang     = request.headers.get('Accept-Language', '')
    dev_hash = make_device_hash(ip, ua, lang)

    sess_row = get_session_by_token(token)
    if not sess_row:
        return render_template('attend_error.html', today=now_str(),
            icon='❌', title='Invalid QR Code',
            msg='This QR code is not recognised. Ask your teacher to show the correct one.')

    if not is_session_active(sess_row):
        return render_template('attend_error.html', today=now_str(),
            icon='⏰', title='QR Code Expired',
            msg='This QR code has expired. Ask your teacher to generate a new one.')

    # Check max capacity
    conn = get_conn()
    curr_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM attendance WHERE session_id=?",
        (sess_row['id'],)).fetchone()['cnt']
    max_scans = sess_row.get('max_scans', 999) or 999
    if curr_count >= max_scans:
        conn.close()
        return render_template('attend_error.html', today=now_str(),
            icon='🔒', title='Session Full',
            msg=f'This session has reached its maximum capacity of {max_scans} students.')

    prev_roll = conn.execute("""
        SELECT roll_no FROM scan_log
        WHERE session_id=? AND device_hash=? AND was_blocked=0 AND roll_no!=''
        LIMIT 1
    """, (sess_row['id'], dev_hash)).fetchone()
    conn.close()

    if prev_roll and request.method == 'GET':
        log_scan(sess_row['id'], dev_hash, ip, '', True, 'Device reuse detected')
        log_anomaly('DEVICE_SHARING', 'HIGH',
            f"Device {dev_hash[:8]} tried to mark for 2nd student. Already used for {prev_roll['roll_no']}",
            session_id=sess_row['id'])
        return render_template('attend_error.html', today=now_str(),
            icon='🚫', title='Device Already Used',
            msg='This device was already used to mark attendance in this session.')

    subjects     = get_all_subjects()
    subject      = sess_row['subject']
    subject_name = subjects.get(subject, subject)
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
                f"{roll} tried to mark from 2nd device", session_id=sess_row['id'])
            return render_template('attend_error.html', today=now_str(),
                icon='🚫', title='Already Marked',
                msg=f'Roll number {roll} has already been marked present in this session from another device.')

        risk_score, risk_reason = calculate_risk_score(
            sess_row['id'], dev_hash, ip, roll)

        student, is_new = get_or_create_student(roll, name)
        if not is_new and name and student['name'] != name:
            update_student_name(roll, name)
            student['name'] = name

        ok, msg = mark_attendance(
            student['id'], sess_row['id'], subject,
            ip=ip, device_hash=dev_hash, user_agent=ua,
            risk_score=risk_score, flag_reason=risk_reason)

        log_scan(sess_row['id'], dev_hash, ip, roll, not ok, '' if ok else msg)

        if ok and risk_score > 0.5:
            log_anomaly('HIGH_RISK_SCAN', 'MEDIUM',
                f"{roll} marked with risk {risk_score:.2f}: {risk_reason}",
                student_id=student['id'], session_id=sess_row['id'])

        return render_template('attend_result.html',
            ok=ok, msg=msg, student=student,
            subject=subject, subject_name=subject_name,
            label=label, token=token,
            risk_score=risk_score, today=now_str())

    log_scan(sess_row['id'], dev_hash, ip, '', False, 'page_open')
    return render_template('attend_form.html',
        token=token, subject=subject,
        subject_name=subject_name, label=label,
        today=now_str())


# ── STUDENT STATS ─────────────────────────────────────────────────────────────
@app.route('/mystats', methods=['GET', 'POST'])
def my_stats():
    if not session.get('teacher_ok'):
        flash('Please login as teacher to view student stats.', 'danger')
        return redirect(url_for('teacher_gate'))
    if request.method == 'POST':
        roll = request.form.get('roll_no', '').strip().upper()
        if roll:
            return redirect(url_for('student_stats', roll=roll))
        flash('Enter a roll number.', 'danger')
    return render_template('my_stats_lookup.html', today=now_str())

@app.route('/stats/<roll>')
@teacher_required
def student_stats(roll):
    student = get_student_by_roll(roll)
    if not student:
        flash('No record found.', 'danger')
        return redirect(url_for('my_stats'))
    records, log = get_student_stats(student['id'])
    risk_data = predict_detention_risk(student['id'])
    return render_template('student_stats.html',
        student=student, records=records, log=log,
        risk_data=risk_data, subjects=get_all_subjects(), today=now_str())


# ── PDF REPORT ────────────────────────────────────────────────────────────────
@app.route('/student/<roll>/report')
@teacher_required
def download_student_report(roll):
    student = get_student_by_roll(roll)
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('all_students'))

    records, log = get_student_stats(student['id'])
    risk_data    = predict_detention_risk(student['id'])

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        story  = []

        # ── Header ────────────────────────────────────────────────────────────
        hdr_style = ParagraphStyle('hdr', parent=styles['Title'],
                                   fontSize=20, textColor=colors.HexColor('#6366f1'),
                                   spaceAfter=4)
        story.append(Paragraph('QR Attendance System', hdr_style))
        story.append(Paragraph('<b>Student Attendance Report</b>', styles['Heading2']))
        story.append(HRFlowable(width='100%', color=colors.HexColor('#6366f1')))
        story.append(Spacer(1, 0.3*cm))

        # ── Student Info Table ────────────────────────────────────────────────
        overall_pct = round(sum(r['percentage'] for r in records) / len(records), 1) if records else 0
        worst_risk  = 'safe'
        for r in records:
            if r['status'] == 'danger':   worst_risk = 'danger'
            elif r['status'] == 'warning' and worst_risk == 'safe': worst_risk = 'warning'

        info_data = [
            ['Name',         student['name']],
            ['Roll No',      student['roll_no']],
            ['Email',        student.get('email', '') or 'N/A'],
            ['Overall %',    f"{overall_pct}%"],
            ['Risk Status',  worst_risk.upper()],
            ['Generated',    datetime.now().strftime('%d %B %Y, %H:%M')],
        ]
        info_table = Table(info_data, colWidths=[4*cm, 12*cm])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#13131a')),
            ('TEXTCOLOR',  (0,0), (0,-1), colors.HexColor('#6366f1')),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 10),
            ('FONTNAME',   (0,0), (0,-1),  'Helvetica-Bold'),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#2a2a3a')),
            ('PADDING',    (0,0), (-1,-1), 6),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Bar Chart ─────────────────────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(7, 3))
        fig.patch.set_facecolor('#0a0a0f')
        ax.set_facecolor('#13131a')

        codes = [r['code'] for r in records]
        pcts  = [r['percentage'] for r in records]
        bar_colors = ['#10b981' if p >= 75 else '#f59e0b' if p >= 60 else '#ef4444'
                      for p in pcts]

        bars = ax.bar(codes, pcts, color=bar_colors, edgecolor='#2a2a3a', linewidth=0.5)
        ax.axhline(75, color='#10b981', linestyle='--', linewidth=1.2,
                   alpha=0.8, label='75% threshold')
        ax.set_ylim(0, 110)
        ax.set_ylabel('Attendance %', color='#e8e8f0', fontsize=9)
        ax.tick_params(colors='#6b7280', labelsize=8)
        ax.spines['bottom'].set_color('#2a2a3a')
        ax.spines['left'].set_color('#2a2a3a')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.set_title('Subject-wise Attendance', color='#e8e8f0', fontsize=11, pad=10)
        ax.legend(fontsize=8, facecolor='#13131a', edgecolor='#2a2a3a',
                  labelcolor='#e8e8f0')
        for bar, pct in zip(bars, pcts):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                    f'{pct}%', ha='center', va='bottom',
                    color='#e8e8f0', fontsize=8, fontweight='bold')

        chart_buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(chart_buf, format='png', facecolor=fig.get_facecolor(),
                    dpi=120, bbox_inches='tight')
        plt.close()
        chart_buf.seek(0)

        from reportlab.platypus import Image as RLImage
        chart_img = RLImage(chart_buf, width=14*cm, height=6*cm)
        story.append(chart_img)
        story.append(Spacer(1, 0.4*cm))

        # ── Subject Breakdown Table ───────────────────────────────────────────
        story.append(Paragraph('<b>Subject Breakdown</b>', styles['Heading3']))
        tbl_data = [['Subject', 'Code', 'Attended', 'Total', '%', 'Status']]
        for r in records:
            rd = risk_data.get(r['code'], {})
            risk_label = rd.get('risk', r['status']).upper() if rd else r['status'].upper()
            tbl_data.append([
                r['name'], r['code'],
                str(r['attended']), str(r['total']),
                f"{r['percentage']}%", risk_label
            ])
        subj_table = Table(tbl_data, colWidths=[5*cm, 1.5*cm, 2*cm, 2*cm, 2*cm, 3*cm])
        subj_style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
            ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,-1), 9),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#2a2a3a')),
            ('PADDING',    (0,0), (-1,-1), 6),
            ('ALIGN',      (2,0), (-1,-1), 'CENTER'),
        ])
        for i, r in enumerate(records, 1):
            if r['status'] == 'safe':
                subj_style.add('TEXTCOLOR', (5, i), (5, i), colors.HexColor('#10b981'))
            elif r['status'] == 'warning':
                subj_style.add('TEXTCOLOR', (5, i), (5, i), colors.HexColor('#f59e0b'))
            else:
                subj_style.add('TEXTCOLOR', (5, i), (5, i), colors.HexColor('#ef4444'))
        subj_table.setStyle(subj_style)
        story.append(subj_table)
        story.append(Spacer(1, 0.4*cm))

        # ── AI Analysis (if available) ────────────────────────────────────────
        ai_analysis = ''
        client = _get_ai_client()
        if client:
            try:
                import anthropic
                context = f"Student {student['name']} (Roll: {student['roll_no']}). " \
                          f"Overall attendance: {overall_pct}%. " \
                          + " | ".join([f"{r['name']}: {r['percentage']}% ({r['status']})"
                                        for r in records])
                resp = client.messages.create(
                    model='claude-sonnet-4-5',
                    max_tokens=300,
                    messages=[{
                        'role': 'user',
                        'content': f"As an academic advisor, write a 3-4 sentence personalized "
                                   f"attendance risk analysis for this student: {context}. "
                                   f"Be specific, constructive, and encouraging."
                    }]
                )
                ai_analysis = resp.content[0].text
            except Exception:
                pass

        if ai_analysis:
            ai_style = ParagraphStyle('ai', parent=styles['Normal'],
                                      fontSize=9, leading=14,
                                      backColor=colors.HexColor('#1a1a24'),
                                      borderColor=colors.HexColor('#6366f1'),
                                      borderWidth=1, borderPadding=8,
                                      textColor=colors.HexColor('#e8e8f0'))
            story.append(Paragraph('<b>AI Analysis</b>', styles['Heading3']))
            story.append(Paragraph(ai_analysis, ai_style))
            story.append(Spacer(1, 0.3*cm))

        # ── Footer ────────────────────────────────────────────────────────────
        story.append(HRFlowable(width='100%', color=colors.HexColor('#2a2a3a')))
        footer_style = ParagraphStyle('footer', parent=styles['Normal'],
                                      fontSize=8, textColor=colors.HexColor('#6b7280'),
                                      alignment=1)
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f"Generated by QR Attendance System · {datetime.now().strftime('%d %B %Y, %H:%M')}",
            footer_style))

        doc.build(story)
        buf.seek(0)
        resp = make_response(buf.read())
        resp.headers['Content-Type']        = 'application/pdf'
        resp.headers['Content-Disposition'] = f'attachment; filename=attendance_{roll}.pdf'
        return resp

    except ImportError as e:
        flash(f'PDF library not installed: {e}', 'danger')
        return redirect(url_for('student_stats', roll=roll))
    except Exception as e:
        flash(f'Error generating PDF: {e}', 'danger')
        return redirect(url_for('student_stats', roll=roll))


# ── SEND WEEKLY REPORT BY EMAIL ───────────────────────────────────────────────
@app.route('/teacher/send-weekly-reports', methods=['POST'])
@teacher_required
def send_weekly_reports():
    if not SENDGRID_API_KEY or not SENDGRID_FROM:
        flash('Email not configured. Please set SENDGRID_API_KEY and SENDGRID_FROM secrets.', 'danger')
        return redirect(url_for('teacher_dashboard'))

    conn = get_conn()
    students = conn.execute(
        "SELECT * FROM students WHERE email != '' AND email IS NOT NULL").fetchall()
    conn.close()

    sent = 0; failed = 0
    for s in students:
        s = dict(s)
        records, _ = get_student_stats(s['id'])
        risk_data  = predict_detention_risk(s['id'])

        overall_pct = round(sum(r['percentage'] for r in records) / len(records), 1) if records else 0
        week_start  = (datetime.now() - timedelta(days=7)).strftime('%d %b')
        week_end    = datetime.now().strftime('%d %b %Y')

        rows_html = ''
        for r in records:
            color = '#10b981' if r['status'] == 'safe' else '#f59e0b' if r['status'] == 'warning' else '#ef4444'
            rows_html += f"""
            <tr>
              <td style="padding:10px;border-bottom:1px solid #2a2a3a;">{r['name']}</td>
              <td style="padding:10px;border-bottom:1px solid #2a2a3a;text-align:center;
                         font-weight:bold;color:{color};">{r['percentage']}%</td>
              <td style="padding:10px;border-bottom:1px solid #2a2a3a;text-align:center;">
                {r['attended']}/{r['total']}</td>
              <td style="padding:10px;border-bottom:1px solid #2a2a3a;text-align:center;
                         color:{color};font-weight:bold;">{r['status'].upper()}</td>
            </tr>"""

        alert = ''
        if overall_pct < 60:
            alert = f'<div style="background:#7f1d1d;border-radius:8px;padding:12px;margin-bottom:16px;color:#fca5a5;">⚠️ <strong>Critical:</strong> Your overall attendance is {overall_pct}%. Immediate improvement required to avoid detention.</div>'
        elif overall_pct < 75:
            alert = f'<div style="background:#78350f;border-radius:8px;padding:12px;margin-bottom:16px;color:#fde68a;">⚠️ <strong>Warning:</strong> Your overall attendance is {overall_pct}%. You are below the 75% threshold.</div>'
        else:
            alert = f'<div style="background:#064e3b;border-radius:8px;padding:12px;margin-bottom:16px;color:#6ee7b7;">✅ Great job! Your overall attendance is {overall_pct}%. Keep it up!</div>'

        html = f"""
        <!DOCTYPE html>
        <html>
        <body style="background:#0a0a0f;color:#e8e8f0;font-family:system-ui,sans-serif;margin:0;padding:20px;">
          <div style="max-width:600px;margin:0 auto;background:#13131a;border-radius:12px;
                      border:1px solid #2a2a3a;overflow:hidden;">
            <div style="background:#6366f1;padding:24px;text-align:center;">
              <h1 style="margin:0;color:#fff;font-size:1.4rem;">📊 Weekly Attendance Report</h1>
              <p style="margin:6px 0 0;color:#c7d2fe;font-size:.9rem;">{week_start} – {week_end}</p>
            </div>
            <div style="padding:24px;">
              <p style="margin-top:0;">Hi <strong>{s['name']}</strong> ({s['roll_no']}),</p>
              {alert}
              <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
                <thead>
                  <tr style="background:#1a1a24;">
                    <th style="padding:10px;text-align:left;color:#6b7280;font-size:.8rem;">SUBJECT</th>
                    <th style="padding:10px;text-align:center;color:#6b7280;font-size:.8rem;">%</th>
                    <th style="padding:10px;text-align:center;color:#6b7280;font-size:.8rem;">CLASSES</th>
                    <th style="padding:10px;text-align:center;color:#6b7280;font-size:.8rem;">STATUS</th>
                  </tr>
                </thead>
                <tbody>{rows_html}</tbody>
              </table>
              <p style="font-size:.8rem;color:#6b7280;margin-bottom:0;">
                This is an automated weekly report from your institution's attendance system.
              </p>
            </div>
          </div>
        </body>
        </html>"""

        ok, err = _send_email(s['email'],
                              f"Weekly Attendance Report — {week_start} to {week_end}",
                              html)
        if ok:
            sent += 1
        else:
            failed += 1

    if sent:
        flash(f'Weekly reports sent to {sent} student(s).', 'success')
    if failed:
        flash(f'{failed} report(s) failed. Check SendGrid settings.', 'danger')
    if not students:
        flash('No students with email addresses found.', 'danger')
    return redirect(url_for('teacher_dashboard'))


# ── TEACHER GATE ──────────────────────────────────────────────────────────────
@app.route('/teacher', methods=['GET', 'POST'])
def teacher_gate():
    if session.get('teacher_ok'):
        return redirect(url_for('teacher_dashboard'))

    # Rate limiting
    now_ts    = datetime.now().timestamp()
    lock_until = session.get('pin_lock_until', 0)
    if now_ts < lock_until:
        remaining = int(lock_until - now_ts)
        return render_template('teacher_gate.html',
            first_time=False, today=now_str(),
            locked=True, lock_remaining=remaining)

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
                session.pop('pin_attempts', None)
                session.pop('pin_lock_until', None)
                flash(f'Welcome {name}!','success')
                return redirect(url_for('teacher_dashboard'))
        else:
            pin = request.form.get('pin','').strip()
            name = verify_teacher_pin(pin)
            if name:
                session['teacher_ok']   = True
                session['teacher_name'] = name
                session.pop('pin_attempts', None)
                session.pop('pin_lock_until', None)
                return redirect(url_for('teacher_dashboard'))
            else:
                attempts = session.get('pin_attempts', 0) + 1
                session['pin_attempts'] = attempts
                if attempts >= 5:
                    session['pin_lock_until'] = now_ts + 300
                    session['pin_attempts']   = 0
                    remaining = 300
                    return render_template('teacher_gate.html',
                        first_time=False, today=now_str(),
                        locked=True, lock_remaining=remaining)
                flash(f'Wrong PIN. {5 - attempts} attempt(s) remaining.','danger')

    return render_template('teacher_gate.html',
        first_time=first_time, today=now_str(), locked=False, lock_remaining=0)

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
    subjects  = get_all_subjects()
    has_smtp  = bool(SENDGRID_API_KEY and SENDGRID_FROM)
    schedule  = get_email_schedule()
    return render_template('teacher_dashboard.html',
        sessions=sessions, subjects=subjects,
        teacher=get_teacher(), today=now_str(),
        insights=insights, heatmap=heatmap,
        anomalies=anomalies, has_smtp=has_smtp,
        schedule=schedule)


# ── GENERATE QR ───────────────────────────────────────────────────────────────
@app.route('/teacher/generate', methods=['GET', 'POST'])
@teacher_required
def generate_qr():
    qr_data  = None
    local_ip = get_local_ip()
    subjects = get_all_subjects()

    if request.method == 'POST':
        subject    = request.form.get('subject','')
        label      = request.form.get('label','').strip()
        expiry     = request.form.get('expiry','30')
        ip_lock    = request.form.get('ip_lock','').strip()
        max_scans  = request.form.get('max_scans','999').strip()
        notes      = request.form.get('notes','').strip()

        if subject not in subjects:
            flash('Select a valid subject.','danger')
            return redirect(url_for('generate_qr'))

        try:
            max_scans = int(max_scans) if max_scans and int(max_scans) > 0 else 999
        except Exception:
            max_scans = 999

        token = secrets_module.token_hex(4)

        if expiry == 'never':
            expires_at = None; expiry_label = 'Never expires'
        else:
            mins       = int(expiry)
            expires_at = (datetime.now() + timedelta(minutes=mins)).isoformat()
            expiry_label = f'Expires in {mins} min'

        sid = create_qr_session(
            token, subject, label or subjects[subject],
            expires_at, session.get('teacher_name','Teacher'),
            allowed_ip_prefix=ip_lock,
            max_scans=max_scans, notes=notes)

        att_url = f"http://{local_ip}:5000/attend/{token}"
        img = encode_qr(att_url)
        buf = io.BytesIO(); img.save(buf,'PNG'); buf.seek(0)
        b64 = base64.b64encode(buf.read()).decode()
        img.save(os.path.join(QR_FOLDER, f'{token}.png'))

        qr_data = dict(
            token=token, subject=subject,
            subject_name=subjects[subject],
            label=label or subjects[subject],
            b64=b64, session_id=sid,
            expiry_label=expiry_label,
            att_url=att_url, local_ip=local_ip,
            notes=notes, max_scans=max_scans)

    return render_template('generate_qr.html',
        subjects=subjects, qr_data=qr_data,
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
        subjects=get_all_subjects(), today=now_str())

@app.route('/teacher/session/deactivate/<int:sess_id>', methods=['POST'])
@teacher_required
def deactivate_sess(sess_id):
    deactivate_session(sess_id)
    flash('Session deactivated.','success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/session/delete/<int:sess_id>', methods=['POST'])
@teacher_required
def delete_sess(sess_id):
    delete_session(sess_id)
    flash('Session deleted.','success')
    return redirect(url_for('teacher_dashboard'))


# ── ATTENDANCE CORRECTION ─────────────────────────────────────────────────────
@app.route('/teacher/attendance/remove', methods=['POST'])
@teacher_required
def remove_attendance_route():
    student_id = request.form.get('student_id', type=int)
    session_id = request.form.get('session_id', type=int)
    sess_id    = request.form.get('sess_id', type=int)
    if student_id and session_id:
        remove_attendance(student_id, session_id)
        flash('Attendance record removed.','success')
    return redirect(url_for('session_detail', sess_id=sess_id or session_id))

@app.route('/teacher/attendance/add-manual', methods=['POST'])
@teacher_required
def add_manual_route():
    roll_no    = request.form.get('roll_no','').strip().upper()
    session_id = request.form.get('session_id', type=int)
    sess_id    = request.form.get('sess_id', type=int)
    if roll_no and session_id:
        ok, msg = add_manual_attendance(roll_no, session_id)
        flash(msg, 'success' if ok else 'danger')
    return redirect(url_for('session_detail', sess_id=sess_id or session_id))


# ── ALL STUDENTS ──────────────────────────────────────────────────────────────
@app.route('/teacher/students')
@teacher_required
def all_students():
    data      = get_all_students_report()
    risk_list = get_all_students_risk()
    subjects  = get_all_subjects()
    return render_template('all_students.html',
        data=data, risk_list=risk_list,
        subjects=subjects, today=now_str())

@app.route('/teacher/students/add', methods=['POST'])
@teacher_required
def add_student():
    roll  = request.form.get('roll_no','').strip().upper()
    name  = request.form.get('name','').strip()
    email = request.form.get('email','').strip()
    if roll and name:
        get_or_create_student(roll, name, email=email)
        flash(f'{roll} — {name} added.','success')
    else:
        flash('Enter both roll number and name.','danger')
    return redirect(url_for('all_students'))

@app.route('/teacher/students/delete/<int:student_id>', methods=['POST'])
@teacher_required
def delete_student_route(student_id):
    delete_student(student_id)
    flash('Student deleted.','success')
    return redirect(url_for('all_students'))

@app.route('/teacher/students/bulk-delete', methods=['POST'])
@teacher_required
def bulk_delete():
    data = request.get_json()
    ids  = data.get('ids', []) if data else []
    if ids:
        bulk_delete_students([int(i) for i in ids])
        return jsonify({'ok': True, 'deleted': len(ids)})
    return jsonify({'ok': False, 'error': 'No IDs provided'})

@app.route('/teacher/students/bulk-export', methods=['POST'])
@teacher_required
def bulk_export():
    data = request.get_json()
    ids  = data.get('ids', []) if data else []
    if not ids:
        return jsonify({'ok': False, 'error': 'No IDs'})
    report   = get_selected_students_report([int(i) for i in ids])
    subjects = get_all_subjects()
    buf = io.StringIO()
    w   = csv.writer(buf)
    hdr = ['Roll No', 'Name', 'Email'] + [f'{c} %' for c in subjects] + ['Overall %']
    w.writerow(hdr)
    for d in report:
        s    = d['student']
        pcts = [sm['pct'] for sm in d['summary']]
        avg  = round(sum(pcts)/len(pcts), 1) if pcts else 0
        row  = [s['roll_no'], s['name'], s.get('email','')]
        row += [f"{sm['pct']}%" for sm in d['summary']]
        row += [f"{avg}%"]
        w.writerow(row)
    resp = make_response(buf.getvalue())
    resp.headers['Content-Type']        = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=selected_students.csv'
    return resp


# ── SUBJECT MANAGEMENT ────────────────────────────────────────────────────────
@app.route('/teacher/subjects/add', methods=['POST'])
@teacher_required
def add_subject_route():
    code = request.form.get('code','').strip().upper()
    name = request.form.get('name','').strip()
    if code and name:
        ok, msg = add_subject(code, name)
        flash(msg, 'success' if ok else 'danger')
    else:
        flash('Enter both code and name.','danger')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/subjects/delete/<code>', methods=['POST'])
@teacher_required
def delete_subject_route(code):
    ok, msg = delete_subject(code)
    flash(msg, 'success' if ok else 'danger')
    return redirect(url_for('teacher_dashboard'))


# ── ANOMALIES ─────────────────────────────────────────────────────────────────
@app.route('/teacher/anomalies')
@teacher_required
def view_anomalies():
    anomalies = get_anomalies(100)
    flagged   = get_flagged_attendance()
    return render_template('anomalies.html',
        anomalies=anomalies, flagged=flagged, today=now_str())


# ── ANALYTICS ─────────────────────────────────────────────────────────────────
@app.route('/teacher/analytics')
@teacher_required
def analytics():
    data = get_advanced_analytics()
    return render_template('analytics.html', data=data, today=now_str())


# ── EXPORT CSV ────────────────────────────────────────────────────────────────
@app.route('/teacher/export/<subject>')
@teacher_required
def export_csv(subject):
    subjects = get_all_subjects()
    if subject not in subjects and subject != 'all':
        flash('Invalid subject.','danger')
        return redirect(url_for('all_students'))
    conn = get_conn()
    if subject == 'all':
        rows = conn.execute("""
            SELECT s.roll_no, s.name, s.email, a.subject, a.marked_at, qs.label
            FROM attendance a
            JOIN students s ON s.id=a.student_id
            JOIN qr_sessions qs ON qs.id=a.session_id
            ORDER BY s.roll_no, a.subject, a.marked_at
        """).fetchall()
        filename = 'attendance_all.csv'
        headers  = ['Roll No','Name','Email','Subject','Date/Time','Session']
    else:
        rows = conn.execute("""
            SELECT s.roll_no, s.name, s.email, a.marked_at, qs.label
            FROM attendance a
            JOIN students s ON s.id=a.student_id
            JOIN qr_sessions qs ON qs.id=a.session_id
            WHERE a.subject=?
            ORDER BY s.roll_no, a.marked_at
        """, (subject,)).fetchall()
        filename = f'attendance_{subject}.csv'
        headers  = ['Roll No','Name','Email','Date/Time','Session']
    conn.close()
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(headers)
    for r in rows: w.writerow(list(r))
    resp = make_response(buf.getvalue())
    resp.headers['Content-Type']        = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return resp


# ── API: real-time count ──────────────────────────────────────────────────────
@app.route('/api/session/<int:sess_id>/count')
@teacher_required
def session_count(sess_id):
    conn = get_conn()
    cnt  = conn.execute(
        "SELECT COUNT(*) as cnt FROM attendance WHERE session_id=?",
        (sess_id,)).fetchone()['cnt']
    conn.close()
    return jsonify({'count': cnt})


# ── API: AI Student Chatbot ───────────────────────────────────────────────────
@app.route('/api/ai/student-chat', methods=['POST'])
@teacher_required
def ai_student_chat():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'AI not configured. Please add ANTHROPIC_API_KEY secret.'}), 503
    data    = request.get_json() or {}
    roll    = data.get('roll', '')
    message = data.get('message', '')
    history = data.get('history', [])

    student = get_student_by_roll(roll)
    if not student:
        return jsonify({'error': 'Student not found'}), 404

    records, _  = get_student_stats(student['id'])
    risk_data   = predict_detention_risk(student['id'])
    overall_pct = round(sum(r['percentage'] for r in records) / len(records), 1) if records else 0

    context = (f"Student: {student['name']}, Roll: {student['roll_no']}, "
               f"Overall: {overall_pct}%. "
               + " | ".join([f"{r['name']}: {r['percentage']}% ({r['status']})" for r in records]))

    messages = [{'role': 'user' if m['role'] == 'user' else 'assistant', 'content': m['content']}
                for m in history[-6:]]
    messages.append({'role': 'user', 'content': message})

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-sonnet-4-5',
            max_tokens=400,
            system=(f"You are a helpful academic advisor. Student data: {context}. "
                    f"Answer concisely about attendance, risk, and improvement tips. "
                    f"Be friendly, direct, and specific to this student's data."),
            messages=messages
        )
        return jsonify({'reply': resp.content[0].text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── API: AI Teacher Report ────────────────────────────────────────────────────
@app.route('/api/ai/teacher-report', methods=['POST'])
@teacher_required
def ai_teacher_report():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'AI not configured. Please add ANTHROPIC_API_KEY secret.'}), 503
    insights   = get_class_insights()
    risk_list  = get_all_students_risk()
    critical   = [s for s in risk_list if s['worst_risk'] in ('critical','danger')]
    context    = (f"Class insights: {[i['text'] for i in insights]}. "
                  f"Students at risk ({len(critical)}): "
                  + ", ".join([f"{s['name']} ({s['min_pct']}%)" for s in critical[:10]]))
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-sonnet-4-5',
            max_tokens=600,
            messages=[{'role': 'user', 'content':
                f"As an educational analytics expert, generate a structured class attendance report "
                f"with these sections: OVERALL HEALTH, URGENT ATTENTION, TREND ANALYSIS, "
                f"RECOMMENDED ACTIONS. Data: {context}. Be specific and actionable."}]
        )
        return jsonify({'report': resp.content[0].text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── API: AI Anomaly Explainer ─────────────────────────────────────────────────
@app.route('/api/ai/explain-anomaly', methods=['POST'])
@teacher_required
def ai_explain_anomaly():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'AI not configured. Please add ANTHROPIC_API_KEY secret.'}), 503
    data  = request.get_json() or {}
    atype = data.get('type', '')
    desc  = data.get('description', '')
    sev   = data.get('severity', '')
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-sonnet-4-5',
            max_tokens=200,
            messages=[{'role': 'user', 'content':
                f"Explain this attendance anomaly in plain English (2 sentences) and give "
                f"one specific action for the teacher. "
                f"Type: {atype}, Severity: {sev}, Description: {desc}. "
                f"Format: EXPLANATION: ... | ACTION: ..."}]
        )
        text = resp.content[0].text
        parts = text.split('|')
        explanation = parts[0].replace('EXPLANATION:', '').strip() if parts else text
        action = parts[1].replace('ACTION:', '').strip() if len(parts) > 1 else ''
        return jsonify({'explanation': explanation, 'action': action})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── EMAIL SCHEDULE SETTINGS ───────────────────────────────────────────────────
@app.route('/teacher/email-schedule', methods=['POST'])
@teacher_required
def save_email_schedule():
    enabled = '1' if request.form.get('enabled') else '0'
    day     = request.form.get('day',    '0').strip()
    hour    = request.form.get('hour',   '8').strip()
    minute  = request.form.get('minute', '0').strip()
    set_setting('email_schedule_enabled', enabled)
    set_setting('email_schedule_day',     day)
    set_setting('email_schedule_hour',    hour)
    set_setting('email_schedule_minute',  minute)
    _reschedule_email_job()
    status = 'enabled' if enabled == '1' else 'disabled'
    flash(f'Auto email schedule saved and {status}.', 'success')
    return redirect(url_for('teacher_dashboard'))


# ── SCHEDULER ─────────────────────────────────────────────────────────────────
DAY_NAMES = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']

def _auto_send_weekly_reports():
    """Called by APScheduler — sends weekly reports to all students with emails."""
    with app.app_context():
        if not SENDGRID_API_KEY or not SENDGRID_FROM:
            print('[Scheduler] SendGrid not configured, skipping.')
            return
        conn = get_conn()
        students = conn.execute(
            "SELECT * FROM students WHERE email != '' AND email IS NOT NULL"
        ).fetchall()
        conn.close()

        sent = failed = 0
        for s in students:
            s = dict(s)
            records, _ = get_student_stats(s['id'])
            if not records:
                continue
            overall_pct = round(sum(r['percentage'] for r in records) / len(records), 1)
            week_start  = (datetime.now() - timedelta(days=7)).strftime('%d %b')
            week_end    = datetime.now().strftime('%d %b %Y')

            rows_html = ''
            for r in records:
                color = '#10b981' if r['status']=='safe' else '#f59e0b' if r['status']=='warning' else '#ef4444'
                rows_html += f"""<tr>
                  <td style="padding:10px;border-bottom:1px solid #2a2a3a;">{r['name']}</td>
                  <td style="padding:10px;border-bottom:1px solid #2a2a3a;text-align:center;
                             font-weight:bold;color:{color};">{r['percentage']}%</td>
                  <td style="padding:10px;border-bottom:1px solid #2a2a3a;text-align:center;">
                    {r['attended']}/{r['total']}</td>
                  <td style="padding:10px;border-bottom:1px solid #2a2a3a;text-align:center;
                             color:{color};font-weight:bold;">{r['status'].upper()}</td>
                </tr>"""

            if overall_pct < 60:
                alert = f'<div style="background:#7f1d1d;border-radius:8px;padding:12px;margin-bottom:16px;color:#fca5a5;">⚠️ <strong>Critical:</strong> Your overall attendance is {overall_pct}%. Immediate improvement required.</div>'
            elif overall_pct < 75:
                alert = f'<div style="background:#78350f;border-radius:8px;padding:12px;margin-bottom:16px;color:#fde68a;">⚠️ <strong>Warning:</strong> Your overall attendance is {overall_pct}%. Below the 75% threshold.</div>'
            else:
                alert = f'<div style="background:#064e3b;border-radius:8px;padding:12px;margin-bottom:16px;color:#6ee7b7;">✅ Great job! Your overall attendance is {overall_pct}%.</div>'

            html = f"""<!DOCTYPE html>
            <html><body style="background:#0a0a0f;color:#e8e8f0;font-family:system-ui,sans-serif;margin:0;padding:20px;">
              <div style="max-width:600px;margin:0 auto;background:#13131a;border-radius:12px;border:1px solid #2a2a3a;overflow:hidden;">
                <div style="background:#6366f1;padding:24px;text-align:center;">
                  <h1 style="margin:0;color:#fff;font-size:1.4rem;">📊 Weekly Attendance Report</h1>
                  <p style="margin:6px 0 0;color:#c7d2fe;font-size:.9rem;">{week_start} – {week_end}</p>
                </div>
                <div style="padding:24px;">
                  <p style="margin-top:0;">Hi <strong>{s['name']}</strong> ({s['roll_no']}),</p>
                  {alert}
                  <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
                    <thead><tr style="background:#1a1a24;">
                      <th style="padding:10px;text-align:left;color:#6b7280;font-size:.8rem;">SUBJECT</th>
                      <th style="padding:10px;text-align:center;color:#6b7280;font-size:.8rem;">%</th>
                      <th style="padding:10px;text-align:center;color:#6b7280;font-size:.8rem;">CLASSES</th>
                      <th style="padding:10px;text-align:center;color:#6b7280;font-size:.8rem;">STATUS</th>
                    </tr></thead>
                    <tbody>{rows_html}</tbody>
                  </table>
                  <p style="font-size:.8rem;color:#6b7280;margin-bottom:0;">This is an automated weekly report from your institution's attendance system.</p>
                </div>
              </div>
            </body></html>"""

            ok, _ = _send_email(
                s['email'],
                f"Weekly Attendance Report — {week_start} to {week_end}",
                html)
            if ok: sent += 1
            else:  failed += 1

        set_setting('email_last_sent', datetime.now().strftime('%d %b %Y %H:%M'))
        print(f'[Scheduler] Weekly reports: {sent} sent, {failed} failed.')


scheduler = BackgroundScheduler(daemon=True)

def _reschedule_email_job():
    """Remove the old job and re-add with current settings."""
    if scheduler.get_job('weekly_email'):
        scheduler.remove_job('weekly_email')
    cfg = get_email_schedule()
    if cfg['enabled']:
        scheduler.add_job(
            _auto_send_weekly_reports,
            CronTrigger(day_of_week=cfg['day'], hour=cfg['hour'], minute=cfg['minute']),
            id='weekly_email',
            replace_existing=True,
            misfire_grace_time=3600
        )
        print(f"[Scheduler] Weekly email scheduled: {DAY_NAMES[cfg['day']]} {cfg['hour']:02d}:{cfg['minute']:02d}")
    else:
        print('[Scheduler] Weekly email schedule disabled.')


# Start scheduler once (guard against double-start in debug reloader)
if not scheduler.running:
    scheduler.start()
    _reschedule_email_job()
    atexit.register(lambda: scheduler.shutdown(wait=False))


if __name__ == '__main__':
    ip = get_local_ip()
    cfg = get_email_schedule()
    print("\n" + "="*55)
    print("  QR Attendance System — Industry Edition")
    print("="*55)
    print(f"  Laptop : http://127.0.0.1:5000")
    print(f"  Phones : http://{ip}:5000")
    t = get_teacher()
    if t: print(f"\n  Teacher: {t['name']}")
    else: print(f"\n  First run: visit /teacher to set PIN")
    if cfg['enabled']:
        print(f"  Auto-email: {DAY_NAMES[cfg['day']]}s at {cfg['hour']:02d}:{cfg['minute']:02d}")
    print("="*55 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
