"""
ml_engine.py — AI/ML Analytics Engine
Pure Python statistics — no heavy libraries needed.
Features:
  - Real-time risk scoring per scan
  - Detention risk prediction
  - Attendance trend analysis
  - Smart anomaly detection
  - Class-level insights
"""
from datetime import datetime, timedelta
from database import get_conn, get_all_subjects

# ── Risk Scoring ──────────────────────────────────────────────────────────────
def calculate_risk_score(session_id, device_hash, ip_address, roll_no):
    score   = 0.0
    reasons = []
    conn    = get_conn()

    other_rolls = conn.execute("""
        SELECT COUNT(DISTINCT roll_no) as cnt FROM scan_log
        WHERE session_id=? AND device_hash=? AND was_blocked=0 AND roll_no!=?
    """, (session_id, device_hash, roll_no)).fetchone()
    if other_rolls and other_rolls['cnt'] > 0:
        score += 0.6
        reasons.append(f"Device used for {other_rolls['cnt']} other student(s)")

    ip_count = conn.execute("""
        SELECT COUNT(DISTINCT roll_no) as cnt FROM scan_log
        WHERE session_id=? AND ip_address=? AND was_blocked=0
    """, (session_id, ip_address)).fetchone()
    if ip_count:
        n = ip_count['cnt']
        if n > 10:
            score += 0.5; reasons.append(f"IP shared by {n} students (hotspot?)")
        elif n > 5:
            score += 0.2; reasons.append(f"IP shared by {n} students")

    sess = conn.execute(
        "SELECT created_at FROM qr_sessions WHERE id=?", (session_id,)).fetchone()
    if sess:
        try:
            created = datetime.fromisoformat(sess['created_at'])
            elapsed = (datetime.now() - created).total_seconds()
            if elapsed < 5:
                score += 0.3; reasons.append("Marked within 5s of QR creation")
        except Exception:
            pass

    today = datetime.now().strftime('%Y-%m-%d')
    day_count = conn.execute("""
        SELECT COUNT(DISTINCT session_id) as cnt FROM scan_log
        WHERE device_hash=? AND scanned_at LIKE ? AND was_blocked=0
    """, (device_hash, f'{today}%')).fetchone()
    if day_count and day_count['cnt'] > 5:
        score += 0.2; reasons.append(f"Device in {day_count['cnt']} sessions today")

    conn.close()
    return min(score, 1.0), '; '.join(reasons)


# ── Detention Risk Prediction ─────────────────────────────────────────────────
def predict_detention_risk(student_id):
    conn    = get_conn()
    subjects = get_all_subjects()
    totals  = {r['subject']: r['count'] for r in
               conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    result  = {}
    for code in subjects:
        tot = totals.get(code, 0)
        if tot == 0:
            result[code] = {'risk': 'safe', 'projected': 100.0, 'classes_can_miss': 0}
            continue

        att = conn.execute("""
            SELECT COUNT(*) as cnt FROM attendance
            WHERE student_id=? AND subject=?
        """, (student_id, code)).fetchone()['cnt']

        pct      = round(att / tot * 100, 1)
        can_miss = max(0, int((att - 0.75 * tot) / 0.75)) if att > 0 else 0

        if pct >= 85:   risk = 'safe'
        elif pct >= 75: risk = 'warning'
        elif pct >= 60: risk = 'danger'
        else:           risk = 'critical'

        result[code] = {
            'risk': risk, 'percentage': pct,
            'attended': att, 'total': tot,
            'classes_can_miss': can_miss,
        }
    conn.close()
    return result


# ── Class-Level Insights ──────────────────────────────────────────────────────
def get_class_insights():
    conn     = get_conn()
    subjects = get_all_subjects()
    insights = []

    totals = {r['subject']: r['count'] for r in
              conn.execute("SELECT subject, count FROM total_classes").fetchall()}

    for code, name in subjects.items():
        tot = totals.get(code, 0)
        if tot == 0: continue
        at_risk = conn.execute("""
            SELECT COUNT(*) as cnt FROM (
                SELECT student_id,
                       ROUND(COUNT(*) * 100.0 / ?, 1) as pct
                FROM attendance WHERE subject=?
                GROUP BY student_id
                HAVING pct < 75
            )
        """, (tot, code)).fetchone()['cnt']
        if at_risk > 0:
            insights.append({
                'type': 'warning',
                'icon': '⚠️',
                'text': f"{at_risk} student{'s' if at_risk>1 else ''} below 75% in {name}",
                'subject': code
            })

    today     = datetime.now()
    week_ago  = (today - timedelta(days=7)).strftime('%Y-%m-%d')
    two_weeks = (today - timedelta(days=14)).strftime('%Y-%m-%d')

    this_week = conn.execute("""
        SELECT COUNT(*) as cnt FROM attendance WHERE marked_at >= ?
    """, (week_ago,)).fetchone()['cnt']
    last_week = conn.execute("""
        SELECT COUNT(*) as cnt FROM attendance
        WHERE marked_at >= ? AND marked_at < ?
    """, (two_weeks, week_ago)).fetchone()['cnt']

    if last_week > 0:
        change = round((this_week - last_week) / last_week * 100)
        if change < -15:
            insights.append({'type':'danger','icon':'📉',
                'text':f"Overall attendance dropped {abs(change)}% vs last week",'subject':None})
        elif change > 15:
            insights.append({'type':'success','icon':'📈',
                'text':f"Attendance up {change}% compared to last week",'subject':None})

    flagged = conn.execute("""
        SELECT COUNT(*) as cnt FROM attendance
        WHERE flagged=1 AND marked_at >= ?
    """, (week_ago,)).fetchone()['cnt']
    if flagged > 0:
        insights.append({'type':'danger','icon':'🚨',
            'text':f"{flagged} suspicious scan{'s' if flagged>1 else ''} detected this week",
            'subject':None})

    total_students = conn.execute("SELECT COUNT(*) as cnt FROM students").fetchone()['cnt']
    total_sessions = conn.execute("SELECT COUNT(*) as cnt FROM qr_sessions").fetchone()['cnt']
    if total_students > 0:
        insights.append({'type':'info','icon':'👥',
            'text':f"{total_students} students registered across {total_sessions} sessions",
            'subject':None})

    conn.close()
    return insights


# ── Attendance Heatmap Data ───────────────────────────────────────────────────
def get_attendance_heatmap(days=30):
    conn  = get_conn()
    today = datetime.now()
    data  = {}
    for i in range(days):
        d   = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        cnt = conn.execute("""
            SELECT COUNT(*) as cnt FROM attendance WHERE marked_at LIKE ?
        """, (f'{d}%',)).fetchone()['cnt']
        data[d] = cnt
    conn.close()
    return dict(sorted(data.items()))


# ── Student Risk Report ───────────────────────────────────────────────────────
def get_all_students_risk():
    conn     = get_conn()
    subjects = get_all_subjects()
    students = conn.execute("SELECT * FROM students ORDER BY roll_no").fetchall()
    totals   = {r['subject']: r['count'] for r in
                conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    result   = []
    for s in students:
        s = dict(s)
        worst_risk = 'safe'
        min_pct    = 100.0
        for code in subjects:
            tot = totals.get(code, 0)
            if tot == 0: continue
            att = conn.execute("""
                SELECT COUNT(*) as cnt FROM attendance
                WHERE student_id=? AND subject=?
            """, (s['id'], code)).fetchone()['cnt']
            pct = round(att / tot * 100, 1)
            if pct < min_pct:
                min_pct    = pct
                worst_risk = ('critical' if pct < 50 else
                              'danger'   if pct < 60 else
                              'warning'  if pct < 75 else 'safe')
        s['worst_risk'] = worst_risk
        s['min_pct']    = min_pct
        result.append(s)
    conn.close()
    return result
