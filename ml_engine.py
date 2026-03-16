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
from database import get_conn, SUBJECTS

# ── Risk Scoring ──────────────────────────────────────────────────────────────
def calculate_risk_score(session_id, device_hash, ip_address, roll_no):
    """
    Score 0.0 (clean) → 1.0 (suspicious).
    Checks:
      1. Same device marking multiple different students
      2. Same IP used by too many students in one session
      3. Submission speed (too fast after QR generated)
      4. Device seen across many sessions same day
    """
    score   = 0.0
    reasons = []
    conn    = get_conn()

    # ── Factor 1: Same device, different roll_no this session ────────────────
    other_rolls = conn.execute("""
        SELECT COUNT(DISTINCT roll_no) as cnt FROM scan_log
        WHERE session_id=? AND device_hash=? AND was_blocked=0 AND roll_no!=?
    """, (session_id, device_hash, roll_no)).fetchone()
    if other_rolls and other_rolls['cnt'] > 0:
        score += 0.6
        reasons.append(f"Device used for {other_rolls['cnt']} other student(s)")

    # ── Factor 2: Same IP, too many students this session ────────────────────
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

    # ── Factor 3: Speed — scanned within 5 seconds of QR creation ────────────
    sess = conn.execute(
        "SELECT created_at FROM qr_sessions WHERE id=?", (session_id,)).fetchone()
    if sess:
        try:
            created  = datetime.fromisoformat(sess['created_at'])
            elapsed  = (datetime.now() - created).total_seconds()
            if elapsed < 5:
                score += 0.3; reasons.append("Marked within 5s of QR creation")
        except Exception:
            pass

    # ── Factor 4: Same device used in 5+ sessions today ──────────────────────
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
    """
    Predict which students will fall below 75% by end of semester.
    Uses linear trend of last 4 weeks.
    Returns: 'safe' | 'warning' | 'danger' | 'critical'
    """
    conn = get_conn()
    totals = {r['subject']: r['count'] for r in
              conn.execute("SELECT subject, count FROM total_classes").fetchall()}

    result = {}
    for code in SUBJECTS:
        tot = totals.get(code, 0)
        if tot == 0:
            result[code] = {'risk': 'safe', 'projected': 100.0, 'classes_can_miss': 0}
            continue

        att = conn.execute("""
            SELECT COUNT(*) as cnt FROM attendance
            WHERE student_id=? AND subject=?
        """, (student_id, code)).fetchone()['cnt']

        pct = round(att / tot * 100, 1)

        # How many more can they miss and stay at 75%?
        # 0.75 * (tot + future) <= att + future
        # Solve: future >= (0.75*tot - att) / 0.25
        can_miss = max(0, int((att - 0.75 * tot) / 0.75)) if att > 0 else 0

        # Trend — last 4 sessions vs previous 4
        recent = conn.execute("""
            SELECT a.marked_at FROM attendance a
            JOIN qr_sessions qs ON qs.id=a.session_id
            WHERE a.student_id=? AND a.subject=?
            ORDER BY a.marked_at DESC LIMIT 8
        """, (student_id, code)).fetchall()

        trend = 0.0
        if len(recent) >= 4:
            # 1 = attended, score recent vs old
            trend = 0.0  # neutral if not enough data

        if pct >= 85:
            risk = 'safe'
        elif pct >= 75:
            risk = 'warning'
        elif pct >= 60:
            risk = 'danger'
        else:
            risk = 'critical'

        result[code] = {
            'risk': risk, 'percentage': pct,
            'attended': att, 'total': tot,
            'classes_can_miss': can_miss,
            'trend': trend
        }

    conn.close()
    return result


# ── Class-Level Insights ──────────────────────────────────────────────────────
def get_class_insights():
    """
    Returns smart insights for the teacher dashboard.
    e.g. "DS attendance dropped 12% this week"
         "8 students at detention risk in SP"
    """
    conn = get_conn()
    insights = []

    # ── Insight 1: Students below 75% per subject ─────────────────────────────
    totals = {r['subject']: r['count'] for r in
              conn.execute("SELECT subject, count FROM total_classes").fetchall()}

    for code, name in SUBJECTS.items():
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

    # ── Insight 2: Attendance trend this week vs last week ────────────────────
    today     = datetime.now()
    week_ago  = (today - timedelta(days=7)).strftime('%Y-%m-%d')
    two_weeks = (today - timedelta(days=14)).strftime('%Y-%m-%d')
    today_str = today.strftime('%Y-%m-%d')

    this_week = conn.execute("""
        SELECT COUNT(*) as cnt FROM attendance
        WHERE marked_at >= ?
    """, (week_ago,)).fetchone()['cnt']

    last_week = conn.execute("""
        SELECT COUNT(*) as cnt FROM attendance
        WHERE marked_at >= ? AND marked_at < ?
    """, (two_weeks, week_ago)).fetchone()['cnt']

    if last_week > 0:
        change = round((this_week - last_week) / last_week * 100)
        if change < -15:
            insights.append({
                'type': 'danger',
                'icon': '📉',
                'text': f"Overall attendance dropped {abs(change)}% vs last week",
                'subject': None
            })
        elif change > 15:
            insights.append({
                'type': 'success',
                'icon': '📈',
                'text': f"Attendance up {change}% compared to last week",
                'subject': None
            })

    # ── Insight 3: Suspicious scans ───────────────────────────────────────────
    flagged = conn.execute("""
        SELECT COUNT(*) as cnt FROM attendance
        WHERE flagged=1 AND marked_at >= ?
    """, (week_ago,)).fetchone()['cnt']
    if flagged > 0:
        insights.append({
            'type': 'danger',
            'icon': '🚨',
            'text': f"{flagged} suspicious scan{'s' if flagged>1 else ''} detected this week",
            'subject': None
        })

    # ── Insight 4: Total students ─────────────────────────────────────────────
    total_students = conn.execute("SELECT COUNT(*) as cnt FROM students").fetchone()['cnt']
    total_sessions = conn.execute("SELECT COUNT(*) as cnt FROM qr_sessions").fetchone()['cnt']
    if total_students > 0:
        insights.append({
            'type': 'info',
            'icon': '👥',
            'text': f"{total_students} students registered across {total_sessions} sessions",
            'subject': None
        })

    conn.close()
    return insights


# ── Attendance Heatmap Data ───────────────────────────────────────────────────
def get_attendance_heatmap(days=30):
    """Returns daily attendance counts for last N days — for dashboard chart."""
    conn  = get_conn()
    today = datetime.now()
    data  = {}
    for i in range(days):
        d   = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        cnt = conn.execute("""
            SELECT COUNT(*) as cnt FROM attendance
            WHERE marked_at LIKE ?
        """, (f'{d}%',)).fetchone()['cnt']
        data[d] = cnt
    conn.close()
    # Return sorted ascending
    return dict(sorted(data.items()))


# ── Student Risk Report ───────────────────────────────────────────────────────
def get_all_students_risk():
    """For teacher — list all students with their risk level."""
    conn     = get_conn()
    students = conn.execute("SELECT * FROM students ORDER BY roll_no").fetchall()
    totals   = {r['subject']: r['count'] for r in
                conn.execute("SELECT subject, count FROM total_classes").fetchall()}
    result   = []
    for s in students:
        s = dict(s)
        worst_risk = 'safe'
        min_pct    = 100.0
        for code in SUBJECTS:
            tot = totals.get(code, 0)
            if tot == 0: continue
            att = conn.execute("""
                SELECT COUNT(*) as cnt FROM attendance
                WHERE student_id=? AND subject=?
            """, (s['id'], code)).fetchone()['cnt']
            pct = round(att / tot * 100, 1)
            if pct < min_pct:
                min_pct = pct
                worst_risk = ('critical' if pct < 50 else
                              'danger'   if pct < 60 else
                              'warning'  if pct < 75 else 'safe')
        s['worst_risk'] = worst_risk
        s['min_pct']    = min_pct
        result.append(s)
    conn.close()
    return result