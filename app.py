"""
Phishing Awareness Training Platform & Simulation Tool
------------------------------------------------------
Flask + SQLite. Educational use only, with management approval.

Ethics by design:
  * NO credentials are ever collected - only the click event is logged.
  * Results are for education, not punishment.
  * Admin area is protected by login + CSRF protection.

Run:    python app.py            -> http://127.0.0.1:5000
Demo:   python app.py seed       -> adds demo users/templates/campaign data
"""
import csv
import io
import os
import re
import secrets
import smtplib
import sqlite3
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
KEY_PATH = os.path.join(BASE_DIR, ".secret_key")

# ----------------------------------------------------------------- config
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
SMTP_HOST = os.environ.get("SMTP_HOST", "")          # empty = dry-run mode
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TLS = os.environ.get("SMTP_TLS", "1") == "1"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{10,64}$")


def get_secret_key():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_PATH) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(SECRET_KEY=get_secret_key(),
                  SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax")

# --------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS admins(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    department TEXT DEFAULT 'General',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS email_templates(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT DEFAULT 'General',
    sender_name TEXT NOT NULL,
    sender_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    red_flags TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS campaigns(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    template_id INTEGER NOT NULL REFERENCES email_templates(id),
    status TEXT DEFAULT 'draft',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    launched_at TEXT);
CREATE TABLE IF NOT EXISTS targets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    send_status TEXT DEFAULT 'pending',
    sent_at TEXT);
CREATE TABLE IF NOT EXISTS clicks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    clicked_at TEXT DEFAULT CURRENT_TIMESTAMP,
    ip TEXT, user_agent TEXT);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if not db.execute("SELECT 1 FROM admins").fetchone():
        db.execute("INSERT INTO admins(username, password_hash) VALUES(?,?)",
                   (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD)))
    db.commit()
    db.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------- security helpers
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token")


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def clean(text, limit=200):
    return (text or "").strip()[:limit]


# ---------------------------------------------------------- risk analytics
def risk_level(score):
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def user_risk_rows(db, user_id=None):
    """Vulnerability score per employee = clicked campaigns / received * 100."""
    sql = """
    SELECT u.id, u.name, u.email, u.department,
           COUNT(CASE WHEN t.send_status IN ('sent','dry-run') THEN 1 END) AS received,
           COUNT(DISTINCT CASE WHEN c.id IS NOT NULL THEN t.id END) AS clicked
    FROM users u
    LEFT JOIN targets t ON t.user_id = u.id
    LEFT JOIN clicks c ON c.target_id = t.id
    {where}
    GROUP BY u.id ORDER BY u.name"""
    where, args = ("WHERE u.id = ?", (user_id,)) if user_id else ("", ())
    rows = []
    for r in db.execute(sql.format(where=where), args):
        d = dict(r)
        d["score"] = round(100 * d["clicked"] / d["received"]) if d["received"] else 0
        d["level"] = risk_level(d["score"]) if d["received"] else "N/A"
        rows.append(d)
    return rows


def campaign_stats(db, campaign_id=None):
    sql = """
    SELECT ca.id, ca.name, ca.status, ca.launched_at, ca.created_at, et.name AS template,
           COUNT(CASE WHEN t.send_status IN ('sent','dry-run') THEN 1 END) AS sent,
           COUNT(DISTINCT CASE WHEN c.id IS NOT NULL THEN t.id END) AS clicked,
           COUNT(t.id) AS targets
    FROM campaigns ca
    JOIN email_templates et ON et.id = ca.template_id
    LEFT JOIN targets t ON t.campaign_id = ca.id
    LEFT JOIN clicks c ON c.target_id = t.id
    {where}
    GROUP BY ca.id ORDER BY ca.id"""
    where, args = ("WHERE ca.id = ?", (campaign_id,)) if campaign_id else ("", ())
    rows = []
    for r in db.execute(sql.format(where=where), args):
        d = dict(r)
        d["rate"] = round(100 * d["clicked"] / d["sent"]) if d["sent"] else 0
        rows.append(d)
    return rows


# --------------------------------------------------------------- emailing
def render_body(body, name, link):
    return body.replace("{{NAME}}", name).replace("{{LINK}}", link)


def send_email(to_addr, sender_name, sender_email, subject, html):
    """Returns 'sent' (real SMTP) or 'dry-run' (SMTP_HOST not configured)."""
    if not SMTP_HOST:
        return "dry-run"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = to_addr
    msg["X-Simulation"] = "Phishing-Awareness-Training"
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
        if SMTP_TLS:
            s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(sender_email, [to_addr], msg.as_string())
    return "sent"


# ------------------------------------------------------------------ routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        row = get_db().execute("SELECT * FROM admins WHERE username=?",
                               (clean(request.form.get("username"), 50),)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            session.clear()
            session["admin"] = row["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    stats = campaign_stats(db)
    sent = sum(c["sent"] for c in stats)
    clicked = sum(c["clicked"] for c in stats)
    risks = [r for r in user_risk_rows(db) if r["received"]]
    top = sorted(risks, key=lambda r: (-r["score"], r["name"]))[:5]
    summary = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "campaigns": len(stats),
        "sent": sent,
        "click_rate": round(100 * clicked / sent) if sent else 0,
        "avg_risk": round(sum(r["score"] for r in risks) / len(risks)) if risks else 0,
    }
    return render_template("dashboard.html", summary=summary, stats=stats, top=top)


# ---- users
@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name, email = clean(request.form.get("name"), 100), clean(request.form.get("email"), 120).lower()
            dept = clean(request.form.get("department"), 60) or "General"
            if not name or not EMAIL_RE.match(email):
                flash("Enter a valid name and email.", "error")
            else:
                try:
                    db.execute("INSERT INTO users(name,email,department) VALUES(?,?,?)", (name, email, dept))
                    db.commit()
                    flash(f"Added {name}.", "success")
                except sqlite3.IntegrityError:
                    flash("That email already exists.", "error")
        elif action == "import":
            f = request.files.get("csv_file")
            if not f or not f.filename.lower().endswith(".csv"):
                flash("Please upload a .csv file (columns: name,email,department).", "error")
            else:
                added = skipped = 0
                reader = csv.DictReader(io.StringIO(f.read().decode("utf-8-sig", "ignore")))
                for row in reader:
                    row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
                    name, email = row.get("name", "")[:100], row.get("email", "").lower()[:120]
                    if not name or not EMAIL_RE.match(email):
                        skipped += 1
                        continue
                    try:
                        db.execute("INSERT INTO users(name,email,department) VALUES(?,?,?)",
                                   (name, email, row.get("department", "General")[:60] or "General"))
                        added += 1
                    except sqlite3.IntegrityError:
                        skipped += 1
                db.commit()
                flash(f"Imported {added} users, skipped {skipped}.", "success")
        elif action == "delete":
            db.execute("DELETE FROM users WHERE id=?", (request.form.get("user_id", type=int),))
            db.commit()
            flash("User removed.", "success")
        return redirect(url_for("users"))
    return render_template("users.html", rows=user_risk_rows(db))


@app.route("/users/<int:user_id>")
@login_required
def user_history(user_id):
    db = get_db()
    rows = user_risk_rows(db, user_id)
    if not rows:
        abort(404)
    history = db.execute("""
        SELECT ca.name AS campaign, et.name AS template, t.send_status, t.sent_at,
               MIN(c.clicked_at) AS clicked_at
        FROM targets t JOIN campaigns ca ON ca.id=t.campaign_id
        JOIN email_templates et ON et.id=ca.template_id
        LEFT JOIN clicks c ON c.target_id=t.id
        WHERE t.user_id=? GROUP BY t.id ORDER BY ca.id""", (user_id,)).fetchall()
    return render_template("user_history.html", u=rows[0], history=history)


# ---- email templates
@app.route("/templates", methods=["GET", "POST"])
@login_required
def phishing_templates():
    db = get_db()
    if request.method == "POST":
        if request.form.get("action") == "delete":
            try:
                db.execute("DELETE FROM email_templates WHERE id=?", (request.form.get("template_id", type=int),))
                db.commit()
                flash("Template deleted.", "success")
            except sqlite3.IntegrityError:
                flash("Template is used by a campaign and cannot be deleted.", "error")
            return redirect(url_for("phishing_templates"))
        f = {k: clean(request.form.get(k), 5000 if k in ("body", "red_flags") else 200)
             for k in ("name", "category", "sender_name", "sender_email", "subject", "body", "red_flags")}
        if not all(f[k] for k in ("name", "sender_name", "sender_email", "subject", "body")):
            flash("Name, sender, subject and body are required.", "error")
        elif "{{LINK}}" not in f["body"]:
            flash("The body must contain {{LINK}} where the tracking link should go.", "error")
        else:
            db.execute("""INSERT INTO email_templates(name,category,sender_name,sender_email,subject,body,red_flags)
                          VALUES(:name,:category,:sender_name,:sender_email,:subject,:body,:red_flags)""", f)
            db.commit()
            flash("Template saved.", "success")
        return redirect(url_for("phishing_templates"))
    rows = db.execute("SELECT * FROM email_templates ORDER BY id DESC").fetchall()
    return render_template("phishing_template.html", rows=rows)


# ---- campaigns
@app.route("/campaigns")
@login_required
def campaigns():
    return render_template("campaigns.html", rows=campaign_stats(get_db()))


@app.route("/campaigns/create", methods=["GET", "POST"])
@login_required
def create_campaign():
    db = get_db()
    tpls = db.execute("SELECT id,name,category FROM email_templates ORDER BY name").fetchall()
    people = db.execute("SELECT * FROM users ORDER BY department, name").fetchall()
    if request.method == "POST":
        name = clean(request.form.get("name"), 120)
        tid = request.form.get("template_id", type=int)
        picked = [int(x) for x in request.form.getlist("user_ids") if x.isdigit()]
        if not name or not tid or not picked:
            flash("Give the campaign a name, a template and at least one target.", "error")
            return render_template("create_campaign.html", tpls=tpls, people=people)
        cur = db.execute("INSERT INTO campaigns(name,template_id) VALUES(?,?)", (name, tid))
        cid = cur.lastrowid
        for uid in picked:
            db.execute("INSERT INTO targets(campaign_id,user_id,token) VALUES(?,?,?)",
                       (cid, uid, secrets.token_urlsafe(16)))
        db.commit()
        flash("Campaign created. Review it, then launch.", "success")
        return redirect(url_for("campaign_detail", cid=cid))
    return render_template("create_campaign.html", tpls=tpls, people=people)


@app.route("/campaigns/<int:cid>")
@login_required
def campaign_detail(cid):
    db = get_db()
    stats = campaign_stats(db, cid)
    if not stats:
        abort(404)
    tpl = db.execute("""SELECT et.* FROM email_templates et JOIN campaigns ca
                        ON ca.template_id=et.id WHERE ca.id=?""", (cid,)).fetchone()
    targets = db.execute("""
        SELECT t.*, u.name, u.email, u.department, MIN(c.clicked_at) AS clicked_at
        FROM targets t JOIN users u ON u.id=t.user_id
        LEFT JOIN clicks c ON c.target_id=t.id
        WHERE t.campaign_id=? GROUP BY t.id ORDER BY u.name""", (cid,)).fetchall()
    return render_template("campaign_detail.html", c=stats[0], tpl=tpl,
                           targets=targets, base_url=BASE_URL, dry=not SMTP_HOST)


@app.route("/campaigns/<int:cid>/launch", methods=["POST"])
@login_required
def launch_campaign(cid):
    db = get_db()
    tpl = db.execute("""SELECT et.* FROM email_templates et JOIN campaigns ca
                        ON ca.template_id=et.id WHERE ca.id=?""", (cid,)).fetchone()
    if not tpl:
        abort(404)
    ok = fail = 0
    rows = db.execute("""SELECT t.id, t.token, u.name, u.email FROM targets t
                         JOIN users u ON u.id=t.user_id
                         WHERE t.campaign_id=? AND t.send_status IN ('pending','failed')""", (cid,)).fetchall()
    for t in rows:
        link = f"{BASE_URL}/t/{t['token']}"
        try:
            status = send_email(t["email"], tpl["sender_name"], tpl["sender_email"],
                                tpl["subject"], render_body(tpl["body"], t["name"], link))
            db.execute("UPDATE targets SET send_status=?, sent_at=? WHERE id=?", (status, now(), t["id"]))
            ok += 1
        except Exception as exc:                       # SMTP problems must not crash launch
            app.logger.warning("send failed for %s: %s", t["email"], exc)
            db.execute("UPDATE targets SET send_status='failed' WHERE id=?", (t["id"],))
            fail += 1
    db.execute("UPDATE campaigns SET status='active', launched_at=COALESCE(launched_at,?) WHERE id=?", (now(), cid))
    db.commit()
    mode = "(dry-run: no real email sent; use the tracking links below)" if not SMTP_HOST else ""
    flash(f"Launched: {ok} sent, {fail} failed. {mode}", "success" if not fail else "error")
    return redirect(url_for("campaign_detail", cid=cid))


@app.route("/campaigns/<int:cid>/delete", methods=["POST"])
@login_required
def delete_campaign(cid):
    db = get_db()
    db.execute("DELETE FROM campaigns WHERE id=?", (cid,))
    db.commit()
    flash("Campaign deleted.", "success")
    return redirect(url_for("campaigns"))


# ---- tracking + awareness page (PUBLIC - this is what employees see)
@app.route("/t/<token>")
def track(token):
    if not TOKEN_RE.match(token):
        abort(404)
    db = get_db()
    t = db.execute("""SELECT t.id, et.name AS template, et.red_flags, u.name
                      FROM targets t JOIN campaigns ca ON ca.id=t.campaign_id
                      JOIN email_templates et ON et.id=ca.template_id
                      JOIN users u ON u.id=t.user_id WHERE t.token=?""", (token,)).fetchone()
    if not t:
        abort(404)
    # Only the click itself is stored. Nothing is typed or captured.
    db.execute("INSERT INTO clicks(target_id,ip,user_agent) VALUES(?,?,?)",
               (t["id"], request.remote_addr, (request.headers.get("User-Agent") or "")[:300]))
    db.commit()
    flags = [x.strip() for x in (t["red_flags"] or "").splitlines() if x.strip()]
    return render_template("landing.html", name=t["name"].split()[0], template=t["template"], flags=flags)


# ---- reports
@app.route("/report")
@login_required
def report():
    db = get_db()
    return render_template("report.html", stats=campaign_stats(db), risks=user_risk_rows(db),
                           depts=dept_rows(db))


def dept_rows(db):
    agg = {}
    for r in user_risk_rows(db):
        d = agg.setdefault(r["department"], {"department": r["department"], "received": 0, "clicked": 0, "users": 0})
        d["received"] += r["received"]
        d["clicked"] += r["clicked"]
        d["users"] += 1
    out = []
    for d in agg.values():
        d["rate"] = round(100 * d["clicked"] / d["received"]) if d["received"] else 0
        out.append(d)
    return sorted(out, key=lambda d: -d["rate"])


@app.route("/report.csv")
@login_required
def report_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "email", "department", "emails_received", "clicked", "risk_score_percent", "risk_level"])
    for r in user_risk_rows(get_db()):
        w.writerow([r["name"], r["email"], r["department"], r["received"], r["clicked"], r["score"], r["level"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=risk_report.csv"})


# -------------------------------------------------------------- demo data
DEMO_TEMPLATES = [
    ("Password Reset Alert", "Credentials", "IT Support", "it-support@company-helpdesk.co",
     "Action required: your password expires today",
     "<p>Hi {{NAME}},</p><p>Your account password will expire in <b>2 hours</b>. "
     "To avoid losing access, verify your account immediately:</p>"
     "<p><a href='{{LINK}}'>https://company-login.secure-verify.co/reset</a></p>"
     "<p>IT Support Team</p>",
     "Urgent deadline created to make you panic (\"expires in 2 hours\")\n"
     "Sender domain 'company-helpdesk.co' is not your real company domain\n"
     "The link text does not match the real destination (hover to check)\n"
     "Generic greeting and threat of losing access"),
    ("Pending Invoice", "Finance", "Accounts Dept", "billing@invoices-portal.net",
     "Invoice #88213 overdue - immediate payment needed",
     "<p>Dear {{NAME}},</p><p>Invoice #88213 is overdue. View the attached invoice here: "
     "<a href='{{LINK}}'>Download Invoice</a></p><p>Accounts Receivable</p>",
     "You were not expecting an invoice\nUnknown sender and external domain\n"
     "Pressure about payment being overdue\nInvoices are not normally shared via a bare link"),
    ("Prize / Gift Card", "Reward", "HR Rewards", "rewards@hr-bonus-center.com",
     "You've been selected for a Rs. 5,000 gift card!",
     "<p>Congratulations {{NAME}}!</p><p>Claim your employee reward before midnight: "
     "<a href='{{LINK}}'>Claim now</a></p>",
     "Too good to be true - unexpected reward\nFake urgency (\"before midnight\")\n"
     "HR does not send rewards from outside domains"),
]


def seed_demo():
    import random
    init_db()
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    if db.execute("SELECT 1 FROM users").fetchone():
        print("Database already has data - skipping seed.")
        return
    for t in DEMO_TEMPLATES:
        db.execute("""INSERT INTO email_templates(name,category,sender_name,sender_email,subject,body,red_flags)
                      VALUES(?,?,?,?,?,?,?)""", t)
    names = ["Rahul Sharma", "Priya Verma", "Amit Singh", "Neha Gupta", "Karan Mishra", "Sneha Yadav",
             "Vikas Tiwari", "Anjali Dubey", "Rohit Kumar", "Pooja Patel", "Manish Shukla", "Ritu Agarwal"]
    depts = ["IT", "Finance", "HR", "Sales"]
    for i, n in enumerate(names):
        db.execute("INSERT INTO users(name,email,department) VALUES(?,?,?)",
                   (n, n.lower().replace(" ", ".") + "@example.com", depts[i % 4]))
    random.seed(7)
    # click probability falls campaign by campaign = learning effect
    for idx, p in enumerate([0.60, 0.40, 0.20], start=1):
        cur = db.execute("INSERT INTO campaigns(name,template_id,status,created_at,launched_at) VALUES(?,?,?,?,?)",
                         (f"Campaign {idx}: {DEMO_TEMPLATES[idx-1][0]}", idx, "active",
                          f"2026-0{idx+6}-01 09:00:00", f"2026-0{idx+6}-01 10:00:00"))
        for uid in range(1, len(names) + 1):
            tc = db.execute("INSERT INTO targets(campaign_id,user_id,token,send_status,sent_at) VALUES(?,?,?,?,?)",
                            (cur.lastrowid, uid, secrets.token_urlsafe(16), "dry-run", f"2026-0{idx+6}-01 10:00:00"))
            if random.random() < p:
                db.execute("INSERT INTO clicks(target_id,clicked_at,ip,user_agent) VALUES(?,?,?,?)",
                           (tc.lastrowid, f"2026-0{idx+6}-01 1{random.randint(0,9)}:{random.randint(10,59)}:00",
                            "10.0.0.%d" % uid, "demo-seed"))
    db.commit()
    db.close()
    print("Demo data added: 12 users, 3 templates, 3 campaigns with click history.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        seed_demo()
    else:
        init_db()
        print(f"\n  Admin login -> user: {ADMIN_USER}  password: {ADMIN_PASSWORD}  (change via ADMIN_PASSWORD env var)")
        print(f"  Email mode  -> {'SMTP ' + SMTP_HOST if SMTP_HOST else 'DRY-RUN (no real emails; set SMTP_HOST to send)'}\n")
        app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
