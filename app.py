"""
Phishing Awareness Training Platform & Simulation Tool
Flask + SQLite. Educational use only, with management approval.
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

from flask import (
    Flask, Response, abort, flash, g, redirect,
    render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Vercel's /tmp directory is writable but temporary.
DB_PATH = (
    os.path.join("/tmp", "database.db")
    if os.environ.get("VERCEL") == "1"
    else os.path.join(BASE_DIR, "database.db")
)

KEY_PATH = os.path.join(BASE_DIR, ".secret_key")

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TLS = os.environ.get("SMTP_TLS", "1") == "1"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{10,64}$")


def get_secret_key():
    """Get a stable secret from the environment or local development file."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key

    try:
        if os.path.exists(KEY_PATH):
            with open(KEY_PATH, "r", encoding="utf-8") as file:
                key = file.read().strip()
                if key:
                    return key

        key = secrets.token_hex(32)
        with open(KEY_PATH, "w", encoding="utf-8") as file:
            file.write(key)
        return key

    except OSError:
        # Configure SECRET_KEY in Vercel for stable sessions.
        return secrets.token_hex(32)


app = Flask(__name__)
app.config.update(
    SECRET_KEY=get_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ---------------------------------------------------------------
# Database
# ---------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    department TEXT DEFAULT 'General',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS email_templates(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT DEFAULT 'General',
    sender_name TEXT NOT NULL,
    sender_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    red_flags TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campaigns(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    template_id INTEGER NOT NULL REFERENCES email_templates(id),
    status TEXT DEFAULT 'draft',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    launched_at TEXT
);

CREATE TABLE IF NOT EXISTS targets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    send_status TEXT DEFAULT 'pending',
    sent_at TEXT
);

CREATE TABLE IF NOT EXISTS clicks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    clicked_at TEXT DEFAULT CURRENT_TIMESTAMP,
    ip TEXT,
    user_agent TEXT
);
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
        db.execute(
            "INSERT INTO admins(username, password_hash) VALUES(?, ?)",
            (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD)),
        )

    db.commit()
    db.close()


# Initialize the database for Vercel.
# Note: /tmp storage is temporary and not shared reliably between instances.
if os.environ.get("VERCEL") == "1":
    init_db()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")

        if not sent or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def clean(text, limit=200):
    return (text or "").strip()[:limit]


# ---------------------------------------------------------------
# Risk analytics
# ---------------------------------------------------------------

def risk_level(score):
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def user_risk_rows(db, user_id=None):
    """Calculate employee click rate for received simulations."""
    sql = """
    SELECT u.id, u.name, u.email, u.department,
           COUNT(
               CASE WHEN t.send_status IN ('sent', 'dry-run')
               THEN 1 END
           ) AS received,
           COUNT(
               DISTINCT CASE WHEN c.id IS NOT NULL
               THEN t.id END
           ) AS clicked
    FROM users u
    LEFT JOIN targets t ON t.user_id = u.id
    LEFT JOIN clicks c ON c.target_id = t.id
    {where}
    GROUP BY u.id
    ORDER BY u.name
    """

    where, args = (
        ("WHERE u.id = ?", (user_id,))
        if user_id
        else ("", ())
    )

    rows = []

    for row in db.execute(sql.format(where=where), args):
        data = dict(row)
        data["score"] = (
            round(100 * data["clicked"] / data["received"])
            if data["received"]
            else 0
        )
        data["level"] = (
            risk_level(data["score"])
            if data["received"]
            else "N/A"
        )
        rows.append(data)

    return rows


def campaign_stats(db, campaign_id=None):
    sql = """
    SELECT ca.id, ca.name, ca.status, ca.launched_at, ca.created_at,
           et.name AS template,
           COUNT(
               CASE WHEN t.send_status IN ('sent', 'dry-run')
               THEN 1 END
           ) AS sent,
           COUNT(
               DISTINCT CASE WHEN c.id IS NOT NULL
               THEN t.id END
           ) AS clicked,
           COUNT(t.id) AS targets
    FROM campaigns ca
    JOIN email_templates et ON et.id = ca.template_id
    LEFT JOIN targets t ON t.campaign_id = ca.id
    LEFT JOIN clicks c ON c.target_id = t.id
    {where}
    GROUP BY ca.id
    ORDER BY ca.id
    """

    where, args = (
        ("WHERE ca.id = ?", (campaign_id,))
        if campaign_id
        else ("", ())
    )

    rows = []

    for row in db.execute(sql.format(where=where), args):
        data = dict(row)
        data["rate"] = (
            round(100 * data["clicked"] / data["sent"])
            if data["sent"]
            else 0
        )
        rows.append(data)

    return rows


# ---------------------------------------------------------------
# Emailing
# ---------------------------------------------------------------

def render_body(body, name, link):
    return body.replace("{{NAME}}", name).replace("{{LINK}}", link)


def send_email(to_addr, sender_name, sender_email, subject, html):
    """Return dry-run when SMTP is not configured."""
    if not SMTP_HOST:
        return "dry-run"

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = f"{sender_name} <{sender_email}>"
    message["To"] = to_addr
    message["X-Simulation"] = "Phishing-Awareness-Training"
    message.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        if SMTP_TLS:
            server.starttls()
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASS)

        server.sendmail(
            sender_email,
            [to_addr],
            message.as_string(),
        )

    return "sent"


# ---------------------------------------------------------------
# Home and login routes
# ---------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = clean(request.form.get("username"), 50)

        row = get_db().execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,),
        ).fetchone()

        if row and check_password_hash(
            row["password_hash"],
            request.form.get("password", ""),
        ):
            session.clear()
            session["admin"] = row["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    stats = campaign_stats(db)

    sent = sum(campaign["sent"] for campaign in stats)
    clicked = sum(campaign["clicked"] for campaign in stats)

    risks = [
        row for row in user_risk_rows(db)
        if row["received"]
    ]

    top = sorted(
        risks,
        key=lambda row: (-row["score"], row["name"]),
    )[:5]

    summary = {
        "users": db.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0],
        "campaigns": len(stats),
        "sent": sent,
        "click_rate": round(100 * clicked / sent) if sent else 0,
        "avg_risk": (
            round(sum(row["score"] for row in risks) / len(risks))
            if risks
            else 0
        ),
    }

    return render_template(
        "dashboard.html",
        summary=summary,
        stats=stats,
        top=top,
    )


# ---------------------------------------------------------------
# Users
# ---------------------------------------------------------------

@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            name = clean(request.form.get("name"), 100)
            email = clean(request.form.get("email"), 120).lower()
            department = (
                clean(request.form.get("department"), 60)
                or "General"
            )

            if not name or not EMAIL_RE.match(email):
                flash("Enter a valid name and email.", "error")
            else:
                try:
                    db.execute(
                        """
                        INSERT INTO users(name, email, department)
                        VALUES(?, ?, ?)
                        """,
                        (name, email, department),
                    )
                    db.commit()
                    flash(f"Added {name}.", "success")

                except sqlite3.IntegrityError:
                    flash("That email already exists.", "error")

        elif action == "import":
            uploaded_file = request.files.get("csv_file")

            if (
                not uploaded_file
                or not uploaded_file.filename.lower().endswith(".csv")
            ):
                flash(
                    "Please upload a CSV with name,email,department columns.",
                    "error",
                )
            else:
                added = 0
                skipped = 0

                reader = csv.DictReader(
                    io.StringIO(
                        uploaded_file.read().decode(
                            "utf-8-sig", "ignore"
                        )
                    )
                )

                for row in reader:
                    row = {
                        (key or "").strip().lower():
                        (value or "").strip()
                        for key, value in row.items()
                    }

                    name = row.get("name", "")[:100]
                    email = row.get("email", "").lower()[:120]

                    if not name or not EMAIL_RE.match(email):
                        skipped += 1
                        continue

                    try:
                        db.execute(
                            """
                            INSERT INTO users(name, email, department)
                            VALUES(?, ?, ?)
                            """,
                            (
                                name,
                                email,
                                row.get("department", "General")[:60]
                                or "General",
                            ),
                        )
                        added += 1

                    except sqlite3.IntegrityError:
                        skipped += 1

                db.commit()
                flash(
                    f"Imported {added} users, skipped {skipped}.",
                    "success",
                )

        elif action == "delete":
            db.execute(
                "DELETE FROM users WHERE id = ?",
                (request.form.get("user_id", type=int),),
            )
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

    history = db.execute(
        """
        SELECT ca.name AS campaign, et.name AS template,
               t.send_status, t.sent_at,
               MIN(c.clicked_at) AS clicked_at
        FROM targets t
        JOIN campaigns ca ON ca.id = t.campaign_id
        JOIN email_templates et ON et.id = ca.template_id
        LEFT JOIN clicks c ON c.target_id = t.id
        WHERE t.user_id = ?
        GROUP BY t.id
        ORDER BY ca.id
        """,
        (user_id,),
    ).fetchall()

    return render_template(
        "user_history.html",
        u=rows[0],
        history=history,
    )


# ---------------------------------------------------------------
# Email templates
# ---------------------------------------------------------------

@app.route("/templates", methods=["GET", "POST"])
@login_required
def phishing_templates():
    db = get_db()

    if request.method == "POST":
        if request.form.get("action") == "delete":
            try:
                db.execute(
                    "DELETE FROM email_templates WHERE id = ?",
                    (request.form.get("template_id", type=int),),
                )
                db.commit()
                flash("Template deleted.", "success")

            except sqlite3.IntegrityError:
                flash(
                    "Template is used by a campaign and cannot be deleted.",
                    "error",
                )

            return redirect(url_for("phishing_templates"))

        fields = (
            "name",
            "category",
            "sender_name",
            "sender_email",
            "subject",
            "body",
            "red_flags",
        )

        form_data = {
            key: clean(
                request.form.get(key),
                5000 if key in ("body", "red_flags") else 200,
            )
            for key in fields
        }

        if not all(
            form_data[key]
            for key in (
                "name",
                "sender_name",
                "sender_email",
                "subject",
                "body",
            )
        ):
            flash(
                "Name, sender, subject and body are required.",
                "error",
            )

        elif "{{LINK}}" not in form_data["body"]:
            flash(
                "The body must contain {{LINK}} for the tracking link.",
                "error",
            )

        else:
            db.execute(
                """
                INSERT INTO email_templates(
                    name, category, sender_name, sender_email,
                    subject, body, red_flags
                )
                VALUES(
                    :name, :category, :sender_name, :sender_email,
                    :subject, :body, :red_flags
                )
                """,
                form_data,
            )
            db.commit()
            flash("Template saved.", "success")

        return redirect(url_for("phishing_templates"))

    rows = db.execute(
        "SELECT * FROM email_templates ORDER BY id DESC"
    ).fetchall()

    return render_template("phishing_template.html", rows=rows)


# ---------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------

@app.route("/campaigns")
@login_required
def campaigns():
    return render_template(
        "campaigns.html",
        rows=campaign_stats(get_db()),
    )


@app.route("/campaigns/create", methods=["GET", "POST"])
@login_required
def create_campaign():
    db = get_db()

    templates = db.execute(
        "SELECT id, name, category FROM email_templates ORDER BY name"
    ).fetchall()

    people = db.execute(
        "SELECT * FROM users ORDER BY department, name"
    ).fetchall()

    if request.method == "POST":
        name = clean(request.form.get("name"), 120)
        template_id = request.form.get("template_id", type=int)

        picked = [
            int(value)
            for value in request.form.getlist("user_ids")
            if value.isdigit()
        ]

        if not name or not template_id or not picked:
            flash(
                "Give the campaign a name, a template and at least one target.",
                "error",
            )
            return render_template(
                "create_campaign.html",
                tpls=templates,
                people=people,
            )

        cursor = db.execute(
            "INSERT INTO campaigns(name, template_id) VALUES(?, ?)",
            (name, template_id),
        )
        campaign_id = cursor.lastrowid

        for user_id in picked:
            db.execute(
                """
                INSERT INTO targets(campaign_id, user_id, token)
                VALUES(?, ?, ?)
                """,
                (
                    campaign_id,
                    user_id,
                    secrets.token_urlsafe(16),
                ),
            )

        db.commit()
        flash("Campaign created. Review it, then launch.", "success")

        return redirect(
            url_for("campaign_detail", cid=campaign_id)
        )

    return render_template(
        "create_campaign.html",
        tpls=templates,
        people=people,
    )


@app.route("/campaigns/<int:cid>")
@login_required
def campaign_detail(cid):
    db = get_db()
    stats = campaign_stats(db, cid)

    if not stats:
        abort(404)

    template = db.execute(
        """
        SELECT et.*
        FROM email_templates et
        JOIN campaigns ca ON ca.template_id = et.id
        WHERE ca.id = ?
        """,
        (cid,),
    ).fetchone()

    targets = db.execute(
        """
        SELECT t.*, u.name, u.email, u.department,
               MIN(c.clicked_at) AS clicked_at
        FROM targets t
        JOIN users u ON u.id = t.user_id
        LEFT JOIN clicks c ON c.target_id = t.id
        WHERE t.campaign_id = ?
        GROUP BY t.id
        ORDER BY u.name
        """,
        (cid,),
    ).fetchall()

    return render_template(
        "campaign_detail.html",
        c=stats[0],
        tpl=template,
        targets=targets,
        base_url=BASE_URL,
        dry=not SMTP_HOST,
    )


@app.route("/campaigns/<int:cid>/launch", methods=["POST"])
@login_required
def launch_campaign(cid):
    db = get_db()

    template = db.execute(
        """
        SELECT et.*
        FROM email_templates et
        JOIN campaigns ca ON ca.template_id = et.id
        WHERE ca.id = ?
        """,
        (cid,),
    ).fetchone()

    if not template:
        abort(404)

    success_count = 0
    failure_count = 0

    targets = db.execute(
        """
        SELECT t.id, t.token, u.name, u.email
        FROM targets t
        JOIN users u ON u.id = t.user_id
        WHERE t.campaign_id = ?
          AND t.send_status IN ('pending', 'failed')
        """,
        (cid,),
    ).fetchall()

    for target in targets:
        link = f"{BASE_URL}/t/{target['token']}"

        try:
            status = send_email(
                target["email"],
                template["sender_name"],
                template["sender_email"],
                template["subject"],
                render_body(template["body"], target["name"], link),
            )

            db.execute(
                """
                UPDATE targets
                SET send_status = ?, sent_at = ?
                WHERE id = ?
                """,
                (status, now(), target["id"]),
            )
            success_count += 1

        except Exception as exc:
            app.logger.warning(
                "Email send failed for %s: %s",
                target["email"],
                exc,
            )

            db.execute(
                "UPDATE targets SET send_status = 'failed' WHERE id = ?",
                (target["id"],),
            )
            failure_count += 1

    db.execute(
        """
        UPDATE campaigns
        SET status = 'active',
            launched_at = COALESCE(launched_at, ?)
        WHERE id = ?
        """,
        (now(), cid),
    )

    db.commit()

    mode = (
        "(dry-run: no real email sent; use the tracking links below)"
        if not SMTP_HOST
        else ""
    )

    flash(
        f"Launched: {success_count} sent, {failure_count} failed. {mode}",
        "success" if not failure_count else "error",
    )

    return redirect(url_for("campaign_detail", cid=cid))


@app.route("/campaigns/<int:cid>/delete", methods=["POST"])
@login_required
def delete_campaign(cid):
    db = get_db()
    db.execute(
        "DELETE FROM campaigns WHERE id = ?",
        (cid,),
    )
    db.commit()

    flash("Campaign deleted.", "success")
    return redirect(url_for("campaigns"))


# ---------------------------------------------------------------
# Tracking and awareness page
# ---------------------------------------------------------------

@app.route("/t/<token>")
def track(token):
    if not TOKEN_RE.match(token):
        abort(404)

    db = get_db()

    target = db.execute(
        """
        SELECT t.id, et.name AS template, et.red_flags, u.name
        FROM targets t
        JOIN campaigns ca ON ca.id = t.campaign_id
        JOIN email_templates et ON et.id = ca.template_id
        JOIN users u ON u.id = t.user_id
        WHERE t.token = ?
        """,
        (token,),
    ).fetchone()

    if not target:
        abort(404)

    # Record only the click event. Never collect credentials.
    db.execute(
        """
        INSERT INTO clicks(target_id, ip, user_agent)
        VALUES(?, ?, ?)
        """,
        (
            target["id"],
            request.remote_addr,
            (request.headers.get("User-Agent") or "")[:300],
        ),
    )
    db.commit()

    flags = [
        item.strip()
        for item in (target["red_flags"] or "").splitlines()
        if item.strip()
    ]

    first_name = target["name"].split()[0]

    return render_template(
        "landing.html",
        name=first_name,
        template=target["template"],
        flags=flags,
    )


# ---------------------------------------------------------------
# Reports
# ---------------------------------------------------------------

@app.route("/report")
@login_required
def report():
    db = get_db()

    return render_template(
        "report.html",
        stats=campaign_stats(db),
        risks=user_risk_rows(db),
        depts=dept_rows(db),
    )


def dept_rows(db):
    aggregate = {}

    for row in user_risk_rows(db):
        department = row["department"]

        data = aggregate.setdefault(
            department,
            {
                "department": department,
                "received": 0,
                "clicked": 0,
                "users": 0,
            },
        )

        data["received"] += row["received"]
        data["clicked"] += row["clicked"]
        data["users"] += 1

    output = []

    for data in aggregate.values():
        data["rate"] = (
            round(100 * data["clicked"] / data["received"])
            if data["received"]
            else 0
        )
        output.append(data)

    return sorted(output, key=lambda item: -item["rate"])


@app.route("/report.csv")
@login_required
def report_csv():
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(
        [
            "name",
            "email",
            "department",
            "emails_received",
            "clicked",
            "risk_score_percent",
            "risk_level",
        ]
    )

    for row in user_risk_rows(get_db()):
        writer.writerow(
            [
                row["name"],
                row["email"],
                row["department"],
                row["received"],
                row["clicked"],
                row["score"],
                row["level"],
            ]
        )

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=risk_report.csv"
        },
    )


# ---------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------

DEMO_TEMPLATES = [
    (
        "Password Reset Alert",
        "Credentials",
        "IT Support",
        "it-support@company-helpdesk.co",
        "Action required: your password expires today",
        (
            "<p>Hi {{NAME}},</p>"
            "<p>Your account password will expire in <b>2 hours</b>. "
            "To avoid losing access, verify your account immediately:</p>"
            "<p><a href='{{LINK}}'>Review password notice</a></p>"
            "<p>IT Support Team</p>"
        ),
        (
            'Urgent deadline creates panic ("expires in 2 hours")\n'
            "Sender domain is unfamiliar\n"
            "Check the actual destination of links\n"
            "Generic greeting and threat of losing access"
        ),
    ),
    (
        "Pending Invoice",
        "Finance",
        "Accounts Dept",
        "billing@invoices-portal.net",
        "Invoice #88213 overdue - immediate payment needed",
        (
            "<p>Dear {{NAME}},</p>"
            "<p>Invoice #88213 is overdue. View the invoice here: "
            "<a href='{{LINK}}'>Download Invoice</a></p>"
            "<p>Accounts Receivable</p>"
        ),
        (
            "You were not expecting an invoice\n"
            "Unknown sender and external domain\n"
            "Pressure about an overdue payment\n"
            "Unexpected invoice links deserve caution"
        ),
    ),
    (
        "Prize / Gift Card",
        "Reward",
        "HR Rewards",
        "rewards@hr-bonus-center.com",
        "You've been selected for a Rs. 5,000 gift card!",
        (
            "<p>Congratulations {{NAME}}!</p>"
            "<p>Claim your employee reward before midnight: "
            "<a href='{{LINK}}'>Claim reward</a></p>"
        ),
        (
            "Unexpected reward that seems too good to be true\n"
            'Fake urgency ("before midnight")\n'
            "Unfamiliar sender domain"
        ),
    ),
]


def seed_demo():
    import random

    init_db()

    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")

    if db.execute("SELECT 1 FROM users").fetchone():
        print("Database already has data - skipping seed.")
        db.close()
        return

    for template in DEMO_TEMPLATES:
        db.execute(
            """
            INSERT INTO email_templates(
                name, category, sender_name, sender_email,
                subject, body, red_flags
            )
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            template,
        )

    names = [
        "Rahul Sharma",
        "Priya Verma",
        "Amit Singh",
        "Neha Gupta",
        "Karan Mishra",
        "Sneha Yadav",
        "Vikas Tiwari",
        "Anjali Dubey",
        "Rohit Kumar",
        "Pooja Patel",
        "Manish Shukla",
        "Ritu Agarwal",
    ]

    departments = ["IT", "Finance", "HR", "Sales"]

    for index, name in enumerate(names):
        db.execute(
            """
            INSERT INTO users(name, email, department)
            VALUES(?, ?, ?)
            """,
            (
                name,
                name.lower().replace(" ", ".") + "@example.com",
                departments[index % 4],
            ),
        )

    random.seed(7)

    for index, probability in enumerate([0.60, 0.40, 0.20], start=1):
        cursor = db.execute(
            """
            INSERT INTO campaigns(
                name, template_id, status, created_at, launched_at
            )
            VALUES(?, ?, ?, ?, ?)
            """,
            (
                f"Campaign {index}: {DEMO_TEMPLATES[index - 1][0]}",
                index,
                "active",
                f"2026-0{index + 6}-01 09:00:00",
                f"2026-0{index + 6}-01 10:00:00",
            ),
        )

        campaign_id = cursor.lastrowid

        for user_id in range(1, len(names) + 1):
            target_cursor = db.execute(
                """
                INSERT INTO targets(
                    campaign_id, user_id, token, send_status, sent_at
                )
                VALUES(?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    user_id,
                    secrets.token_urlsafe(16),
                    "dry-run",
                    f"2026-0{index + 6}-01 10:00:00",
                ),
            )

            if random.random() < probability:
                db.execute(
                    """
                    INSERT INTO clicks(
                        target_id, clicked_at, ip, user_agent
                    )
                    VALUES(?, ?, ?, ?)
                    """,
                    (
                        target_cursor.lastrowid,
                        (
                            f"2026-0{index + 6}-01 "
                            f"1{random.randint(0, 9)}:"
                            f"{random.randint(10, 59)}:00"
                        ),
                        f"10.0.0.{user_id}",
                        "demo-seed",
                    ),
                )

    db.commit()
    db.close()

    print(
        "Demo data added: 12 users, 3 templates, "
        "3 campaigns with click history."
    )


# ---------------------------------------------------------------
# Start application
# ---------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        seed_demo()
    else:
        init_db()

        print(
            f"\nAdmin login -> user: {ADMIN_USER} "
            f"password: {ADMIN_PASSWORD}\n"
        )

        print(
            "Email mode -> "
            + (
                f"SMTP {SMTP_HOST}"
                if SMTP_HOST
                else "DRY-RUN (no real emails sent)"
            )
            + "\n"
        )

        app.run(debug=os.environ.get("FLASK_DEBUG") == "1")