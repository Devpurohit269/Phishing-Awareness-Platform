# Phishing Awareness Training Platform & Simulation Tool

Final-year B.Tech CSE major project — an internal web portal for running
mock phishing campaigns, tracking who clicks, teaching the red flags on
the spot, and scoring employee risk. Built with Flask + SQLite.

## Ethics (by design, not just policy)
- No credentials or personal data are ever captured — only the click event.
- Intended for internal use with management approval.
- Results are meant to educate employees, not punish them.

## Quick start

```bash
pip install -r requirements.txt
python app.py seed      # optional: adds 12 demo users, 3 templates, 3 campaigns with history
python app.py            # runs on http://127.0.0.1:5000
```

Default admin login: `admin` / `admin123` (override with the `ADMIN_PASSWORD` env var).

## Sending real email (optional)
By default the app runs in **dry-run mode**: "sending" a campaign just marks
emails as sent and gives you clickable tracking links on the campaign page,
so you can demo the whole flow with zero setup. To send real email, set
these environment variables before running the app:

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your_address@gmail.com
export SMTP_PASS=your_app_password
export BASE_URL=http://<your-ip-or-domain>:5000
python app.py
```

For a safe class demo, use a catch-all SMTP sandbox like Mailtrap or a local
MailHog instance instead of real inboxes.

## Project structure

```
Phishing-Awareness-Platform/
├── app.py                  # Flask app: routes, DB schema, tracking, emailing, risk scoring
├── requirements.txt
├── templates/               # Jinja2 HTML templates
│   ├── base.html, index.html, login.html
│   ├── dashboard.html, users.html, user_history.html
│   ├── phishing_template.html
│   ├── campaigns.html, create_campaign.html, campaign_detail.html
│   ├── landing.html         # the "you just clicked a simulated phish" education page
│   └── report.html
└── static/
    ├── css/style.css
    └── js/script.js
```

## Core flow (matches the presentation's workflow slide)
1. **Create** — admin builds an email template and picks target employees.
2. **Send** — app generates a unique token per recipient and emails (or dry-runs) the link.
3. **Track** — visiting `/t/<token>` logs a click against that employee, nothing else.
4. **Educate** — the landing page immediately explains the red flags of that specific lure.
5. **Report** — dashboard and CSV export show click rates, department comparisons, and
   per-employee risk scores (clicks ÷ emails received).

## Notable implementation details
- CSRF protection on every POST (custom token, no extra dependency).
- Passwords hashed with Werkzeug's `generate_password_hash`.
- Tracking tokens are 128-bit (`secrets.token_urlsafe`), unguessable.
- CSV bulk import for employees (`name,email,department` columns).
- Risk level thresholds: Low < 25%, Medium 25-49%, High ≥ 50% click rate.
