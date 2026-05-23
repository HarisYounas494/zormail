"""
ZorMail Render Edition
- Runs on Render as a normal Flask web service.
- Receives mail through an HTTP webhook (Cloudflare Email Routing Worker / Mailgun / SendGrid inbound parse).
- Supports user signup/signin for mailboxes.
- Supports a secret admin page with lockout + rate limiting.
"""

import os
import re
import json
import time
import hmac
import secrets
import logging
import threading
import email as email_lib
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from email.header import decode_header
from urllib.parse import quote

import bleach
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# ── Paths / Config ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data")).resolve()
MAIL_DIR = DATA_DIR / "mail"
CONFIG_FILE = DATA_DIR / "config.json"
USERS_FILE = DATA_DIR / "users.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MAIL_DIR.mkdir(parents=True, exist_ok=True)

WEB_PORT = int(os.environ.get("PORT", os.environ.get("WEB_PORT", 5000)))
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
SESSION_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"

DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123-change-me")
ADMIN_PATH_ENV = os.environ.get("ADMIN_PATH", "").strip("/")

MAX_WEBHOOK_BYTES = int(os.environ.get("MAX_WEBHOOK_BYTES", 1024 * 1024))  # 1 MB default

EMAIL_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
LOCAL_RE = re.compile(r"^[a-zA-Z0-9._%+-]{1,64}$")
DOMAIN_RE = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

log = logging.getLogger("zormail")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_SECURE,
    MAX_CONTENT_LENGTH=MAX_WEBHOOK_BYTES,
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

DATA_LOCK = threading.RLock()

ADMIN_FAILS = {}  # ip -> {"count": int, "until": timestamp}
USER_FAILS = {}   # ip -> {"count": int, "until": timestamp}

# ── JSON helpers ───────────────────────────────────────────────────────────────
def load_json(path: Path, default):
    with DATA_LOCK:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("Could not read %s: %s", path, e)
        return default

def save_json(path: Path, data):
    with DATA_LOCK:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

def initial_config():
    admin_path = ADMIN_PATH_ENV or f"admin-{secrets.token_urlsafe(12)}"
    webhook_secret = os.environ.get("WEBHOOK_SECRET") or secrets.token_urlsafe(32)
    return {
        "domains": [],
        "webhook_secret": webhook_secret,
        "admin_path": admin_path,
        "admin_password_hash": generate_password_hash(DEFAULT_ADMIN_PASSWORD),
        "created": datetime.utcnow().isoformat(),
        "public_signup": True,
    }

def get_config():
    c = load_json(CONFIG_FILE, None)
    if not c:
        c = initial_config()
        save_json(CONFIG_FILE, c)
        log.warning("Admin path is /%s", c["admin_path"])
    # Env variables can override secrets/path on Render.
    if ADMIN_PATH_ENV:
        c["admin_path"] = ADMIN_PATH_ENV
    if os.environ.get("WEBHOOK_SECRET"):
        c["webhook_secret"] = os.environ["WEBHOOK_SECRET"]
    return c

def save_config(config):
    # Do not persist env-only overrides accidentally.
    save_json(CONFIG_FILE, config)

def get_users():
    return load_json(USERS_FILE, {})

def save_users(users):
    save_json(USERS_FILE, users)

# ── Security helpers ───────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp

def ip_blocked(store):
    item = store.get(get_remote_address())
    return item and item.get("until", 0) > time.time()

def register_fail(store, max_fails=3, lock_minutes=15):
    ip = get_remote_address()
    item = store.setdefault(ip, {"count": 0, "until": 0})
    item["count"] += 1
    if item["count"] >= max_fails:
        item["until"] = time.time() + lock_minutes * 60

def clear_fails(store):
    store.pop(get_remote_address(), None)

def lockout_response(store):
    left = int(max(0, store.get(get_remote_address(), {}).get("until", 0) - time.time()))
    return jsonify({"ok": False, "error": f"Too many wrong attempts. Try again in {max(1, left // 60)} minute(s)."}), 429

def require_user(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Admin required"}), 401
        return f(*args, **kwargs)
    return decorated

def safe_email(value):
    value = (value or "").lower().strip()
    if len(value) > 254 or not EMAIL_RE.match(value):
        return ""
    return value

def safe_domain(value):
    value = (value or "").lower().strip()
    if len(value) > 253 or not DOMAIN_RE.match(value):
        return ""
    return value

def configured_domains():
    return [d["domain"] for d in get_config().get("domains", [])]

def user_can_access(address):
    return session.get("is_admin") or session.get("user_email") == address.lower()

def get_mail_folder(address):
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", address.lower().replace("@", "_at_"))
    folder = MAIL_DIR / safe
    folder.mkdir(parents=True, exist_ok=True)
    return folder

# ── Mail parsing/storage ───────────────────────────────────────────────────────
def decode_str(s):
    if not s:
        return ""
    try:
        parts = decode_header(str(s))
        out = ""
        for value, enc in parts:
            if isinstance(value, bytes):
                out += value.decode(enc or "utf-8", errors="replace")
            else:
                out += str(value)
        return out
    except Exception:
        return str(s)

ALLOWED_TAGS = [
    "a", "p", "br", "strong", "b", "em", "i", "u", "ul", "ol", "li", "blockquote",
    "code", "pre", "span", "div", "table", "thead", "tbody", "tr", "td", "th",
    "h1", "h2", "h3", "h4", "hr"
]
ALLOWED_ATTRS = {"a": ["href", "title"], "td": ["colspan", "rowspan"], "th": ["colspan", "rowspan"]}

def sanitize_html(html):
    if not html:
        return ""
    return bleach.clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, protocols=["http", "https", "mailto"], strip=True)

def parse_email_file(filepath):
    try:
        msg = email_lib.message_from_bytes(Path(filepath).read_bytes())
        body_text = ""
        body_html = ""
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()
                if "attachment" in disp.lower() or filename:
                    attachments.append(decode_str(filename or "file"))
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="replace")
                if ctype == "text/plain" and not body_text:
                    body_text = content
                elif ctype == "text/html" and not body_html:
                    body_html = sanitize_html(content)
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                if msg.get_content_type() == "text/html":
                    body_html = sanitize_html(payload.decode(charset, errors="replace"))
                else:
                    body_text = payload.decode(charset, errors="replace")

        folder = Path(filepath).parent
        read_ids = set(load_json(folder / ".read", []))
        return {
            "id": Path(filepath).stem,
            "from": decode_str(msg.get("From", "Unknown")),
            "to": decode_str(msg.get("To", "")),
            "subject": decode_str(msg.get("Subject", "(No Subject)")),
            "date": decode_str(msg.get("Date", "")),
            "body_text": body_text[:200000],
            "body_html": body_html[:200000],
            "attachments": attachments[:20],
            "timestamp": Path(filepath).stat().st_mtime,
            "read": Path(filepath).stem in read_ids,
        }
    except Exception as e:
        log.error("Parse error %s: %s", filepath, e)
        return None

def get_emails_for(address):
    folder = get_mail_folder(address)
    emails = []
    for f in sorted(folder.glob("*.eml"), key=lambda x: x.stat().st_mtime, reverse=True):
        parsed = parse_email_file(f)
        if parsed:
            emails.append(parsed)
    return emails

def save_incoming(recipient, sender, subject, body_text="", body_html="", date_str=""):
    recipient = safe_email(recipient)
    if not recipient:
        raise ValueError("Bad recipient")

    date_str = date_str or datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")
    subject = str(subject or "(No Subject)")[:300]
    sender = str(sender or "unknown")[:300]
    body_text = str(body_text or "")[:500000]
    body_html = str(body_html or "")[:500000]

    if body_html:
        raw = (
            f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\nDate: {date_str}\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"zmboundary\"\r\n\r\n"
            f"--zmboundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body_text}\r\n"
            f"--zmboundary\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body_html}\r\n"
            f"--zmboundary--\r\n"
        ).encode("utf-8", errors="replace")
    else:
        raw = (
            f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\nDate: {date_str}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{body_text}"
        ).encode("utf-8", errors="replace")

    filename = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.eml"
    (get_mail_folder(recipient) / filename).write_bytes(raw)
    return filename

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    if session.get("is_admin"):
        return redirect(url_for("admin_page"))
    if session.get("user_email"):
        return redirect(url_for("mailbox_page"))
    return redirect(url_for("signin_page"))

@app.route("/signup")
def signup_page():
    return render_template("auth.html", mode="signup", domains=configured_domains())

@app.route("/signin")
def signin_page():
    return render_template("auth.html", mode="signin", domains=configured_domains())

@app.route("/mail")
def mailbox_page():
    if not session.get("user_email"):
        return redirect(url_for("signin_page"))
    return render_template("mail.html", email=session["user_email"])

@app.route("/<path:maybe_admin>", methods=["GET"])
def secret_admin_page(maybe_admin):
    if maybe_admin.strip("/") == get_config().get("admin_path"):
        return render_template("admin_login.html", admin_path=get_config().get("admin_path"))
    abort(404)

@app.route("/admin")
def admin_shortcut_disabled():
    abort(404)

@app.route("/admin-panel")
def admin_page():
    if not session.get("is_admin"):
        return redirect("/" + get_config().get("admin_path"))
    return render_template("admin.html", admin_path=get_config().get("admin_path"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin_page"))

# ── Auth API ──────────────────────────────────────────────────────────────────
@app.route("/api/signup", methods=["POST"])
@limiter.limit("10 per hour")
def api_signup():
    c = get_config()
    if not c.get("public_signup", True):
        return jsonify({"error": "Signup is disabled"}), 403

    data = request.get_json(silent=True) or {}
    local = (data.get("local") or "").lower().strip()
    domain = safe_domain(data.get("domain") or "")
    password = data.get("password") or ""

    if not LOCAL_RE.match(local):
        return jsonify({"error": "Use only letters, numbers, dot, underscore, percent, plus, or hyphen."}), 400
    if domain not in configured_domains():
        return jsonify({"error": "That domain is not available"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    email = f"{local}@{domain}".lower()
    users = get_users()
    if email in users:
        return jsonify({"error": "Mailbox already exists"}), 409

    users[email] = {
        "email": email,
        "domain": domain,
        "password_hash": generate_password_hash(password),
        "created": datetime.utcnow().isoformat(),
        "disabled": False,
        "role": "user",
    }
    save_users(users)
    get_mail_folder(email)
    session.clear()
    session["user_email"] = email
    return jsonify({"ok": True, "email": email})

@app.route("/api/signin", methods=["POST"])
@limiter.limit("20 per hour")
def api_signin():
    if ip_blocked(USER_FAILS):
        return lockout_response(USER_FAILS)

    data = request.get_json(silent=True) or {}
    email = safe_email(data.get("email"))
    password = data.get("password") or ""
    user = get_users().get(email) if email else None

    if not user or user.get("disabled") or not check_password_hash(user.get("password_hash", ""), password):
        register_fail(USER_FAILS, max_fails=5, lock_minutes=10)
        return jsonify({"ok": False, "error": "Wrong email or password"}), 401

    clear_fails(USER_FAILS)
    session.clear()
    session["user_email"] = email
    return jsonify({"ok": True})

@app.route("/api/admin/login", methods=["POST"])
@limiter.limit("6 per hour")
def api_admin_login():
    if ip_blocked(ADMIN_FAILS):
        return lockout_response(ADMIN_FAILS)

    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    admin_hash = get_config().get("admin_password_hash", "")

    if not check_password_hash(admin_hash, password):
        register_fail(ADMIN_FAILS, max_fails=3, lock_minutes=30)
        return jsonify({"ok": False, "error": "Wrong admin password"}), 401

    clear_fails(ADMIN_FAILS)
    session.clear()
    session["is_admin"] = True
    return jsonify({"ok": True})

# ── User Mail API ─────────────────────────────────────────────────────────────
@app.route("/api/me")
@require_user
def api_me():
    email = session["user_email"]
    emails = get_emails_for(email)
    return jsonify({"email": email, "total": len(emails), "unread": sum(1 for e in emails if not e["read"])})

@app.route("/api/mail/<path:address>")
@require_user
def api_get_mail(address):
    address = safe_email(address)
    if not address or not user_can_access(address):
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"emails": get_emails_for(address)})

@app.route("/api/mail/<path:address>/<mail_id>/read", methods=["POST"])
@require_user
def api_mark_read(address, mail_id):
    address = safe_email(address)
    if not address or not user_can_access(address):
        return jsonify({"error": "Forbidden"}), 403
    if not re.match(r"^[a-zA-Z0-9_-]+(?:-[a-f0-9]+)?$", mail_id):
        return jsonify({"error": "Bad mail id"}), 400
    folder = get_mail_folder(address)
    read_file = folder / ".read"
    read_ids = set(load_json(read_file, []))
    read_ids.add(mail_id)
    save_json(read_file, list(read_ids))
    return jsonify({"ok": True})

@app.route("/api/mail/<path:address>/<mail_id>", methods=["DELETE"])
@require_user
def api_delete_mail(address, mail_id):
    address = safe_email(address)
    if not address or not user_can_access(address):
        return jsonify({"error": "Forbidden"}), 403
    if not re.match(r"^[a-zA-Z0-9_-]+(?:-[a-f0-9]+)?$", mail_id):
        return jsonify({"error": "Bad mail id"}), 400
    f = get_mail_folder(address) / f"{mail_id}.eml"
    if f.exists():
        f.unlink()
    return jsonify({"ok": True})

@app.route("/api/change-password", methods=["POST"])
@require_user
@limiter.limit("6 per hour")
def api_user_change_password():
    data = request.get_json(silent=True) or {}
    old = data.get("old") or ""
    new = data.get("new") or ""
    email = session["user_email"]
    users = get_users()
    user = users.get(email)
    if not user or not check_password_hash(user.get("password_hash", ""), old):
        return jsonify({"error": "Wrong current password"}), 401
    if len(new) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    user["password_hash"] = generate_password_hash(new)
    save_users(users)
    return jsonify({"ok": True})

# ── Admin API ─────────────────────────────────────────────────────────────────
@app.route("/api/admin/config")
@require_admin
def api_admin_config():
    c = get_config()
    return jsonify({
        "domains": c.get("domains", []),
        "webhook_secret": c.get("webhook_secret", ""),
        "admin_path": c.get("admin_path", ""),
        "public_signup": c.get("public_signup", True),
        "webhook_url_hint": request.host_url.rstrip("/") + "/webhook/receive",
    })

@app.route("/api/admin/domain", methods=["POST"])
@require_admin
@limiter.limit("30 per hour")
def api_admin_add_domain():
    data = request.get_json(silent=True) or {}
    domain = safe_domain(data.get("domain"))
    if not domain:
        return jsonify({"error": "Valid domain required"}), 400
    c = get_config()
    if domain in [d["domain"] for d in c.get("domains", [])]:
        return jsonify({"error": "Domain already exists"}), 409
    c.setdefault("domains", []).append({"domain": domain, "added": datetime.utcnow().isoformat()})
    save_config(c)
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/admin/domain/<domain>", methods=["DELETE"])
@require_admin
def api_admin_delete_domain(domain):
    domain = safe_domain(domain)
    c = get_config()
    c["domains"] = [d for d in c.get("domains", []) if d["domain"] != domain]
    save_config(c)
    return jsonify({"ok": True})

@app.route("/api/admin/users")
@require_admin
def api_admin_users():
    users = get_users()
    result = []
    for email, info in sorted(users.items()):
        emails = get_emails_for(email)
        result.append({
            "email": email,
            "domain": info.get("domain"),
            "created": info.get("created"),
            "disabled": info.get("disabled", False),
            "total": len(emails),
            "unread": sum(1 for e in emails if not e["read"]),
        })
    return jsonify({"users": result})

@app.route("/api/admin/users/<path:email>/toggle", methods=["POST"])
@require_admin
def api_admin_toggle_user(email):
    email = safe_email(email)
    users = get_users()
    if email not in users:
        return jsonify({"error": "User not found"}), 404
    users[email]["disabled"] = not users[email].get("disabled", False)
    save_users(users)
    return jsonify({"ok": True, "disabled": users[email]["disabled"]})

@app.route("/api/admin/test-mail", methods=["POST"])
@require_admin
@limiter.limit("20 per hour")
def api_admin_test_mail():
    data = request.get_json(silent=True) or {}
    recipient = safe_email(data.get("address"))
    if recipient not in get_users():
        return jsonify({"error": "Mailbox not found"}), 404
    save_incoming(
        recipient=recipient,
        sender="ZorMail Test <test@zormail.local>",
        subject="ZorMail test email",
        body_text=f"This is a test email delivered at {datetime.utcnow().isoformat()} UTC.",
        body_html=f"<h2>ZorMail test email</h2><p>Delivered at {datetime.utcnow().isoformat()} UTC.</p>",
    )
    return jsonify({"ok": True})

@app.route("/api/admin/change-password", methods=["POST"])
@require_admin
@limiter.limit("5 per hour")
def api_admin_change_password():
    data = request.get_json(silent=True) or {}
    old = data.get("old") or ""
    new = data.get("new") or ""
    c = get_config()
    if not check_password_hash(c.get("admin_password_hash", ""), old):
        return jsonify({"error": "Wrong current admin password"}), 401
    if len(new) < 12:
        return jsonify({"error": "Admin password must be at least 12 characters"}), 400
    c["admin_password_hash"] = generate_password_hash(new)
    save_config(c)
    return jsonify({"ok": True})

@app.route("/api/admin/signup-mode", methods=["POST"])
@require_admin
def api_admin_signup_mode():
    data = request.get_json(silent=True) or {}
    c = get_config()
    c["public_signup"] = bool(data.get("public_signup"))
    save_config(c)
    return jsonify({"ok": True, "public_signup": c["public_signup"]})

# ── Inbound webhook ───────────────────────────────────────────────────────────
@app.route("/webhook/receive", methods=["POST"])
@limiter.limit("120 per minute")
def webhook_receive():
    data = request.get_json(silent=True) or {}
    config = get_config()
    secret = config.get("webhook_secret", "")

    provided = request.headers.get("X-ZorMail-Secret") or data.get("secret", "")
    if secret and not hmac.compare_digest(str(provided), str(secret)):
        return jsonify({"error": "Unauthorized"}), 401

    recipient = safe_email(data.get("to") or data.get("recipient"))
    sender = data.get("from") or data.get("sender") or ""
    subject = data.get("subject") or "(No Subject)"
    text = data.get("text") or data.get("body_text") or ""
    html = data.get("html") or data.get("body_html") or ""
    date_str = data.get("date") or ""

    if recipient not in get_users():
        return jsonify({"error": "Unknown recipient"}), 404

    save_incoming(recipient, sender, subject, text, html, date_str)
    return jsonify({"ok": True})

# ── Simple health check ───────────────────────────────────────────────────────
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == "__main__":
    c = get_config()
    print("\nZorMail Render Edition running")
    print(f"User signin: http://localhost:{WEB_PORT}/signin")
    print(f"Admin URL:   http://localhost:{WEB_PORT}/{c.get('admin_path')}")
    print("Default admin password comes from ADMIN_PASSWORD env, otherwise admin123-change-me\n")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
