"""Unified multi-user webmail client.

Flask UI on http://127.0.0.1:8000 and an aiosmtpd listener on 127.0.0.1:1026.
Outbound mail is submitted to the threat gateway on 127.0.0.1:1025. The gateway
relays ALLOW verdicts back to this listener, which stores one inbox row per
recipient.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import smtplib
import sys
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Optional

from aiosmtpd.controller import Controller
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from shared.config import (
    GATEWAY_PORT,
    RECEIVER_SMTP_PORT,
    SECRET_KEY,
    WEBMAIL_DB_PATH,
    WEBMAIL_PORT,
)
from shared.db import (
    create_webmail_user,
    get_db,
    get_webmail_user_by_email,
    init_webmail_db,
    verify_webmail_user,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Webmail] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("WebmailService")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class WebmailUser(UserMixin):
    """Flask-Login user bound to a webmail mailbox address."""

    def __init__(self, user_id: int, email: str) -> None:
        self.id = str(user_id)
        self.email = email


def normalize_email(value: str) -> str:
    """Return the bare address, lowercased, from a header or envelope value."""
    _, address = parseaddr(value or "")
    candidate = (address or value or "").strip().lower()
    if "<" in candidate and ">" in candidate:
        candidate = candidate.split("<", 1)[1].split(">", 1)[0].strip().lower()
    return candidate


def extract_body(raw_bytes: bytes) -> tuple[str, str, str, str, float, int]:
    """Return subject, From header, body, verdict, threat score, and ai score."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        text = raw_bytes.decode("utf-8", errors="replace")
        return "(Unparsed Subject)", "", text, "", 0.0, 0

    subject = str(msg.get("subject", "") or "(No Subject)")
    sender = str(msg.get("from", "") or "")
    verdict = str(msg.get("X-Phishing-Verdict", "") or "").strip().upper()
    score_header = str(msg.get("X-Threat-Score", "") or "").strip()
    ai_header = str(msg.get("X-AI-Score", "") or "").strip()
    try:
        score = float(score_header) if score_header else 0.0
    except ValueError:
        score = 0.0
    try:
        ai_score = int(float(ai_header)) if ai_header else 0
    except ValueError:
        ai_score = 0

    chunks: list[str] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
            if isinstance(content, str):
                chunks.append(content)
                continue
        except Exception:
            pass
        try:
            payload = part.get_payload(decode=True) or b""
            chunks.append(payload.decode("utf-8", errors="replace"))
        except Exception:
            pass
    body = "\n\n".join(chunks).strip() or raw_bytes.decode("utf-8", errors="replace")
    return subject, sender, body, verdict, score, ai_score


def store_incoming_message(
    raw_bytes: bytes,
    mail_from: str,
    rcpt_tos: list[str],
    db_path: str,
) -> int:
    """Persist one inbox or spam row per envelope recipient. Returns rows inserted."""
    subject, header_from, body, verdict, score, ai_score = extract_body(raw_bytes)
    sender = normalize_email(mail_from) or normalize_email(header_from) or "unknown@lab.local"
    recipients = [normalize_email(rcpt) for rcpt in rcpt_tos if normalize_email(rcpt)]
    if not recipients:
        header_to = ""
        try:
            parsed = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            header_to = str(parsed.get("to", "") or "")
        except Exception:
            header_to = ""
        fallback = normalize_email(header_to)
        if fallback:
            recipients = [fallback]
    if not recipients:
        recipients = ["unknown@lab.local"]

    # Determine folder based on threat inspection headers
    if verdict in ("QUARANTINE", "BLOCK") or score >= 50.0:
        folder = "spam"
    else:
        folder = "inbox"

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    inserted = 0
    with get_db(db_path) as conn:
        for recipient in recipients:
            conn.execute(
                """
                INSERT INTO inbox (
                    recipient, sender, subject, body, is_read, timestamp, folder,
                    ai_score, threat_score, verdict
                )
                VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
                """,
                (
                    recipient,
                    sender,
                    subject or "(No Subject)",
                    body,
                    timestamp,
                    folder,
                    ai_score,
                    int(score),
                    verdict or ("BLOCK" if folder == "spam" else "ALLOW"),
                ),
            )
            inserted += 1
    return inserted


class WebmailInboxHandler:
    """Accept ALLOW relays from the gateway and file them in the user inbox."""

    def __init__(self, db_path: str = WEBMAIL_DB_PATH) -> None:
        self.db_path = db_path
        init_webmail_db(self.db_path)

    async def handle_DATA(self, server, session, envelope) -> str:
        raw_bytes: bytes = envelope.content or b""
        mail_from = envelope.mail_from or ""
        rcpt_tos = list(envelope.rcpt_tos or [])
        count = store_incoming_message(raw_bytes, mail_from, rcpt_tos, self.db_path)
        logger.info(
            "Stored %s inbox row(s) from '%s' for %s",
            count,
            mail_from,
            ", ".join(rcpt_tos) or "(no recipient)",
        )
        return "250 Message delivered to recipient mailbox"


def create_webmail_smtp_server(
    host: str = "127.0.0.1",
    port: int = RECEIVER_SMTP_PORT,
    db_path: str = WEBMAIL_DB_PATH,
) -> Controller:
    """Build the background SMTP listener that receives gateway relays."""
    init_webmail_db(db_path)
    handler = WebmailInboxHandler(db_path=db_path)
    return Controller(handler, hostname=host, port=port)


def create_webmail_app(
    db_path: str = WEBMAIL_DB_PATH,
    gateway_host: str = "127.0.0.1",
    gateway_port: int = GATEWAY_PORT,
) -> Flask:
    """Create the Flask webmail application. Does not bind the SMTP port."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "lab-webmail-fixed-session-key-2026"
    app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=7)
    app.config["SESSION_PERMANENT"] = True
    app.config["DB_PATH"] = db_path
    app.config["GATEWAY_HOST"] = gateway_host
    app.config["GATEWAY_PORT"] = gateway_port

    init_webmail_db(db_path)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.login_message = "Sign in to open your mailbox."
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str) -> Optional[WebmailUser]:
        if not user_id:
            return None
        try:
            with get_db(app.config["DB_PATH"]) as conn:
                row = conn.execute(
                    "SELECT id, email FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()
            if not row:
                return None
            return WebmailUser(row["id"], row["email"])
        except Exception:
            return None

    @app.context_processor
    def inject_mailbox() -> dict:
        unread_inbox = 0
        unread_spam = 0
        if current_user.is_authenticated:
            with get_db(app.config["DB_PATH"]) as conn:
                unread_inbox = conn.execute(
                    """
                    SELECT COUNT(*) FROM inbox
                    WHERE recipient = ? AND is_read = 0 AND (folder = 'inbox' OR folder IS NULL)
                    """,
                    (current_user.email,),
                ).fetchone()[0]
                unread_spam = conn.execute(
                    """
                    SELECT COUNT(*) FROM inbox
                    WHERE recipient = ? AND is_read = 0 AND folder = 'spam'
                    """,
                    (current_user.email,),
                ).fetchone()[0]
        return {
            "unread_count": unread_inbox,
            "unread_inbox_count": unread_inbox,
            "unread_spam_count": unread_spam,
        }

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("inbox"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("inbox"))
        error = None
        if request.method == "POST":
            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")
            user = verify_webmail_user(email, password, db_path=app.config["DB_PATH"])
            if user:
                session.permanent = True
                login_user(WebmailUser(user["id"], user["email"]), remember=True)
                next_url = request.args.get("next") or ""
                if next_url.startswith("/") and not next_url.startswith("//"):
                    return redirect(next_url)
                return redirect(url_for("inbox"))
            error = "That email and password do not match a mailbox."
        return render_template("login.html", error=error)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("inbox"))
        error = None
        if request.method == "POST":
            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            if not EMAIL_RE.match(email):
                error = "Enter a valid email address."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            elif password != confirm:
                error = "Passwords do not match."
            else:
                created = create_webmail_user(email, password, db_path=app.config["DB_PATH"])
                if not created:
                    error = "An account with that email already exists."
                else:
                    session.permanent = True
                    login_user(WebmailUser(created["id"], created["email"]), remember=True)
                    flash("Mailbox created. You are signed in.", "success")
                    return redirect(url_for("inbox"))
        return render_template("register.html", error=error)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Signed out.", "info")
        return redirect(url_for("login"))

    @app.route("/inbox")
    @login_required
    def inbox():
        with get_db(app.config["DB_PATH"]) as conn:
            messages = conn.execute(
                """
                SELECT * FROM inbox
                WHERE recipient = ? AND (folder = 'inbox' OR folder IS NULL)
                ORDER BY timestamp DESC, id DESC
                """,
                (current_user.email,),
            ).fetchall()
        return render_template("inbox.html", messages=messages, active_folder="inbox", folder_title="Inbox")

    @app.route("/sent")
    @login_required
    def sent():
        with get_db(app.config["DB_PATH"]) as conn:
            messages = conn.execute(
                """
                SELECT * FROM inbox
                WHERE sender = ? AND folder = 'sent'
                ORDER BY timestamp DESC, id DESC
                """,
                (current_user.email,),
            ).fetchall()
        return render_template("inbox.html", messages=messages, active_folder="sent", folder_title="Sent")

    @app.route("/spam")
    @login_required
    def spam():
        with get_db(app.config["DB_PATH"]) as conn:
            messages = conn.execute(
                """
                SELECT * FROM inbox
                WHERE recipient = ? AND folder = 'spam'
                ORDER BY timestamp DESC, id DESC
                """,
                (current_user.email,),
            ).fetchall()
        return render_template("inbox.html", messages=messages, active_folder="spam", folder_title="Spam")

    @app.route("/compose", methods=["GET", "POST"])
    @login_required
    def compose():
        if request.method == "GET":
            return render_template("compose.html")

        # Hard-code sender to current_user.email; ignore any request.form fallback
        sender_email = current_user.email
        recipient = normalize_email(request.form.get("recipient", ""))
        subject = (request.form.get("subject") or "").strip()
        body = request.form.get("body") or ""

        if not EMAIL_RE.match(recipient):
            flash("Enter a valid recipient address.", "error")
            return render_template("compose.html", recipient=recipient, subject=subject, body=body), 400

        message = EmailMessage()
        message["From"] = sender_email
        message["To"] = recipient
        message["Subject"] = subject or "(No Subject)"
        message.set_content(body)

        gateway_host = app.config["GATEWAY_HOST"]
        gateway_port = app.config["GATEWAY_PORT"]
        try:
            with smtplib.SMTP(gateway_host, gateway_port, timeout=5) as client:
                client.send_message(message)
        except Exception as exc:
            logger.warning("SMTP submit to gateway failed: %s", exc)
            flash(
                f"Could not reach the gateway at {gateway_host}:{gateway_port}. "
                "Start the threat gateway on port 1025 and try again.",
                "error",
            )
            return render_template(
                "compose.html", recipient=recipient, subject=subject, body=body
            ), 502

        # Insert a copy of the outgoing message into DB with folder = 'sent'
        sent_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with get_db(app.config["DB_PATH"]) as conn:
            conn.execute(
                """
                INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp, folder)
                VALUES (?, ?, ?, ?, 1, ?, 'sent')
                """,
                (recipient, sender_email, subject or "(No Subject)", body, sent_timestamp),
            )

        logger.info(
            "Submitted mail from %s to %s via %s:%s",
            sender_email,
            recipient,
            gateway_host,
            gateway_port,
        )
        flash(
            "Submitted to the security gateway. The recipient sees it only if the gateway allows delivery.",
            "success",
        )
        return redirect(url_for("inbox"))

    @app.route("/api/mark-read/<int:msg_id>", methods=["POST"])
    def mark_read(msg_id: int):
        if not current_user.is_authenticated:
            return jsonify({"error": "authentication required"}), 401
        with get_db(app.config["DB_PATH"]) as conn:
            row = conn.execute(
                "SELECT id, is_read FROM inbox WHERE id = ? AND recipient = ?",
                (msg_id, current_user.email),
            ).fetchone()
            if not row:
                return jsonify({"error": "message not found"}), 404
            new_state = 0 if int(row["is_read"]) else 1
            conn.execute(
                "UPDATE inbox SET is_read = ? WHERE id = ? AND recipient = ?",
                (new_state, msg_id, current_user.email),
            )
        return jsonify({"id": msg_id, "is_read": new_state})

    return app


def run_webmail(
    host: str = "127.0.0.1",
    http_port: int = WEBMAIL_PORT,
    smtp_port: int = RECEIVER_SMTP_PORT,
    db_path: str = WEBMAIL_DB_PATH,
    gateway_host: str = "127.0.0.1",
    gateway_port: int = GATEWAY_PORT,
) -> None:
    """Start the inbox SMTP listener and the Flask webmail UI."""
    init_webmail_db(db_path)
    controller = create_webmail_smtp_server(host=host, port=smtp_port, db_path=db_path)
    controller.start()
    logger.info("Webmail SMTP listener active on %s:%s", host, smtp_port)

    app = create_webmail_app(
        db_path=db_path,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
    )
    logger.info("Webmail UI active on http://%s:%s", host, http_port)
    try:
        app.run(host=host, port=http_port, debug=False, use_reloader=False, threaded=True)
    finally:
        logger.info("Stopping webmail SMTP listener...")
        controller.stop()


if __name__ == "__main__":
    run_webmail(
        host=os.getenv("WEBMAIL_HOST", "127.0.0.1"),
        http_port=int(os.getenv("WEBMAIL_PORT", WEBMAIL_PORT)),
        smtp_port=int(os.getenv("RECEIVER_SMTP_PORT", RECEIVER_SMTP_PORT)),
    )
