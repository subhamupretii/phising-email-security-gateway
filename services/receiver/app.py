from __future__ import annotations

import datetime
import email
from email import policy
import logging
import os
import sqlite3
import sys
from typing import Optional
from aiosmtpd.controller import Controller
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from shared.config import (
    RECEIVER_DB_PATH,
    RECEIVER_SMTP_PORT,
    RECEIVER_UI_PORT,
    SECRET_KEY,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Receiver] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ReceiverService")


def init_receiver_db(db_path: str = RECEIVER_DB_PATH) -> None:
    """Initialize the receiver mailbox database table."""
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(db_path, timeout=15.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=15000;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                raw_eml TEXT NOT NULL,
                ai_score INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'ALLOW'
            )
            """
        )
        # Auto-migration for receiver_inbox.db
        for col_def in [
            ("ai_score", "INTEGER DEFAULT 0"),
            ("threat_score", "INTEGER DEFAULT 0"),
            ("verdict", "TEXT DEFAULT 'ALLOW'"),
        ]:
            try:
                conn.execute(f"ALTER TABLE inbox ADD COLUMN {col_def[0]} {col_def[1]}")
            except sqlite3.OperationalError:
                pass
        conn.commit()


def parse_email_content(raw_bytes: bytes) -> tuple[str, str, str, str, str]:
    """Extract subject, sender, recipient, plain text / HTML body, and raw eml string."""
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        subject = str(msg.get("subject", "") or "(No Subject)")
        sender = str(msg.get("from", "") or "")
        recipient = str(msg.get("to", "") or "")
        raw_eml = raw_bytes.decode("utf-8", errors="replace")

        # Extract readable body
        body_chunks: list[str] = []
        parts = msg.walk() if msg.is_multipart() else [msg]
        for part in parts:
            if part.get_content_maintype() == "multipart":
                continue
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        body_chunks.append(content)
                        continue
                except Exception:
                    pass
                try:
                    payload = part.get_payload(decode=True) or b""
                    body_chunks.append(payload.decode("utf-8", errors="replace"))
                except Exception:
                    pass

        body = "\n\n".join(body_chunks).strip() or raw_eml
        return subject, sender, recipient, body, raw_eml
    except Exception as exc:
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        return "(Unparsed Subject)", "unknown@sender.lab", "victim@receiverserver.lab", raw_text, raw_text


class ReceiverMailHandler:
    """aiosmtpd asynchronous handler for receiving relayed emails and saving to SQLite inbox."""

    def __init__(self, db_path: str = RECEIVER_DB_PATH) -> None:
        self.db_path = db_path
        init_receiver_db(self.db_path)

    async def handle_DATA(self, server, session, envelope) -> str:
        """Process incoming SMTP message and store into receiver database."""
        raw_bytes: bytes = envelope.content
        env_from = envelope.mail_from or ""
        env_rcpts = ", ".join(envelope.rcpt_tos) if envelope.rcpt_tos else ""

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        subject, parsed_from, parsed_to, body, raw_eml = parse_email_content(raw_bytes)

        final_sender = env_from or parsed_from or "unknown@sender.lab"
        final_recipient = env_rcpts or parsed_to or "victim@receiverserver.lab"

        with sqlite3.connect(self.db_path, timeout=15.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                INSERT INTO inbox (timestamp, sender, recipient, subject, body, raw_eml)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now_utc, final_sender, final_recipient, subject, body, raw_eml),
            )
            conn.commit()

        logger.info("Delivered relayed email '%s' from '%s' to '%s'", subject, final_sender, final_recipient)
        return "250 Message delivered to recipient mailbox"


def create_receiver_smtp_server(
    host: str = "127.0.0.1",
    port: int = RECEIVER_SMTP_PORT,
    db_path: str = RECEIVER_DB_PATH,
) -> Controller:
    """Instantiate the aiosmtpd Controller for the receiver mail service."""
    init_receiver_db(db_path)
    handler = ReceiverMailHandler(db_path=db_path)
    return Controller(handler, hostname=host, port=port)


def create_receiver_app(db_path: str = RECEIVER_DB_PATH) -> Flask:
    """Create and configure the Receiver Web Inbox Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DB_PATH"] = db_path

    @app.route("/")
    def index():
        """Render the recipient webmail inbox."""
        init_receiver_db(app.config["DB_PATH"])
        with sqlite3.connect(app.config["DB_PATH"], timeout=15.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.row_factory = sqlite3.Row
            emails = conn.execute("SELECT * FROM inbox ORDER BY id DESC").fetchall()

        return render_template(
            "index.html",
            emails=emails,
            target_user="victim@receiverserver.lab",
            total_count=len(emails),
        )

    @app.route("/api/emails")
    def api_emails():
        """JSON endpoint returning all delivered inbox messages."""
        init_receiver_db(app.config["DB_PATH"])
        with sqlite3.connect(app.config["DB_PATH"], timeout=15.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.row_factory = sqlite3.Row
            emails = conn.execute("SELECT * FROM inbox ORDER BY id DESC").fetchall()
            return jsonify([dict(e) for e in emails])

    @app.route("/clear", methods=["POST"])
    def clear_inbox():
        """Clear all messages from the receiver inbox database."""
        init_receiver_db(app.config["DB_PATH"])
        with sqlite3.connect(app.config["DB_PATH"], timeout=15.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("DELETE FROM inbox")
            conn.commit()
        flash("Recipient inbox cleared successfully.", "info")
        return redirect(url_for("index"))

    return app


def run_receiver(
    host: str = "127.0.0.1",
    http_port: int = RECEIVER_UI_PORT,
    smtp_port: int = RECEIVER_SMTP_PORT,
    db_path: str = RECEIVER_DB_PATH,
) -> None:
    """Start both the background SMTP server on port 1026 and Flask Web Inbox on port 8002."""
    init_receiver_db(db_path=db_path)

    # 1. Start background aiosmtpd listener on port 1026
    controller = create_receiver_smtp_server(host=host, port=smtp_port, db_path=db_path)
    controller.start()
    logger.info("Receiver SMTP listener active on %s:%s (saving to %s)", host, smtp_port, db_path)

    # 2. Start Flask Web Inbox on port 8002
    app = create_receiver_app(db_path=db_path)
    logger.info("Receiver Web Inbox active on http://%s:%s", host, http_port)

    try:
        app.run(host=host, port=http_port, debug=False)
    finally:
        logger.info("Stopping Receiver SMTP listener...")
        controller.stop()


if __name__ == "__main__":
    run_receiver()

