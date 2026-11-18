from __future__ import annotations

import email
from email.message import EmailMessage
import logging
import os
import smtplib
import sys
from typing import Optional
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
    GATEWAY_PORT,
    SENDER_UI_PORT,
    SECRET_KEY,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Sender] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("SenderService")


def create_sender_app(
    gateway_host: str = "127.0.0.1",
    gateway_port: int = GATEWAY_PORT,
) -> Flask:
    """Create and configure the Sender Webmail Simulator Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["GATEWAY_HOST"] = gateway_host
    app.config["GATEWAY_PORT"] = gateway_port

    @app.route("/", methods=["GET"])
    def index():
        """Render the webmail composer interface."""
        return render_template(
            "index.html",
            gateway_host=app.config["GATEWAY_HOST"],
            gateway_port=app.config["GATEWAY_PORT"],
        )

    @app.route("/send", methods=["POST"])
    def send_email():
        """Construct and dispatch an RFC 5322 email to the security gateway."""
        # Handle both JSON payloads and standard web form submissions
        if request.is_json:
            data = request.get_json() or {}
            sender = data.get("sender", "").strip()
            recipient = data.get("recipient", "").strip()
            subject = data.get("subject", "").strip()
            body = data.get("body", "")
            is_html = bool(data.get("is_html", False))
        else:
            sender = request.form.get("sender", "").strip()
            recipient = request.form.get("recipient", "").strip()
            subject = request.form.get("subject", "").strip()
            body = request.form.get("body", "")
            is_html = request.form.get("is_html") == "on"

        # Validation
        if not sender or not recipient:
            err_msg = "Both Sender and Recipient addresses are required."
            if request.is_json:
                return jsonify({"status": "error", "message": err_msg}), 400
            flash(err_msg, "error")
            return redirect(url_for("index"))

        # Build RFC 5322 Email Message
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject or "(No Subject)"

        if is_html:
            msg.set_content(body)  # Plaintext alternative fallback
            msg.add_alternative(body, subtype="html")
        else:
            msg.set_content(body)

        target_host = app.config["GATEWAY_HOST"]
        target_port = app.config["GATEWAY_PORT"]

        # Dispatch via SMTP to Gateway
        try:
            with smtplib.SMTP(target_host, target_port, timeout=5) as client:
                client.send_message(msg)
            
            success_msg = (
                f"Email successfully dispatched to Email Security Gateway "
                f"({target_host}:{target_port}) for inspection!"
            )
            logger.info("Dispatched email from '%s' to '%s' via %s:%s", sender, recipient, target_host, target_port)
            
            if request.is_json:
                return jsonify({
                    "status": "success",
                    "message": success_msg,
                    "sender": sender,
                    "recipient": recipient,
                    "subject": subject,
                }), 200

            flash(success_msg, "success")
            return redirect(url_for("index"))

        except Exception as exc:
            error_msg = (
                f"Failed to dispatch email to Gateway ({target_host}:{target_port}): {exc}. "
                "Ensure the Threat Gateway service is running on port 1025."
            )
            logger.warning("SMTP dispatch failure: %s", exc)

            if request.is_json:
                return jsonify({"status": "error", "message": error_msg}), 502

            flash(error_msg, "error")
            return redirect(url_for("index"))

    return app


def run_sender(
    host: str = "127.0.0.1",
    port: int = SENDER_UI_PORT,
    gateway_host: str = "127.0.0.1",
    gateway_port: int = GATEWAY_PORT,
) -> None:
    """Start the Sender Webmail Simulator service."""
    app = create_sender_app(gateway_host=gateway_host, gateway_port=gateway_port)
    print(f"[*] Starting Sender Webmail Simulator on http://{host}:{port} ...")
    print(f"[*] Dispatching SMTP to Gateway: {gateway_host}:{gateway_port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_sender()

