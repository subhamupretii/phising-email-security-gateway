from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import smtplib
import sys
import threading
import time
from email import policy
from email.parser import BytesParser
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError
from aiosmtpd.controller import Controller

from shared.config import (
    GATEWAY_PORT,
    RECEIVER_SMTP_PORT,
    EVIDENCE_DIR,
    DB_PATH,
    DASHBOARD_PORT,
)
from shared.db import get_db, init_gateway_db
from services.gateway.heuristics import analyse_email

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Gateway] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("GatewayService")

# Dashboard real-time notification URL — always 127.0.0.1 to skip IPv6 resolution
DASHBOARD_NOTIFY_URL = f"http://127.0.0.1:{DASHBOARD_PORT}/api/internal/notify"


def _notify_dashboard(payload: dict) -> None:
    """Fire-and-forget POST to the dashboard WebSocket relay endpoint.

    Runs in a daemon thread so the SMTP handler is NEVER blocked waiting for
    the dashboard (which may be slow or offline). Timeout capped at 1.5 s.
    """
    def _send() -> None:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = Request(
                DASHBOARD_NOTIFY_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urlopen(req, timeout=1.5)
        except Exception:
            # Dashboard offline / unreachable — non-critical, keep processing
            pass

    t = threading.Thread(target=_send, daemon=True)
    t.start()


class ThreatGatewayHandler:
    """aiosmtpd asynchronous handler for inspecting inbound SMTP traffic."""

    def __init__(
        self,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = RECEIVER_SMTP_PORT,
        evidence_dir: str = EVIDENCE_DIR,
        db_path: str = DB_PATH,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.evidence_dir = evidence_dir
        self.db_path = db_path
        os.makedirs(self.evidence_dir, exist_ok=True)

    async def handle_DATA(self, server, session, envelope) -> str:
        """Inspect inbound email payload, calculate hashes, persist evidence, and relay if allowed."""
        sender = envelope.mail_from
        recipients = ", ".join(envelope.rcpt_tos)
        content_bytes = envelope.content
        if isinstance(content_bytes, str):
            content_bytes = content_bytes.encode("utf-8")
        else:
            content_bytes = bytes(content_bytes)

        # 1. Forensic Hash & Timezone-Aware UTC Timestamp
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now_utc.isoformat()
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()

        # 2. Store raw .eml payload in EVIDENCE_DIR
        eml_filename = f"{now_utc.strftime('%Y%m%d_%H%M%S')}_{sha256_hash[:12]}.eml"
        eml_path = os.path.join(self.evidence_dir, eml_filename)
        os.makedirs(os.path.dirname(eml_path), exist_ok=True)
        with open(eml_path, "wb") as f:
            f.write(content_bytes)

        # Also mirror to data/evidence if the data directory exists
        base_project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_evidence_dir = os.path.join(base_project_dir, "data", "evidence")
        if os.path.exists(os.path.join(base_project_dir, "data")):
            try:
                os.makedirs(data_evidence_dir, exist_ok=True)
                data_eml_path = os.path.join(data_evidence_dir, eml_filename)
                if not os.path.exists(data_eml_path):
                    with open(data_eml_path, "wb") as f_data:
                        f_data.write(content_bytes)
            except Exception:
                pass

        # 3. Threat Assessment via Heuristics
        verdict = analyse_email(content_bytes)
        score = verdict["score"]
        threat_score = verdict.get("threat_score", score)
        ai_score = verdict.get("ai_score", 0)
        decision = verdict["decision"]
        verdict_str = verdict.get("verdict", decision)
        subject = verdict.get("subject") or "(No Subject)"

        # 4. Write Audit Record to SQLite Database
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO messages (
                    timestamp, sender, recipient, subject, score, decision, sha256_hash, eml_path,
                    ai_score, threat_score, verdict
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    sender,
                    recipients,
                    subject,
                    score,
                    decision,
                    sha256_hash,
                    eml_path,
                    ai_score,
                    threat_score,
                    verdict_str,
                ),
            )
            msg_id = cursor.lastrowid

        # 4b. Real-Time Push: Notify dashboard via WebSocket relay
        _notify_dashboard({
            "id": msg_id,
            "timestamp": timestamp,
            "sender": sender,
            "recipient": recipients,
            "subject": subject,
            "score": score,
            "decision": decision,
            "sha256_hash": sha256_hash,
            "ai_score": ai_score,
            "threat_score": threat_score,
            "verdict": verdict_str,
        })

        logger.info(
            "[MSG #%s] From: %s | Subject: '%s' | Score: %s/100 | Verdict: %s",
            msg_id,
            sender,
            subject,
            score,
            decision,
        )

        # 5. Upstream Relay: Forward ALLOW messages to receiver port 1026; suppress QUARANTINE / BLOCK
        if decision == "ALLOW":
            try:
                # Add verdict headers to relayed content
                try:
                    parsed_relay = BytesParser(policy=policy.default).parsebytes(content_bytes)
                    parsed_relay["X-Phishing-Verdict"] = verdict_str
                    parsed_relay["X-Threat-Score"] = str(threat_score)
                    parsed_relay["X-AI-Score"] = str(ai_score)
                    relay_bytes = parsed_relay.as_bytes()
                except Exception:
                    relay_bytes = content_bytes

                with smtplib.SMTP(self.upstream_host, self.upstream_port, timeout=1) as relay:
                    relay.sendmail(sender, envelope.rcpt_tos, relay_bytes)
                logger.info("[->] [MSG #%s] Relayed upstream to %s:%s", msg_id, self.upstream_host, self.upstream_port)
            except Exception as exc:
                logger.warning(
                    "[*] [MSG #%s] Upstream relay (%s:%s) offline/unreachable: %s. Safely logged & quarantined.",
                    msg_id,
                    self.upstream_host,
                    self.upstream_port,
                    exc,
                )
        else:
            logger.info("[!] [MSG #%s] Upstream forwarding suppressed by '%s' policy.", msg_id, decision)

        return "250 Message accepted for delivery"


def create_gateway_controller(
    host: str = "127.0.0.1",
    port: int = GATEWAY_PORT,
    upstream_host: str = "127.0.0.1",
    upstream_port: int = RECEIVER_SMTP_PORT,
    evidence_dir: str = EVIDENCE_DIR,
    db_path: str = DB_PATH,
) -> Controller:
    """Instantiate and configure the aiosmtpd Controller."""
    init_gateway_db(db_path=db_path)
    handler = ThreatGatewayHandler(
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        evidence_dir=evidence_dir,
        db_path=db_path,
    )
    return Controller(handler, hostname=host, port=port)


def run_gateway(
    host: Optional[str] = None,
    port: Optional[int] = None,
    upstream_host: str = "127.0.0.1",
    upstream_port: int = RECEIVER_SMTP_PORT,
) -> None:
    """Run the Email Security Gateway service continuously."""
    bind_host = host or os.getenv("GATEWAY_HOST", "127.0.0.1")
    bind_port = port or int(os.getenv("GATEWAY_PORT", GATEWAY_PORT))

    controller = create_gateway_controller(
        host=bind_host,
        port=bind_port,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
    )
    controller.start()
    logger.info("Threat Gateway active on %s:%s (Relaying ALLOW to %s:%s)...", bind_host, bind_port, upstream_host, upstream_port)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping Threat Gateway service...")
    finally:
        controller.stop()


if __name__ == "__main__":
    run_gateway()
