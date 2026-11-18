import os
import sys
import datetime
import hashlib
import sqlite3
import smtplib
from aiosmtpd.controller import Controller

# Absolute Paths for Shared Database & Evidence Storage
BASE_DIR = "/home/kali/Desktop/phishing_email_security_gateway"
DB_PATH = os.path.join(BASE_DIR, "gateway.db")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")

# Upstream Relay Configuration (For ALLOWED messages in production)
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 1026

# Risk Scoring Heuristic Keywords
SUSPICIOUS_KEYWORDS = ["urgent", "verify", "password", "account", "suspended", "reset", "alert"]

def init_db():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            score INTEGER,
            decision TEXT,
            sha256_hash TEXT,
            eml_path TEXT
        )
    ''')
    conn.commit()
    conn.close()

class GatewayHandler:
    async def handle_DATA(self, server, session, envelope):
        sender = envelope.mail_from
        recipients = ", ".join(envelope.rcpt_tos)
        content_bytes = envelope.content
        content_str = content_bytes.decode('utf-8', errors='ignore')

        # Extract Subject line
        subject = "(No Subject)"
        for line in content_str.splitlines():
            if line.lower().startswith("subject:"):
                subject = line[8:].strip()
                break

        # Calculate Threat Risk Score
        score = 0
        lowered_body = content_str.lower()
        
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in lowered_body:
                score += 15
        
        if "http://" in lowered_body or "https://" in lowered_body:
            score += 25
            
        if ".invalid" in lowered_body or ".xyz" in lowered_body or ".top" in lowered_body:
            score += 30

        score = min(score, 100)

        # Verdict Decision Logic
        if score >= 70:
            decision = "BLOCK"
        elif score >= 35:
            decision = "QUARANTINE"
        else:
            decision = "ALLOW"

        # Forensic Hash & Modern Timezone-Aware UTC Timestamp
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now_utc.isoformat()
        
        eml_filename = f"{now_utc.strftime('%Y%m%d_%H%M%S')}_{sha256_hash[:8]}.eml"
        eml_path = os.path.join(EVIDENCE_DIR, eml_filename)

        with open(eml_path, 'wb') as f:
            f.write(content_bytes)

        # Record Audit Entry in SQLite
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (timestamp, sender, recipient, subject, score, decision, sha256_hash, eml_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, sender, recipients, subject, score, decision, sha256_hash, eml_path))
        msg_id = cursor.lastrowid
        conn.commit()
        conn.close()

        print(f"[+] [MSG #{msg_id}] From: {sender} | Subject: '{subject}' | Score: {score} | Verdict: {decision}")

        # Upstream Relay Strategy (Non-blocking fallback for lab environment)
        if decision == "ALLOW":
            try:
                with smtplib.SMTP(UPSTREAM_HOST, UPSTREAM_PORT, timeout=2) as relay:
                    relay.sendmail(sender, envelope.rcpt_tos, content_bytes)
                print(f"[->] [MSG #{msg_id}] Relayed upstream to {UPSTREAM_HOST}:{UPSTREAM_PORT}")
            except Exception:
                print(f"[*] [MSG #{msg_id}] Upstream relay unavailable. Message safely logged & stored locally.")
        else:
            print(f"[!] [MSG #{msg_id}] Forwarding suppressed by '{decision}' policy.")

        return '250 Message accepted for delivery'

if __name__ == "__main__":
    init_db()
    handler = GatewayHandler()
    controller = Controller(handler, hostname='0.0.0.0', port=1025)
    controller.start()
    print("[*] Email Security Gateway Service running on 0.0.0.0:1025...")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping Email Security Gateway...")
        controller.stop()
