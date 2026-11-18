import smtplib
import sys
from email.mime.text import MIMEText

GATEWAY_IP = "127.0.0.1"
GATEWAY_PORT = 1025

mode = sys.argv[1].lower() if len(sys.argv) > 1 else "clean"

if mode == "phishing":
    subject = "Urgent: Account Suspended - Action Required"
    body = "Your account access has been suspended. Please verify your password immediately at http://login-verify.example.invalid to restore access."
    sender = "security@senderserver.lab"
elif mode == "block":
    subject = "URGENT RESET: Account Password Verification Required"
    body = "SECURITY ALERT: Urgent action required! Reset your account credentials now at http://login-verify.example.invalid or http://update-credentials.invalid to prevent permanent account suspension."
    sender = "attacker@senderserver.lab"
else:  # clean / allow
    subject = "Quarterly Financial Status Report"
    body = "Hi Team, please find the quarterly status report attached for your review."
    sender = "user@senderserver.lab"

msg = MIMEText(body)
msg['Subject'] = subject
msg['From'] = sender
msg['To'] = "victim@receiverserver.lab"

try:
    with smtplib.SMTP(GATEWAY_IP, GATEWAY_PORT) as server:
        server.send_message(msg)
    print(f"[+] Successfully sent '{mode}' test email to gateway ({GATEWAY_IP}:{GATEWAY_PORT})")
except Exception as e:
    print(f"[!] Failed to send email: {e}")
