import os

# Dynamic path anchoring for seamless execution on Windows and cross-platform environments
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.path.join(BASE_DIR, "gateway.db")
RECEIVER_DB_PATH = os.path.join(BASE_DIR, "receiver_inbox.db")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")

SECRET_KEY = os.getenv("SECRET_KEY", "gateway-soc-admin-fixed-secret-2026")

# Webmail database (multi-user mailbox store)
WEBMAIL_DB_PATH = os.path.join(BASE_DIR, "webmail.db")

# Network service ports
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1025))
RECEIVER_SMTP_PORT = int(os.getenv("RECEIVER_SMTP_PORT", 1026))
SENDER_UI_PORT = int(os.getenv("SENDER_UI_PORT", 8001))
RECEIVER_UI_PORT = int(os.getenv("RECEIVER_UI_PORT", 8002))
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 5000))
WEBMAIL_PORT = int(os.getenv("WEBMAIL_PORT", 8000))

