import os
import sqlite3
import hashlib
from flask import Flask, render_template_string, abort, send_file

app = Flask(__name__)

# Absolute path configuration to ensure single shared database instance
BASE_DIR = "/home/kali/Desktop/phishing_email_security_gateway"
DB_PATH = os.path.join(BASE_DIR, "gateway.db")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Inline HTML Templates for zero external template dependency
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Security Gateway Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f4f6f9; color: #333; }
        .container { max-width: 1100px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; font-size: 24px; color: #1e293b; }
        .subtitle { font-size: 14px; color: #64748b; margin-bottom: 20px; }
        .notice-box { background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; margin-bottom: 20px; border-radius: 4px; font-size: 13px; color: #92400e; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
        th { background-color: #f8fafc; font-weight: 600; color: #475569; }
        tr:hover { background-color: #f1f5f9; }
        .badge { padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .badge-allow { background-color: #dcfce7; color: #166534; }
        .badge-quarantine { background-color: #fef9c3; color: #854d0e; }
        .badge-block { background-color: #fee2e2; color: #991b1b; }
        .btn { text-decoration: none; padding: 5px 10px; background-color: #0284c7; color: white; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .btn:hover { background-color: #0369a1; }
        .btn-verify { background-color: #4f46e5; }
        .btn-verify:hover { background-color: #4338ca; }
        .hash { font-family: monospace; font-size: 11px; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Security Gateway</h1>
        <div class="subtitle">Local demonstration dashboard &middot; NIST SP 800-86 Forensic Audit Logs</div>
        
        <div class="notice-box">
            <strong>Laboratory mode:</strong> Messages are inspected and stored locally. SHA-256 evidence hashes maintain forensic integrity.
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Received (UTC)</th>
                    <th>Sender</th>
                    <th>Subject</th>
                    <th>Verdict</th>
                    <th>Risk Score</th>
                    <th>SHA-256 Evidence Hash</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for msg in messages %}
                <tr>
                    <td>#{{ msg.id }}</td>
                    <td>{{ msg.timestamp }}</td>
                    <td>{{ msg.sender }}</td>
                    <td>{{ msg.subject }}</td>
                    <td>
                        {% if msg.decision == 'ALLOW' %}
                            <span class="badge badge-allow">ALLOW</span>
                        {% elif msg.decision == 'QUARANTINE' %}
                            <span class="badge badge-quarantine">QUARANTINE</span>
                        {% else %}
                            <span class="badge badge-block">BLOCK</span>
                        {% endif %}
                    </td>
                    <td>{{ msg.score }}/100</td>
                    <td class="hash" title="{{ msg.sha256_hash }}">{{ msg.sha256_hash[:12] }}...</td>
                    <td>
                        <a href="/message/{{ msg.id }}" class="btn">View</a>
                        <a href="/verify/{{ msg.id }}" class="btn btn-verify">Verify Hash</a>
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="8" style="text-align: center; color: #94a3b8; padding: 20px;">No email records found in database.</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

DETAIL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Message Audit Detail - #{{ msg.id }}</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background: #f4f6f9; color: #333; }
        .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        a { color: #0284c7; text-decoration: none; }
        pre { background: #1e293b; color: #f8fafc; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
        .meta { margin-bottom: 20px; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/">&larr; Back to Dashboard</a>
        <h2>Message Audit Log #{{ msg.id }}</h2>
        <div class="meta">
            <strong>Timestamp:</strong> {{ msg.timestamp }}<br>
            <strong>From:</strong> {{ msg.sender }}<br>
            <strong>To:</strong> {{ msg.recipient }}<br>
            <strong>Subject:</strong> {{ msg.subject }}<br>
            <strong>Risk Score:</strong> {{ msg.score }} / 100<br>
            <strong>Verdict:</strong> {{ msg.decision }}<br>
            <strong>SHA-256:</strong> <code>{{ msg.sha256_hash }}</code><br>
            <strong>EML Path:</strong> <code>{{ msg.eml_path }}</code>
        </div>
        <h3>Raw Email Evidence Payload (.eml)</h3>
        <pre>{{ raw_content }}</pre>
        <br>
        <a href="/download/{{ msg.id }}" style="padding: 8px 12px; background: #0284c7; color: white; border-radius: 4px; text-decoration: none;">Download Evidence File</a>
    </div>
</body>
</html>
"""

VERIFY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NIST SP 800-86 Forensic Verification</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background: #f4f6f9; color: #333; }
        .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        a { color: #0284c7; text-decoration: none; }
        .status-box { padding: 15px; border-radius: 6px; margin: 20px 0; font-weight: bold; }
        .valid { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .invalid { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        td { padding: 10px; border-bottom: 1px solid #e2e8f0; font-family: monospace; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/">&larr; Back to Dashboard</a>
        <h2>NIST SP 800-86 Cryptographic Hash Verification</h2>
        <p>Integrity analysis for message evidence record #{{ msg.id }}:</p>

        {% if is_valid %}
            <div class="status-box valid">&check; FORENSIC INTEGRITY VERIFIED: SHA-256 hashes match. Evidence remains pristine and untampered.</div>
        {% else %}
            <div class="status-box invalid">&cross; WARNING: Integrity Failure! Computed disk file hash does not match original baseline record.</div>
        {% endif %}

        <table>
            <tr>
                <td><strong>Database Baseline Hash:</strong></td>
                <td>{{ db_hash }}</td>
            </tr>
            <tr>
                <td><strong>Disk File Computed Hash:</strong></td>
                <td>{{ current_hash }}</td>
            </tr>
        </table>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    conn = get_db_connection()
    messages = conn.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template_string(INDEX_HTML, messages=messages)

@app.route("/message/<int:msg_id>")
def detail(msg_id):
    conn = get_db_connection()
    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
    conn.close()
    if not msg:
        abort(404)
    
    raw_content = "[Evidence file not found on disk]"
    if os.path.exists(msg['eml_path']):
        with open(msg['eml_path'], 'r', errors='ignore') as f:
            raw_content = f.read()

    return render_template_string(DETAIL_HTML, msg=msg, raw_content=raw_content)

@app.route("/verify/<int:msg_id>")
def verify(msg_id):
    conn = get_db_connection()
    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
    conn.close()
    if not msg:
        abort(404)

    db_hash = msg['sha256_hash']
    current_hash = "FILE_NOT_FOUND"
    is_valid = False

    if os.path.exists(msg['eml_path']):
        with open(msg['eml_path'], 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        is_valid = (db_hash == current_hash)

    return render_template_string(VERIFY_HTML, msg=msg, db_hash=db_hash, current_hash=current_hash, is_valid=is_valid)

@app.route("/download/<int:msg_id>")
def download(msg_id):
    conn = get_db_connection()
    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
    conn.close()
    if not msg or not os.path.exists(msg['eml_path']):
        abort(404)
    return send_file(msg['eml_path'], as_attachment=True)

if __name__ == "__main__":
    print("[*] Starting Web Security Dashboard on http://0.0.0.0:5000...")
    app.run(host="0.0.0.0", port=5000, debug=False)
