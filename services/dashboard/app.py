from __future__ import annotations

import email
import io
from datetime import datetime, timedelta, timezone
from email import policy
import hashlib
import os
import sys
from typing import Optional
from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
    session,
)

from shared.config import (
    BASE_DIR,
    DASHBOARD_PORT,
    DB_PATH,
    EVIDENCE_DIR,
    SECRET_KEY,
)
from shared.db import get_db, init_gateway_db, purge_expired_deleted_cases
from services.dashboard.auth import init_auth, login_required, login, logout

# PDF report generation (optional dependency)
try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False
    FPDF = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Flask-SocketIO import with graceful fallback
# ---------------------------------------------------------------------------
try:
    from flask_socketio import SocketIO, emit
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False
    SocketIO = None  # type: ignore[assignment,misc]

# Module-level reference so run_dashboard() can access it
_socketio_instance = None


def _resolve_eml_path(eml_path: str | None, evidence_dir: str = EVIDENCE_DIR) -> str | None:
    """Resolve an eml_path robustly across legacy paths and platforms."""
    if not eml_path:
        return None
    if os.path.exists(eml_path):
        return eml_path

    # Try resolving basename inside evidence_dir
    cleaned = eml_path.replace("\\", "/").rstrip("/")
    basename = os.path.basename(cleaned)
    if basename:
        candidate = os.path.join(evidence_dir, basename)
        if os.path.exists(candidate):
            return candidate

        candidate_data = os.path.join(BASE_DIR, "data", "evidence", basename)
        if os.path.exists(candidate_data):
            return candidate_data

    # Try relative to BASE_DIR
    candidate_rel = os.path.join(BASE_DIR, eml_path)
    if os.path.exists(candidate_rel):
        return candidate_rel

    return eml_path


def create_app(db_path: str = DB_PATH, evidence_dir: str = EVIDENCE_DIR) -> Flask:
    """Create and configure the Flask dashboard application."""
    global _socketio_instance

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DB_PATH"] = db_path
    app.config["EVIDENCE_DIR"] = evidence_dir

    # Persistent session configuration for admin login
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
    app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Initialize authentication & session management
    init_auth(app, db_path=db_path)

    # Alias login/logout at root level for url_for('login')
    app.add_url_rule("/login", endpoint="login", view_func=login, methods=["GET", "POST"])
    app.add_url_rule("/logout", endpoint="logout", view_func=logout, methods=["GET"])

    # -----------------------------------------------------------------
    # Initialize Flask-SocketIO (if available)
    # -----------------------------------------------------------------
    if HAS_SOCKETIO:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
        _socketio_instance = socketio
    else:
        _socketio_instance = None

    # -----------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------

    @app.route("/")
    @login_required
    def index():
        """Main dashboard view featuring overview counters and searchable audit table."""
        purge_expired_deleted_cases(app.config["DB_PATH"])
        with get_db(app.config["DB_PATH"]) as conn:
            messages = conn.execute(
                """
                SELECT * FROM messages
                WHERE is_deleted = 0 OR is_deleted IS NULL
                ORDER BY id DESC LIMIT 100
                """
            ).fetchall()
            stat_rows = conn.execute(
                """
                SELECT decision, COUNT(*) as cnt FROM messages
                WHERE is_deleted = 0 OR is_deleted IS NULL
                GROUP BY decision
                """
            ).fetchall()
            deleted_count_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM messages WHERE is_deleted = 1"
            ).fetchone()

        deleted_count = deleted_count_row["cnt"] if deleted_count_row else 0

        stats = {"allow": 0, "quarantine": 0, "block": 0, "total": 0}
        for r in stat_rows:
            dec = (r["decision"] or "").upper()
            cnt = int(r["cnt"])
            stats["total"] += cnt
            if dec == "ALLOW":
                stats["allow"] = cnt
            elif dec == "QUARANTINE":
                stats["quarantine"] = cnt
            elif dec == "BLOCK":
                stats["block"] = cnt

        return render_template(
            "index.html",
            messages=messages,
            stats=stats,
            deleted_count=deleted_count,
        )

    @app.route("/deleted")
    @login_required
    def deleted_cases():
        """Render soft-deleted cases with 30-day retention countdown."""
        purge_expired_deleted_cases(app.config["DB_PATH"])
        with get_db(app.config["DB_PATH"]) as conn:
            rows = conn.execute(
                """
                SELECT * FROM messages
                WHERE is_deleted = 1
                ORDER BY deleted_at DESC, id DESC
                """
            ).fetchall()

        cases = []
        now_utc = datetime.now(timezone.utc)
        for r in rows:
            case_dict = dict(r)
            del_at_str = case_dict.get("deleted_at")
            days_remaining = 30
            if del_at_str:
                try:
                    # Handle both ISO format with/without timezone
                    del_dt = datetime.fromisoformat(del_at_str.replace("Z", "+00:00"))
                    if del_dt.tzinfo is None:
                        del_dt = del_dt.replace(tzinfo=timezone.utc)
                    elapsed_days = (now_utc - del_dt).total_seconds() / 86400.0
                    days_remaining = max(0, int(30 - elapsed_days))
                except Exception:
                    days_remaining = 30
            case_dict["days_remaining"] = days_remaining
            cases.append(case_dict)

        return render_template("deleted.html", cases=cases)

    @app.route("/api/logs/<int:log_id>/delete", methods=["POST"])
    @login_required
    def api_delete_log(log_id: int):
        """Soft-delete a single case."""
        del_timestamp = datetime.now(timezone.utc).isoformat()
        with get_db(app.config["DB_PATH"]) as conn:
            conn.execute(
                "UPDATE messages SET is_deleted = 1, deleted_at = ? WHERE id = ?",
                (del_timestamp, log_id),
            )
            try:
                conn.execute(
                    "UPDATE logs SET is_deleted = 1, deleted_at = ? WHERE id = ?",
                    (del_timestamp, log_id),
                )
            except Exception:
                pass
        return jsonify({"status": "deleted", "id": log_id}), 200

    @app.route("/api/logs/delete-all", methods=["POST"])
    @login_required
    def api_delete_all_logs():
        """Soft-delete all active cases from the main dashboard."""
        del_timestamp = datetime.now(timezone.utc).isoformat()
        with get_db(app.config["DB_PATH"]) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE messages
                SET is_deleted = 1, deleted_at = ?
                WHERE is_deleted = 0 OR is_deleted IS NULL
                """,
                (del_timestamp,),
            )
            count = cursor.rowcount
            try:
                cursor.execute(
                    """
                    UPDATE logs
                    SET is_deleted = 1, deleted_at = ?
                    WHERE is_deleted = 0 OR is_deleted IS NULL
                    """,
                    (del_timestamp,),
                )
            except Exception:
                pass
        return jsonify({"status": "deleted_all", "count": count}), 200

    @app.route("/api/logs/<int:log_id>/restore", methods=["POST"])
    @login_required
    def api_restore_log(log_id: int):
        """Restore a soft-deleted case."""
        with get_db(app.config["DB_PATH"]) as conn:
            conn.execute(
                "UPDATE messages SET is_deleted = 0, deleted_at = NULL WHERE id = ?",
                (log_id,),
            )
            try:
                conn.execute(
                    "UPDATE logs SET is_deleted = 0, deleted_at = NULL WHERE id = ?",
                    (log_id,),
                )
            except Exception:
                pass
        return jsonify({"status": "restored", "id": log_id}), 200

    @app.route("/api/logs/<int:log_id>/inspect")
    @login_required
    def api_inspect_log(log_id: int):
        """Return full forensic details for a log entry in JSON format."""
        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (log_id,)).fetchone()

        if not msg:
            abort(404, description="Message not found")

        headers_dict = {}
        raw_body = ""
        eml_path = _resolve_eml_path(msg["eml_path"], app.config["EVIDENCE_DIR"])
        if eml_path and os.path.exists(eml_path):
            try:
                with open(eml_path, "rb") as f:
                    raw_bytes = f.read()
                raw_body = raw_bytes.decode("utf-8", errors="replace")
                parsed = email.message_from_bytes(raw_bytes, policy=policy.default)
                for header_name in ["From", "To", "Subject", "Date", "Message-ID", "Reply-To", "Received", "X-Phishing-Verdict", "X-Threat-Score", "X-AI-Score"]:
                    val = parsed.get(header_name)
                    if val:
                        headers_dict[header_name] = str(val)
            except Exception as e:
                raw_body = f"[Error reading file: {e}]"

        threat_score = int(msg["threat_score"] if msg["threat_score"] is not None else msg["score"])
        ai_score = int(msg["ai_score"] if msg["ai_score"] is not None else 0)
        # Calculate approximate heuristic component if not explicitly separated
        heuristic_score = threat_score

        return jsonify({
            "id": msg["id"],
            "timestamp": msg["timestamp"],
            "sender": msg["sender"],
            "recipient": msg["recipient"],
            "subject": msg["subject"],
            "ai_score": ai_score,
            "heuristic_score": heuristic_score,
            "threat_score": threat_score,
            "score": msg["score"],
            "verdict": msg["verdict"] or msg["decision"] or "ALLOW",
            "decision": msg["decision"] or "ALLOW",
            "sha256_hash": msg["sha256_hash"] or "",
            "eml_path": eml_path or "",
            "verification_status": msg["verification_status"] or "UNVERIFIED",
            "last_verified_at": msg["last_verified_at"],
            "headers": headers_dict,
            "raw_content": raw_body,
        }), 200

    @app.route("/api/logs/<int:log_id>/verify-hash", methods=["POST"])
    @login_required
    def api_verify_hash(log_id: int):
        """Compare stored sha256_hash against live computed sha256 hash and persist status."""
        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (log_id,)).fetchone()

        if not msg:
            return jsonify({
                "status": "FILE_MISSING",
                "stored_hash": "",
                "computed_hash": "",
                "error": "Record not found"
            }), 404

        stored_hash = msg["sha256_hash"] or ""
        eml_path = _resolve_eml_path(msg["eml_path"], app.config["EVIDENCE_DIR"])

        if not eml_path or not os.path.exists(eml_path):
            return jsonify({
                "status": "FILE_MISSING",
                "stored_hash": stored_hash,
                "computed_hash": ""
            }), 200

        try:
            with open(eml_path, "rb") as f:
                computed_hash = hashlib.sha256(f.read()).hexdigest()

            if stored_hash.lower() == computed_hash.lower():
                status = "VERIFIED"
            else:
                status = "TAMPERED"
        except Exception:
            return jsonify({
                "status": "FILE_MISSING",
                "stored_hash": stored_hash,
                "computed_hash": ""
            }), 200

        # Persist verification status to database
        verified_timestamp = datetime.now(timezone.utc).isoformat()
        try:
            with get_db(app.config["DB_PATH"]) as conn:
                conn.execute(
                    """
                    UPDATE messages
                    SET verification_status = ?, last_verified_at = ?
                    WHERE id = ?
                    """,
                    (status, verified_timestamp, log_id),
                )
        except Exception:
            pass  # Don't fail if persistence fails

        return jsonify({
            "status": status,
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "verification_status": status,
            "last_verified_at": verified_timestamp
        }), 200

    @app.route("/message/<int:msg_id>")
    @login_required
    def message_detail(msg_id: int):
        """View raw .eml payload, extracted headers, and forensic metadata."""
        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()

        if not msg:
            abort(404, description="Message not found")

        raw_content = "[Evidence payload (.eml) file not found on disk]"
        headers_dict = {}

        eml_path = _resolve_eml_path(msg["eml_path"], app.config["EVIDENCE_DIR"])
        if eml_path and os.path.exists(eml_path):
            try:
                with open(eml_path, "rb") as f:
                    raw_bytes = f.read()
                raw_content = raw_bytes.decode("utf-8", errors="replace")
                parsed = email.message_from_bytes(raw_bytes, policy=policy.default)
                for header_name in ["From", "To", "Subject", "Date", "Message-ID", "Reply-To", "Received"]:
                    val = parsed.get(header_name)
                    if val:
                        headers_dict[header_name] = str(val)
            except Exception as e:
                raw_content = f"[Error reading evidence file: {e}]"

        return render_template(
            "detail.html",
            msg=msg,
            raw_content=raw_content,
            headers=headers_dict,
        )

    @app.route("/verify/<int:msg_id>")
    @login_required
    def verify_message(msg_id: int):
        """NIST SP 800-86 SHA-256 cryptographic forensic hash validator."""
        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()

        if not msg:
            abort(404, description="Message not found")

        db_hash = msg["sha256_hash"] or ""
        current_hash = "FILE_NOT_FOUND"
        file_size = 0
        file_found = False
        is_valid = False

        eml_path = _resolve_eml_path(msg["eml_path"], app.config["EVIDENCE_DIR"])
        if eml_path and os.path.exists(eml_path):
            file_found = True
            file_size = os.path.getsize(eml_path)
            try:
                with open(eml_path, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                is_valid = (db_hash.lower() == current_hash.lower())
            except Exception:
                current_hash = "HASHING_ERROR"

        return render_template(
            "verify.html",
            msg=msg,
            db_hash=db_hash,
            current_hash=current_hash,
            is_valid=is_valid,
            file_found=file_found,
            file_size=file_size,
        )

    @app.route("/download/<int:msg_id>")
    @login_required
    def download_evidence(msg_id: int):
        """Download raw forensic .eml file from disk."""
        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()

        eml_path = _resolve_eml_path(msg["eml_path"] if msg else None, app.config["EVIDENCE_DIR"])
        if not msg or not eml_path or not os.path.exists(eml_path):
            abort(404, description="Evidence file not found")

        return send_file(
            eml_path,
            as_attachment=True,
            download_name=os.path.basename(eml_path),
        )

    @app.route("/api/verify/<int:log_id>", methods=["GET", "POST"])
    def api_verify(log_id: int):
        """Forensic SHA-256 hash verification API endpoint.

        Returns JSON:
            {"status": "VERIFIED" | "TAMPERED" | "MISSING_FILE",
             "stored_hash": "...",
             "current_hash": "..."}
        """
        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (log_id,)).fetchone()

        if not msg:
            return jsonify({
                "status": "MISSING_FILE",
                "stored_hash": "",
                "current_hash": "",
                "error": "Record not found"
            }), 404

        stored_hash = msg["sha256_hash"] or ""
        eml_path = _resolve_eml_path(msg["eml_path"], app.config["EVIDENCE_DIR"])

        if not eml_path or not os.path.exists(eml_path):
            return jsonify({
                "status": "MISSING_FILE",
                "stored_hash": stored_hash,
                "current_hash": ""
            }), 200

        try:
            with open(eml_path, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()

            if stored_hash.lower() == current_hash.lower():
                status = "VERIFIED"
            else:
                status = "TAMPERED"
        except Exception:
            return jsonify({
                "status": "MISSING_FILE",
                "stored_hash": stored_hash,
                "current_hash": ""
            }), 200

        return jsonify({
            "status": status,
            "stored_hash": stored_hash,
            "current_hash": current_hash
        }), 200

    @app.route("/api/stats")
    @login_required
    def api_stats():
        """JSON endpoint returning verdict counts for Chart.js doughnut chart."""
        with get_db(app.config["DB_PATH"]) as conn:
            stat_rows = conn.execute(
                """
                SELECT decision, COUNT(*) as cnt FROM messages
                WHERE is_deleted = 0 OR is_deleted IS NULL
                GROUP BY decision
                """
            ).fetchall()

        stats = {"allow": 0, "quarantine": 0, "block": 0, "total": 0}
        for r in stat_rows:
            dec = (r["decision"] or "").upper()
            cnt = int(r["cnt"])
            stats["total"] += cnt
            if dec == "ALLOW":
                stats["allow"] = cnt
            elif dec == "QUARANTINE":
                stats["quarantine"] = cnt
            elif dec == "BLOCK":
                stats["block"] = cnt

        return jsonify(stats)

    # -----------------------------------------------------------------
    # Real-Time WebSocket Notification Endpoint
    # -----------------------------------------------------------------
    @app.route("/api/internal/notify", methods=["POST"])
    def internal_notify():
        """Receive email event JSON from the gateway and broadcast via WebSocket.

        Payload keys: id, timestamp, sender, recipient, subject, score, decision,
                      sha256_hash.

        If Flask-SocketIO is unavailable the event is silently acknowledged so the
        gateway is never blocked.
        """
        payload = request.get_json(silent=True) or {}

        if HAS_SOCKETIO and _socketio_instance is not None:
            _socketio_instance.emit("new_email_event", payload)
            _socketio_instance.emit("new_event", payload)

        return jsonify({"status": "ok"}), 200

    # -----------------------------------------------------------------
    # Forensic PDF Report Generation
    # -----------------------------------------------------------------
    @app.route("/api/logs/<int:log_id>/report-pdf")
    @login_required
    def api_report_pdf(log_id: int):
        """Generate and download a forensic PDF report for a log entry."""
        if not HAS_FPDF:
            abort(503, description="PDF generation library (fpdf2) is not installed")

        with get_db(app.config["DB_PATH"]) as conn:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (log_id,)).fetchone()

        if not msg:
            abort(404, description="Record not found")

        # Live hash check on disk (read-only, does not alter saved status)
        stored_hash = msg["sha256_hash"] or ""
        eml_path = _resolve_eml_path(msg["eml_path"], app.config["EVIDENCE_DIR"])
        live_hash = "FILE_MISSING"
        if eml_path and os.path.exists(eml_path):
            try:
                with open(eml_path, "rb") as f:
                    live_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                live_hash = "FILE_MISSING"

        verify_status = (msg["verification_status"] or "UNVERIFIED").upper()
        last_verified = msg["last_verified_at"] or "Never"
        if last_verified != "Never":
            try:
                last_verified = last_verified.replace("T", " ")[:19] + " UTC"
            except Exception:
                pass

        ai_score = int(msg["ai_score"] if msg["ai_score"] is not None else 0)
        threat_score = int(msg["threat_score"] if msg["threat_score"] is not None else msg["score"])
        verdict = (msg["verdict"] or msg["decision"] or "ALLOW").upper()

        # Build PDF
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_margins(15, 15, 15)

        # --- Header ---
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(15, 23, 42)  # slate-900
        pdf.cell(0, 10, "Digital Forensic Email Incident Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 116, 139)  # slate-500
        gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        pdf.cell(0, 6, f"Case ID: #{log_id}    |    Generated: {gen_ts}", ln=True, align="C")
        pdf.ln(6)

        # --- Integrity Status Banner ---
        if verify_status == "VERIFIED":
            border_rgb, text_rgb, label = (16, 185, 129), (4, 120, 87), "VERIFIED"
        elif verify_status == "TAMPERED":
            border_rgb, text_rgb, label = (244, 63, 94), (190, 18, 60), "TAMPERED"
        else:
            border_rgb, text_rgb, label = (245, 158, 11), (180, 83, 9), "UNVERIFIED"

        pdf.set_draw_color(*border_rgb)
        pdf.set_line_width(0.6)
        banner_y = pdf.get_y()
        pdf.set_fill_color(248, 250, 252)
        pdf.rect(15, banner_y, 180, 22, style="DF")
        pdf.set_xy(18, banner_y + 3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*text_rgb)
        pdf.cell(60, 6, f"Integrity Status: {label}", ln=False)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(0, 6, f"Last Verified At: {last_verified}", ln=True)
        pdf.set_xy(18, banner_y + 11)
        pdf.cell(0, 6, f"Stored SHA-256: {stored_hash[:32]}..." if stored_hash else "Stored SHA-256: (none)", ln=True)
        pdf.cell(0, 6, f"Live Disk Hash : {live_hash[:32]}..." if live_hash != "FILE_MISSING" else "Live Disk Hash : FILE_MISSING", ln=True)
        pdf.set_y(banner_y + 26)
        pdf.ln(4)

        # --- Message Metadata Table ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "Message Metadata", ln=True)
        pdf.set_draw_color(226, 232, 240)
        pdf.set_line_width(0.2)

        meta_rows = [
            ("Sender", msg["sender"] or ""),
            ("Recipient", msg["recipient"] or ""),
            ("Subject", msg["subject"] or "(No Subject)"),
            ("Interception Timestamp (UTC)", msg["timestamp"] or ""),
            ("Evidence File Path", eml_path or msg["eml_path"] or ""),
        ]
        for label_text, value in meta_rows:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(55, 7, label_text, border=0)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(0, 7, str(value), border=0)
            pdf.ln(1)
        pdf.ln(4)

        # --- Threat Detection Breakdown ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "Threat Detection Breakdown", ln=True)

        if verdict == "BLOCK":
            v_rgb = (225, 29, 72)
        elif verdict == "QUARANTINE":
            v_rgb = (217, 119, 6)
        else:
            v_rgb = (5, 150, 105)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(60, 7, "AI Confidence Score:", border=0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, f"{ai_score}%", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(60, 7, "Composite Threat Score:", border=0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, f"{threat_score}/100", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(60, 7, "Final Gateway Verdict:", border=0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*v_rgb)
        pdf.cell(0, 7, verdict, ln=True)
        pdf.ln(4)

        # --- Cryptographic Chain of Custody ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "Cryptographic Chain of Custody (NIST SP 800-86)", ln=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 116, 139)
        pdf.multi_cell(0, 5, "SHA-256 hashes provide tamper-evident evidence integrity per NIST SP 800-86 forensic handling guidelines.", ln=True)
        pdf.ln(2)

        pdf.set_font("Courier", "B", 8)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 6, "Original Stored SHA-256 Hash:", ln=True)
        pdf.set_font("Courier", "", 8)
        pdf.multi_cell(0, 4.5, stored_hash or "(none)", ln=True)
        pdf.ln(1)

        pdf.set_font("Courier", "B", 8)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 6, "Current Disk SHA-256 Hash:", ln=True)
        pdf.set_font("Courier", "", 8)
        pdf.multi_cell(0, 4.5, live_hash if live_hash != "FILE_MISSING" else "FILE_MISSING", ln=True)
        pdf.ln(1)

        # --- Footer ---
        pdf.ln(6)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 5, "Generated by Phishing Email Security Gateway - Laboratory Environment", ln=True, align="C")

        # Stream PDF bytes
        pdf_bytes = pdf.output()
        return send_file(
            io.BytesIO(pdf_bytes),
            as_attachment=True,
            download_name=f"forensic_report_case_{log_id}.pdf",
            mimetype="application/pdf",
        )

    return app


def run_dashboard(
    host: str = "0.0.0.0",
    port: int = DASHBOARD_PORT,
    db_path: str = DB_PATH,
) -> None:
    """Initialize database and start Web Security Dashboard service."""
    init_gateway_db(db_path=db_path)
    app = create_app(db_path=db_path)
    print(f"[*] Starting Web Security Dashboard on http://{host}:{port} ...")

    if HAS_SOCKETIO and _socketio_instance is not None:
        print("[*] Flask-SocketIO enabled — real-time WebSocket push active")
        try:
            _socketio_instance.run(
                app,
                host=host,
                port=port,
                debug=False,
                use_reloader=False,
                allow_unsafe_werkzeug=True,
            )
        except Exception as e:
            print(f"[!] SocketIO server failed to start: {e}. Falling back to standard Flask.")
            app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    else:
        print("[*] Flask-SocketIO not installed — falling back to standard Flask server")
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
