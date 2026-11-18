from __future__ import annotations

import io
import json
from flask import Flask, abort, render_template, send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.db import get_email_record, init_db, list_email_records


def create_app() -> Flask:
    app = Flask(__name__)
    init_db()

    @app.get("/")
    def index():
        records = list_email_records(limit=100)
        return render_template("index.html", records=records)

    @app.get("/email/<int:record_id>")
    def email_detail(record_id: int):
        record = get_email_record(record_id)
        if record is None:
            abort(404)
        item = dict(record)
        item["reasons_list"] = json.loads(item["reasons"])
        item["recipients_list"] = json.loads(item["recipients"])
        return render_template("detail.html", item=item)

    @app.get("/email/<int:record_id>/pdf")
    def download_pdf(record_id: int):
        record = get_email_record(record_id)
        if record is None:
            abort(404)

        item = dict(record)
        reasons = json.loads(item["reasons"])

        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)

        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, 750, f"Forensic Email Incident Report — Case #{item['id']}")

        p.setFont("Helvetica", 10)
        p.drawString(50, 730, f"Generated UTC: {item['received_at']}")
        p.line(50, 720, 550, 720)

        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, 695, "1. Message Details")
        p.setFont("Helvetica", 10)
        p.drawString(60, 675, f"Sender: {item['sender']}")
        p.drawString(60, 660, f"Subject: {item['subject']}")
        p.drawString(60, 645, f"Decision: {item['decision']} (Risk Score: {item['risk_score']}/100)")

        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, 615, "2. Triggered Risk Indicators")
        p.setFont("Helvetica", 9)
        y = 595
        for r in reasons:
            p.drawString(60, y, f"• {r}")
            y -= 15

        p.line(50, y - 5, 550, y - 5)
        y -= 25
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y, "3. Digital Evidence Integrity")
        p.setFont("Courier", 8)
        y -= 20
        p.drawString(60, y, f"SHA-256 Hash: {item['sha256']}")
        y -= 15
        p.setFont("Helvetica", 9)
        p.drawString(60, y, f"Evidence Path: {item['evidence_path']}")

        p.showPage()
        p.save()

        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"evidence_report_case_{record_id}.pdf",
            mimetype="application/pdf"
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "local-email-security-dashboard"}

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=False)
