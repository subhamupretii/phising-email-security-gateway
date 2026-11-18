import hashlib
import os
import smtplib
import socket
import tempfile
import threading
from email.message import EmailMessage
from email import policy
import pytest
from unittest.mock import patch, MagicMock

from services.gateway.heuristics import (
    analyse_email,
    extract_urls,
    extract_anchors,
    is_ip_hostname,
    detect_anchor_mismatches,
    HIGH_RISK_TLDS,
    SUSPICIOUS_KEYWORDS,
)
from services.gateway.app import ThreatGatewayHandler, create_gateway_controller
from shared.db import get_db, init_gateway_db


def make_email(subject: str, text_body: str = "", html_body: str = "") -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@lab.test"
    msg["To"] = "receiver@lab.test"
    msg["Subject"] = subject
    if text_body and html_body:
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")
    elif html_body:
        msg.set_content(html_body, subtype="html")
    else:
        msg.set_content(text_body)
    return msg.as_bytes()


def test_url_extraction():
    sample_text = (
        "Check this link: https://example.com/login. Also visit http://test.org/path, "
        "and ignore non-url text."
    )
    urls = extract_urls(sample_text)
    assert "https://example.com/login" in urls
    assert "http://test.org/path" in urls


def test_ip_hostname_detection():
    assert is_ip_hostname("192.168.1.1") is True
    assert is_ip_hostname("10.0.0.1:8080") is True
    assert is_ip_hostname("127.0.0.1") is True
    assert is_ip_hostname("example.com") is False
    assert is_ip_hostname("paypal.com") is False
    assert is_ip_hostname("") is False

    # Email with IP link should score +30
    email_bytes = make_email(
        subject="Meeting Notes",
        text_body="Please review the document at http://192.168.1.100/doc"
    )
    res = analyse_email(email_bytes)
    assert res["score"] == 30
    assert "http://192.168.1.100/doc" in res["ip_links"]
    assert res["decision"] == "ALLOW"  # 30 < 35


def test_anchor_text_mismatch():
    # Mismatch: Anchor says paypal.com but links to an IP
    html_mismatch = '<a href="http://192.168.1.50/login">https://www.paypal.com/signin</a>'
    anchors = extract_anchors(html_mismatch)
    mismatches = detect_anchor_mismatches(anchors)
    assert len(mismatches) == 1
    assert mismatches[0]["displayed_domain"] == "paypal.com"
    assert mismatches[0]["target_hostname"] == "192.168.1.50"

    # Mismatch: Anchor says paypal.com but links to phish.xyz
    html_phish = '<a href="http://phish.xyz/login">paypal.com</a>'
    anchors2 = extract_anchors(html_phish)
    mismatches2 = detect_anchor_mismatches(anchors2)
    assert len(mismatches2) == 1

    # Legitimate: Anchor says paypal.com and links to paypal.com
    html_legit = '<a href="https://www.paypal.com/signin">paypal.com</a>'
    anchors_legit = extract_anchors(html_legit)
    mismatches_legit = detect_anchor_mismatches(anchors_legit)
    assert len(mismatches_legit) == 0

    # Legitimate non-domain text: "Click here"
    html_button = '<a href="https://example.com/doc">Click Here</a>'
    anchors_button = extract_anchors(html_button)
    mismatches_button = detect_anchor_mismatches(anchors_button)
    assert len(mismatches_button) == 0


def test_high_risk_tlds():
    for tld in [".invalid", ".top", ".xyz", ".biz", ".info"]:
        email_bytes = make_email(
            subject="Greetings",
            text_body=f"Visit our portal at https://portal{tld}/welcome"
        )
        res = analyse_email(email_bytes)
        assert len(res["high_risk_tld_links"]) > 0
        assert res["score"] >= 30


def test_keyword_scoring():
    # 1 keyword: +15 -> ALLOW
    email_1kw = make_email(subject="verify your email", text_body="Hello friend")
    res1 = analyse_email(email_1kw)
    assert res1["score"] == 15
    assert res1["decision"] == "ALLOW"

    # 3 keywords: +45 -> QUARANTINE (35-69)
    email_3kw = make_email(subject="urgent: password reset", text_body="Hello")
    res2 = analyse_email(email_3kw)
    assert res2["score"] == 45
    assert res2["decision"] == "QUARANTINE"

    # 5 keywords: +75 -> BLOCK (70+)
    email_5kw = make_email(
        subject="urgent: account suspended alert",
        text_body="Please verify your password immediately"
    )
    res3 = analyse_email(email_5kw)
    assert res3["score"] >= 70
    assert res3["decision"] == "BLOCK"


def test_score_capping_at_100():
    # Combine mismatch (+35), high risk tld (+30), IP (+30), and 4 keywords (4*15=60)
    html_body = '<a href="http://192.168.1.1/login">paypal.com</a>'
    text_body = "urgent alert: account suspended immediately! verify password: http://phish.xyz"
    email_bytes = make_email(subject="critical notice", text_body=text_body, html_body=html_body)
    res = analyse_email(email_bytes)
    assert res["score"] == 100
    assert res["decision"] == "BLOCK"


def execute_coroutine(coro):
    """Run a coroutine directly without requiring socket/IOCP proactor event loop initialization."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


def test_threat_gateway_handler_allow_and_relay(tmp_path):
    test_db = str(tmp_path / "gateway.db")
    evidence_dir = str(tmp_path / "evidence")
    init_gateway_db(test_db)

    # Mock envelope
    class DummyEnvelope:
        mail_from = "alice@company.test"
        rcpt_tos = ["bob@company.test"]
        content = make_email(subject="Project sync", text_body="Let us meet at 2pm.")

    handler = ThreatGatewayHandler(
        upstream_host="127.0.0.1",
        upstream_port=1026,
        evidence_dir=evidence_dir,
        db_path=test_db,
    )

    with patch("services.gateway.app.smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        response = execute_coroutine(handler.handle_DATA(None, None, DummyEnvelope()))
        assert response == "250 Message accepted for delivery"

        # Verify relay called for ALLOW
        assert mock_instance.sendmail.called

        # Verify SQLite record inserted
        with get_db(test_db) as conn:
            row = conn.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 1").fetchone()
            assert row is not None
            assert row["sender"] == "alice@company.test"
            assert row["decision"] == "ALLOW"
            assert row["score"] < 35
            assert os.path.exists(row["eml_path"])


def test_threat_gateway_handler_block_suppressed(tmp_path):
    test_db = str(tmp_path / "gateway.db")
    evidence_dir = str(tmp_path / "evidence")
    init_gateway_db(test_db)

    # Phishing message: 5 keywords -> BLOCK
    phish_bytes = make_email(
        subject="urgent: verify account password suspended",
        text_body="immediate alert: unauthorized login"
    )

    class DummyEnvelope:
        mail_from = "attacker@bad.test"
        rcpt_tos = ["victim@company.test"]
        content = phish_bytes

    handler = ThreatGatewayHandler(
        upstream_host="127.0.0.1",
        upstream_port=1026,
        evidence_dir=evidence_dir,
        db_path=test_db,
    )

    with patch("services.gateway.app.smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        response = execute_coroutine(handler.handle_DATA(None, None, DummyEnvelope()))
        assert response == "250 Message accepted for delivery"

        # Verify relay was NOT called for BLOCK
        assert not mock_instance.sendmail.called

        # Verify SQLite record has BLOCK verdict
        with get_db(test_db) as conn:
            row = conn.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 1").fetchone()
            assert row is not None
            assert row["decision"] == "BLOCK"
            assert row["score"] >= 70
            assert os.path.exists(row["eml_path"])
            with open(row["eml_path"], "rb") as f:
                saved_bytes = f.read()
            assert saved_bytes == phish_bytes
            assert hashlib.sha256(saved_bytes).hexdigest() == row["sha256_hash"]


def test_threat_gateway_handler_quarantine_and_evidence_preservation(tmp_path):
    test_db = str(tmp_path / "gateway.db")
    evidence_dir = str(tmp_path / "evidence")
    init_gateway_db(test_db)

    # 3 keywords -> QUARANTINE (score 45)
    quarantine_bytes = make_email(
        subject="urgent: password reset",
        text_body="Please review this notification."
    )

    class DummyEnvelope:
        mail_from = "sender@external.test"
        rcpt_tos = ["user@internal.test"]
        content = quarantine_bytes

    handler = ThreatGatewayHandler(
        upstream_host="127.0.0.1",
        upstream_port=1026,
        evidence_dir=evidence_dir,
        db_path=test_db,
    )

    with patch("services.gateway.app.smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        response = execute_coroutine(handler.handle_DATA(None, None, DummyEnvelope()))
        assert response == "250 Message accepted for delivery"

        # Upstream relay suppressed for QUARANTINE
        assert not mock_instance.sendmail.called

        # SQLite record and evidence file must exist
        with get_db(test_db) as conn:
            row = conn.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 1").fetchone()
            assert row is not None
            assert row["decision"] == "QUARANTINE"
            assert 35 <= row["score"] < 70
            assert os.path.exists(row["eml_path"])
            with open(row["eml_path"], "rb") as f:
                saved_bytes = f.read()
            assert saved_bytes == quarantine_bytes
            assert hashlib.sha256(saved_bytes).hexdigest() == row["sha256_hash"]

