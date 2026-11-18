import os
import sqlite3
import pytest
from services.receiver.app import (
    create_receiver_app,
    init_receiver_db,
    ReceiverMailHandler,
    parse_email_content,
)


def execute_coroutine(coro):
    """Run a coroutine directly without requiring socket/IOCP proactor event loop initialization."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


@pytest.fixture
def receiver_setup(tmp_path):
    test_db = str(tmp_path / "receiver_test.db")
    init_receiver_db(test_db)
    app = create_receiver_app(db_path=test_db)
    app.config["TESTING"] = True
    return app, test_db


def test_parse_email_content():
    sample_bytes = (
        b"From: alice@company.local\r\n"
        b"To: victim@receiverserver.lab\r\n"
        b"Subject: Operations Summary\r\n\r\n"
        b"All systems are operating nominally."
    )
    subject, sender, recipient, body, raw_eml = parse_email_content(sample_bytes)
    assert subject == "Operations Summary"
    assert sender == "alice@company.local"
    assert recipient == "victim@receiverserver.lab"
    assert "All systems are operating nominally." in body
    assert "Operations Summary" in raw_eml


def test_receiver_mail_handler_smtp(tmp_path):
    test_db = str(tmp_path / "handler_test.db")
    init_receiver_db(test_db)
    handler = ReceiverMailHandler(db_path=test_db)

    class DummyEnvelope:
        mail_from = "relayed@senderserver.lab"
        rcpt_tos = ["victim@receiverserver.lab"]
        content = (
            b"From: relayed@senderserver.lab\r\n"
            b"To: victim@receiverserver.lab\r\n"
            b"Subject: Relayed Operations Report\r\n\r\n"
            b"This email was allowed through the security gateway."
        )

    res = execute_coroutine(handler.handle_DATA(None, None, DummyEnvelope()))
    assert res == "250 Message delivered to recipient mailbox"

    # Verify message inserted into SQLite
    with sqlite3.connect(test_db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM inbox ORDER BY id DESC LIMIT 1").fetchone()
        assert row is not None
        assert row["sender"] == "relayed@senderserver.lab"
        assert row["recipient"] == "victim@receiverserver.lab"
        assert row["subject"] == "Relayed Operations Report"
        assert "This email was allowed through the security gateway." in row["body"]


def test_receiver_web_inbox_views(receiver_setup):
    app, test_db = receiver_setup
    client = app.test_client()

    # 1. Empty inbox view
    res = client.get("/")
    assert res.status_code == 200
    assert b"victim@receiverserver.lab" in res.data
    assert b"Your Inbox is Clean" in res.data

    # 2. Add an email to the inbox
    with sqlite3.connect(test_db) as conn:
        conn.execute("""
            INSERT INTO inbox (timestamp, sender, recipient, subject, body, raw_eml)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "2026-11-04T00:30:00Z",
            "operations@company.local",
            "victim@receiverserver.lab",
            "Approved Deployment",
            "The release has been deployed successfully.",
            "Raw RFC 5322 Payload"
        ))
        conn.commit()

    # 3. View inbox with message
    res_populated = client.get("/")
    assert res_populated.status_code == 200
    assert b"Approved Deployment" in res_populated.data
    assert b"operations@company.local" in res_populated.data
    assert b"Verified Clean" in res_populated.data

    # 4. JSON API endpoint
    api_res = client.get("/api/emails")
    assert api_res.status_code == 200
    data = api_res.get_json()
    assert len(data) == 1
    assert data[0]["subject"] == "Approved Deployment"
    assert data[0]["sender"] == "operations@company.local"

    # 5. Clear inbox
    clear_res = client.post("/clear", follow_redirects=True)
    assert clear_res.status_code == 200
    assert b"Your Inbox is Clean" in clear_res.data
    with sqlite3.connect(test_db) as conn:
        count = conn.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]
        assert count == 0

