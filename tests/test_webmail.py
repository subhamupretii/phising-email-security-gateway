from unittest.mock import MagicMock, patch

import pytest
from werkzeug.security import check_password_hash

from services.webmail.app import create_webmail_app, store_incoming_message
from shared.db import (
    DEFAULT_WEBMAIL_PASSWORD,
    DEFAULT_WEBMAIL_USERS,
    get_db,
    init_webmail_db,
    verify_webmail_user,
)


@pytest.fixture
def webmail_db(tmp_path):
    path = str(tmp_path / "webmail.db")
    init_webmail_db(path)
    return path


@pytest.fixture
def client(webmail_db):
    app = create_webmail_app(db_path=webmail_db, gateway_host="127.0.0.1", gateway_port=1025)
    app.config["TESTING"] = True
    return app.test_client()


def _login(client, email="user1@lab.local"):
    return client.post(
        "/login",
        data={"email": email, "password": DEFAULT_WEBMAIL_PASSWORD},
        follow_redirects=True,
    )


def test_webmail_schema_and_seed(webmail_db):
    with get_db(webmail_db) as conn:
        user_cols = [row["name"] for row in conn.execute("PRAGMA table_info(users)")]
        inbox_cols = [row["name"] for row in conn.execute("PRAGMA table_info(inbox)")]
        assert user_cols == ["id", "email", "password_hash"]
        assert inbox_cols == [
            "id",
            "recipient",
            "sender",
            "subject",
            "body",
            "is_read",
            "timestamp",
            "folder",
            "ai_score",
            "threat_score",
            "verdict",
        ]
        rows = conn.execute("SELECT email, password_hash FROM users ORDER BY email").fetchall()

    assert [row["email"] for row in rows] == list(DEFAULT_WEBMAIL_USERS)
    for row in rows:
        assert check_password_hash(row["password_hash"], DEFAULT_WEBMAIL_PASSWORD)

    init_webmail_db(webmail_db)
    with get_db(webmail_db) as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert count == 3
    assert verify_webmail_user("user2@lab.local", DEFAULT_WEBMAIL_PASSWORD, db_path=webmail_db)


def test_inbox_is_limited_to_signed_in_mailbox(client, webmail_db):
    with get_db(webmail_db) as conn:
        conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            ("user1@lab.local", "user2@lab.local", "For user one", "hello one", "2026-11-04T00:00:00+00:00"),
        )
        conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            ("user2@lab.local", "user1@lab.local", "Secret for user two", "hello two", "2026-11-04T00:00:01+00:00"),
        )

    anonymous = client.get("/inbox")
    assert anonymous.status_code == 302
    assert "/login" in anonymous.headers["Location"]

    page = _login(client, "user1@lab.local")
    assert b"For user one" in page.data
    assert b"Secret for user two" not in page.data
    assert b"user1@lab.local" in page.data
    assert b"Mark as read" in page.data


def test_mark_read_toggles_only_own_message(client, webmail_db):
    with get_db(webmail_db) as conn:
        own_id = conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp)
            VALUES ('user1@lab.local', 'user2@lab.local', 'Mine', 'body', 0, '2026-11-04T00:00:00+00:00')
            """
        ).lastrowid
        other_id = conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp)
            VALUES ('user2@lab.local', 'user3@lab.local', 'Theirs', 'body', 0, '2026-11-04T00:00:00+00:00')
            """
        ).lastrowid

    denied = client.post(f"/api/mark-read/{own_id}")
    assert denied.status_code == 401

    _login(client, "user1@lab.local")
    first = client.post(f"/api/mark-read/{own_id}")
    assert first.status_code == 200
    assert first.get_json()["is_read"] == 1
    second = client.post(f"/api/mark-read/{own_id}")
    assert second.get_json()["is_read"] == 0

    missing = client.post(f"/api/mark-read/{other_id}")
    assert missing.status_code == 404


def test_compose_submits_as_signed_in_user(client, webmail_db):
    _login(client, "user1@lab.local")
    with patch("services.webmail.app.smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance
        response = client.post(
            "/compose",
            data={
                "sender": "attacker@evil.com",  # Should be ignored and overridden by user1@lab.local
                "recipient": "user2@lab.local",
                "subject": "Lab note",
                "body": "See you in the lab.",
            },
            follow_redirects=False,
        )
    assert response.status_code == 302
    mock_smtp.assert_called_with("127.0.0.1", 1025, timeout=5)
    sent = mock_instance.send_message.call_args[0][0]
    assert sent["From"] == "user1@lab.local"
    assert sent["To"] == "user2@lab.local"
    assert sent["Subject"] == "Lab note"

    # Verify a copy was saved to Sent folder
    with get_db(webmail_db) as conn:
        sent_row = conn.execute(
            "SELECT * FROM inbox WHERE sender = 'user1@lab.local' AND folder = 'sent'"
        ).fetchone()
        assert sent_row is not None
        assert sent_row["recipient"] == "user2@lab.local"
        assert sent_row["subject"] == "Lab note"
        assert sent_row["body"] == "See you in the lab."
        assert sent_row["is_read"] == 1

    # Verify /sent view displays this message
    sent_page = client.get("/sent")
    assert sent_page.status_code == 200
    assert b"To: user2@lab.local" in sent_page.data
    assert b"Lab note" in sent_page.data


def test_folders_inbox_sent_spam(client, webmail_db):
    _login(client, "user1@lab.local")
    with get_db(webmail_db) as conn:
        # 1. Normal inbox mail
        conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp, folder)
            VALUES ('user1@lab.local', 'user2@lab.local', 'Clean Email', 'Clean body', 0, '2026-11-04T10:00:00+00:00', 'inbox')
            """
        )
        # 2. Spam mail
        conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp, folder)
            VALUES ('user1@lab.local', 'spammer@evil.com', 'Phishing Alert', 'Click here', 0, '2026-11-04T10:01:00+00:00', 'spam')
            """
        )
        # 3. Sent mail
        conn.execute(
            """
            INSERT INTO inbox (recipient, sender, subject, body, is_read, timestamp, folder)
            VALUES ('user3@lab.local', 'user1@lab.local', 'Sent Report', 'Status report', 1, '2026-11-04T10:02:00+00:00', 'sent')
            """
        )

    # Test /inbox
    inbox_res = client.get("/inbox")
    assert b"Clean Email" in inbox_res.data
    assert b"Phishing Alert" not in inbox_res.data
    assert b"Sent Report" not in inbox_res.data

    # Test /spam
    spam_res = client.get("/spam")
    assert b"Phishing Alert" in spam_res.data
    assert b"Clean Email" not in spam_res.data
    assert b"Sent Report" not in spam_res.data

    # Test /sent
    sent_res = client.get("/sent")
    assert b"Sent Report" in sent_res.data
    assert b"Clean Email" not in sent_res.data
    assert b"Phishing Alert" not in sent_res.data


def test_incoming_spam_detection(webmail_db):
    # Test clean message -> inbox
    clean_raw = (
        b"From: user2@lab.local\r\n"
        b"To: user1@lab.local\r\n"
        b"Subject: Clean\r\n"
        b"X-Phishing-Verdict: ALLOW\r\n"
        b"X-Threat-Score: 10\r\n"
        b"\r\n"
        b"Safe message.\r\n"
    )
    store_incoming_message(clean_raw, "user2@lab.local", ["user1@lab.local"], webmail_db)

    # Test quarantine message -> spam
    quarantine_raw = (
        b"From: phisher@evil.com\r\n"
        b"To: user1@lab.local\r\n"
        b"Subject: Urgent Action\r\n"
        b"X-Phishing-Verdict: QUARANTINE\r\n"
        b"X-Threat-Score: 65\r\n"
        b"\r\n"
        b"Suspicious link.\r\n"
    )
    store_incoming_message(quarantine_raw, "phisher@evil.com", ["user1@lab.local"], webmail_db)

    # Test score >= 50 without explicit verdict header -> spam
    high_score_raw = (
        b"From: attacker@evil.com\r\n"
        b"To: user1@lab.local\r\n"
        b"Subject: High Risk\r\n"
        b"X-Threat-Score: 85\r\n"
        b"\r\n"
        b"Dangerous.\r\n"
    )
    store_incoming_message(high_score_raw, "attacker@evil.com", ["user1@lab.local"], webmail_db)

    with get_db(webmail_db) as conn:
        clean_row = conn.execute("SELECT folder FROM inbox WHERE subject = 'Clean'").fetchone()
        assert clean_row["folder"] == "inbox"

        quarantine_row = conn.execute("SELECT folder FROM inbox WHERE subject = 'Urgent Action'").fetchone()
        assert quarantine_row["folder"] == "spam"

        high_score_row = conn.execute("SELECT folder FROM inbox WHERE subject = 'High Risk'").fetchone()
        assert high_score_row["folder"] == "spam"


def test_register_and_duplicate(client, webmail_db):
    created = client.post(
        "/register",
        data={
            "email": "new.user@lab.local",
            "password": "Another@123",
            "confirm": "Another@123",
        },
        follow_redirects=True,
    )
    assert created.status_code == 200
    assert b"new.user@lab.local" in created.data
    client.get("/logout", follow_redirects=True)

    duplicate = client.post(
        "/register",
        data={
            "email": "new.user@lab.local",
            "password": "Another@123",
            "confirm": "Another@123",
        },
    )
    assert b"already exists" in duplicate.data
    with get_db(webmail_db) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE email = ?",
            ("new.user@lab.local",),
        ).fetchone()[0]
    assert count == 1


def test_store_incoming_splits_recipients(webmail_db):
    raw = (
        b"From: user1@lab.local\r\n"
        b"To: user2@lab.local, user3@lab.local\r\n"
        b"Subject: Allowed mail\r\n"
        b"\r\n"
        b"This message was allowed.\r\n"
    )
    inserted = store_incoming_message(
        raw,
        "user1@lab.local",
        ["user2@lab.local", "user3@lab.local"],
        webmail_db,
    )
    assert inserted == 2
    with get_db(webmail_db) as conn:
        rows = conn.execute(
            "SELECT recipient, sender, subject, is_read FROM inbox ORDER BY recipient"
        ).fetchall()
    assert [row["recipient"] for row in rows] == ["user2@lab.local", "user3@lab.local"]
    assert all(row["is_read"] == 0 for row in rows)
    assert rows[0]["subject"] == "Allowed mail"
    assert rows[0]["sender"] == "user1@lab.local"
