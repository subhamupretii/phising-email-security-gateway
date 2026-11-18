import os
import sqlite3
import pytest
from werkzeug.security import check_password_hash

from shared import config
from shared.db import get_db, init_gateway_db, get_user_by_username, verify_user
from shared.models import EmailMessage, AuditRecord, UserSession


def test_config_paths_and_ports():
    # Dynamic base dir should exist and contain gateway files
    assert os.path.exists(config.BASE_DIR)
    assert os.path.isabs(config.BASE_DIR)
    
    # DB and evidence paths
    assert config.DB_PATH == os.path.join(config.BASE_DIR, "gateway.db")
    assert config.RECEIVER_DB_PATH == os.path.join(config.BASE_DIR, "receiver_inbox.db")
    assert config.EVIDENCE_DIR == os.path.join(config.BASE_DIR, "evidence")
    
    # Secret key
    assert config.SECRET_KEY == "windows-sec-lab-key-2026" or os.getenv("SECRET_KEY") == config.SECRET_KEY
    
    # Port assignments
    assert config.GATEWAY_PORT == 1025
    assert config.RECEIVER_SMTP_PORT == 1026
    assert config.SENDER_UI_PORT == 8001
    assert config.RECEIVER_UI_PORT == 8002
    assert config.DASHBOARD_PORT == 5000


def test_db_context_manager(tmp_path):
    test_db = str(tmp_path / "test.db")
    
    with get_db(test_db) as conn:
        conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO test_table (name) VALUES (?)", ("alpha",))
        
    with get_db(test_db) as conn:
        row = conn.execute("SELECT * FROM test_table WHERE name = ?", ("alpha",)).fetchone()
        assert row is not None
        assert row["name"] == "alpha"
        assert row[1] == "alpha"


def test_db_rollback_on_exception(tmp_path):
    test_db = str(tmp_path / "test_rollback.db")
    with get_db(test_db) as conn:
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, val TEXT)")

    with pytest.raises(RuntimeError):
        with get_db(test_db) as conn:
            conn.execute("INSERT INTO items (val) VALUES (?)", ("should_rollback",))
            raise RuntimeError("Forced failure")

    with get_db(test_db) as conn:
        rows = conn.execute("SELECT * FROM items").fetchall()
        assert len(rows) == 0


def test_init_gateway_db(tmp_path):
    test_db = str(tmp_path / "gateway_test.db")
    init_gateway_db(db_path=test_db)

    with get_db(test_db) as conn:
        # Check messages table columns
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(messages)").fetchall()]
        expected_cols = [
            "id", "timestamp", "sender", "recipient", "subject",
            "score", "decision", "sha256_hash", "eml_path"
        ]
        for col in expected_cols:
            assert col in cols, f"Missing column {col} in messages table"

        # Check users table columns
        user_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        expected_user_cols = ["id", "username", "password_hash", "role"]
        for col in expected_user_cols:
            assert col in user_cols, f"Missing column {col} in users table"

        # Check admin user seed
        admin = conn.execute("SELECT * FROM users WHERE username = ?", ("admin",)).fetchone()
        assert admin is not None
        assert admin["username"] == "admin"
        assert admin["role"] == "admin"
        assert check_password_hash(admin["password_hash"], "Admin@123456")

    # Calling init again should be idempotent and not fail or duplicate
    init_gateway_db(db_path=test_db)
    with get_db(test_db) as conn:
        count = conn.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'").fetchone()[0]
        assert count == 1


def test_user_authentication_helpers(tmp_path):
    test_db = str(tmp_path / "auth_test.db")
    init_gateway_db(db_path=test_db)

    # Valid credentials
    user = verify_user("admin", "Admin@123456", db_path=test_db)
    assert user is not None
    assert user["username"] == "admin"

    # Invalid credentials
    assert verify_user("admin", "WrongPassword", db_path=test_db) is None
    assert verify_user("nonexistent", "Admin@123456", db_path=test_db) is None


def test_email_message_model():
    msg = EmailMessage(
        sender="attacker@phish.xyz",
        recipient="victim@corp.local",
        subject="Action Required",
        score=85.0,
        decision="BLOCK",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        eml_path="evidence/test.eml",
    )
    d = msg.to_dict()
    assert d["sender"] == "attacker@phish.xyz"
    assert d["decision"] == "BLOCK"
    assert d["score"] == 85.0

    # Reconstruction from dict
    restored = EmailMessage.from_dict(d)
    assert restored.sender == msg.sender
    assert restored.score == msg.score
    assert restored.sha256_hash == msg.sha256_hash


def test_audit_record_model():
    record = AuditRecord(
        action="INSPECT_EMAIL",
        actor="gateway_worker_1",
        target="msg_101",
        details={"verdict": "QUARANTINE", "score": 45.0},
        sha256_hash="abc123hash",
    )
    d = record.to_dict()
    assert d["action"] == "INSPECT_EMAIL"
    assert d["actor"] == "gateway_worker_1"
    assert d["details"]["verdict"] == "QUARANTINE"

    restored = AuditRecord.from_dict(d)
    assert restored.action == record.action
    assert restored.details == record.details


def test_user_session_model():
    admin_session = UserSession(username="admin", role="admin")
    assert admin_session.is_admin is True

    user_session = UserSession(username="analyst", role="user")
    assert user_session.is_admin is False

    d = admin_session.to_dict()
    assert d["is_admin"] is True
    assert d["username"] == "admin"

