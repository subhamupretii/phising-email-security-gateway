from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional
from werkzeug.security import generate_password_hash, check_password_hash

from shared.config import DB_PATH, EVIDENCE_DIR, WEBMAIL_DB_PATH


@contextmanager
def get_db(db_path: str = DB_PATH, timeout: float = 15.0) -> Generator[sqlite3.Connection, None, None]:
    """SQLite connection context manager with WAL mode, row-factory, and transaction management.

    WAL (Write-Ahead Logging) allows concurrent reads while the gateway writes,
    eliminating the "database is locked" errors that cause intermittent freezes.
    busy_timeout via PRAGMA avoids spinning; synchronous=NORMAL balances safety & speed.
    """
    conn = sqlite3.connect(db_path, timeout=timeout)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent reads+writes without locking
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=15000;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_gateway_db(db_path: str = DB_PATH) -> None:
    """Initialize gateway database schema and seed default admin user if missing.

    Creates:
      - messages table (id, timestamp, sender, recipient, subject, score, decision, sha256_hash, eml_path)
      - users table (id, username, password_hash, role)
      - Default admin user (admin / Admin@123456)
    """
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # Messages table for gateway inspection verdicts & forensic metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                score REAL NOT NULL,
                decision TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                eml_path TEXT,
                ai_score INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'ALLOW',
                is_deleted INTEGER DEFAULT 0,
                deleted_at TEXT DEFAULT NULL,
                verification_status TEXT DEFAULT 'UNVERIFIED',
                last_verified_at TEXT DEFAULT NULL
            )
        """)

        # Auto-migration for existing gateway messages / logs tables
        for col_def in [
            ("ai_score", "INTEGER DEFAULT 0"),
            ("threat_score", "INTEGER DEFAULT 0"),
            ("verdict", "TEXT DEFAULT 'ALLOW'"),
            ("is_deleted", "INTEGER DEFAULT 0"),
            ("deleted_at", "TEXT DEFAULT NULL"),
            ("verification_status", "TEXT DEFAULT 'UNVERIFIED'"),
            ("last_verified_at", "TEXT DEFAULT NULL"),
        ]:
            try:
                cursor.execute(f"ALTER TABLE messages ADD COLUMN {col_def[0]} {col_def[1]}")
            except sqlite3.OperationalError:
                pass

        # Also support alias table 'logs' if created or queried
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                ai_score INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'ALLOW',
                score REAL NOT NULL,
                decision TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                eml_path TEXT,
                is_deleted INTEGER DEFAULT 0,
                deleted_at TEXT DEFAULT NULL,
                verification_status TEXT DEFAULT 'UNVERIFIED',
                last_verified_at TEXT DEFAULT NULL
            )
        """)
        for col_def in [
            ("ai_score", "INTEGER DEFAULT 0"),
            ("threat_score", "INTEGER DEFAULT 0"),
            ("verdict", "TEXT DEFAULT 'ALLOW'"),
            ("is_deleted", "INTEGER DEFAULT 0"),
            ("deleted_at", "TEXT DEFAULT NULL"),
            ("verification_status", "TEXT DEFAULT 'UNVERIFIED'"),
            ("last_verified_at", "TEXT DEFAULT NULL"),
        ]:
            try:
                cursor.execute(f"ALTER TABLE logs ADD COLUMN {col_def[0]} {col_def[1]}")
            except sqlite3.OperationalError:
                pass

        # Users table for dashboard/gateway role-based access
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)

        # Auto-seed default admin user (admin / Admin@123456)
        cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        admin_user = cursor.fetchone()
        if not admin_user:
            admin_hash = generate_password_hash("Admin@123456")
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", admin_hash, "admin"),
            )


def purge_expired_deleted_cases(db_path: str = DB_PATH) -> int:
    """Permanently delete cases marked is_deleted=1 where deleted_at is older than 30 days.

    Uses SQLite datetime() functions to purge records.
    Returns the total count of purged rows.
    """
    purged_count = 0
    try:
        with get_db(db_path) as conn:
            # Check messages table
            cursor = conn.cursor()
            cursor.execute(
                """
                DELETE FROM messages
                WHERE is_deleted = 1
                  AND deleted_at IS NOT NULL
                  AND datetime(deleted_at) <= datetime('now', '-30 days')
                """
            )
            purged_count += cursor.rowcount

            # If logs table exists, also clean it
            try:
                cursor.execute(
                    """
                    DELETE FROM logs
                    WHERE is_deleted = 1
                      AND deleted_at IS NOT NULL
                      AND datetime(deleted_at) <= datetime('now', '-30 days')
                    """
                )
                purged_count += cursor.rowcount
            except Exception:
                pass
    except Exception:
        pass
    return purged_count


def get_user_by_username(username: str, db_path: str = DB_PATH) -> Optional[sqlite3.Row]:
    """Fetch user record by username."""
    with get_db(db_path) as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


# Default lab mailboxes. Created only when the address is not already present.
DEFAULT_WEBMAIL_USERS = (
    "user1@lab.local",
    "user2@lab.local",
    "user3@lab.local",
)
DEFAULT_WEBMAIL_PASSWORD = "User@123456"


def init_webmail_db(db_path: str = WEBMAIL_DB_PATH) -> None:
    """Initialize the multi-user webmail database and seed lab accounts.

    Creates:
      - users table (id, email, password_hash)
      - inbox table (id, recipient, sender, subject, body, is_read, timestamp)
      - user1@lab.local, user2@lab.local, user3@lab.local when missing
        (password: User@123456)
    """
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with get_db(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                folder TEXT NOT NULL DEFAULT 'inbox',
                ai_score INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                verdict TEXT DEFAULT 'ALLOW'
            )
            """
        )

        # Auto-migration: ensure folder, ai_score, threat_score, verdict columns exist
        for col_def in [
            ("folder", "TEXT DEFAULT 'inbox'"),
            ("ai_score", "INTEGER DEFAULT 0"),
            ("threat_score", "INTEGER DEFAULT 0"),
            ("verdict", "TEXT DEFAULT 'ALLOW'"),
        ]:
            try:
                conn.execute(f"ALTER TABLE inbox ADD COLUMN {col_def[0]} {col_def[1]}")
            except sqlite3.OperationalError:
                # Column already exists
                pass

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_inbox_recipient ON inbox (recipient)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_inbox_folder ON inbox (folder)"
        )

        for email in DEFAULT_WEBMAIL_USERS:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, generate_password_hash(DEFAULT_WEBMAIL_PASSWORD)),
                )


def get_webmail_user_by_email(
    email: str,
    db_path: str = WEBMAIL_DB_PATH,
) -> Optional[sqlite3.Row]:
    """Fetch a webmail user by email address (case-insensitive)."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    with get_db(db_path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (normalized,),
        ).fetchone()


def verify_webmail_user(
    email: str,
    password: str,
    db_path: str = WEBMAIL_DB_PATH,
) -> Optional[sqlite3.Row]:
    """Return the webmail user row when the email and password match."""
    user = get_webmail_user_by_email(email, db_path=db_path)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def create_webmail_user(
    email: str,
    password: str,
    db_path: str = WEBMAIL_DB_PATH,
) -> Optional[sqlite3.Row]:
    """Insert a webmail account. Returns None when the email is already taken."""
    normalized = (email or "").strip().lower()
    if not normalized or not password:
        return None
    with get_db(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (normalized,),
        ).fetchone()
        if existing:
            return None
        conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (normalized, generate_password_hash(password)),
        )
    return get_webmail_user_by_email(normalized, db_path=db_path)


def verify_user(username: str, password: str, db_path: str = DB_PATH) -> Optional[sqlite3.Row]:
    """Verify user credentials against stored password hashes.

    Returns the user row if valid, None otherwise.
    """
    user = get_user_by_username(username, db_path=db_path)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None

