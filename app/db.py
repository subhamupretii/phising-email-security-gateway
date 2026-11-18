from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = "/home/kali/Desktop/phishing_email_security_gateway/gateway.db"

def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS email_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipients TEXT NOT NULL,
                subject TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                evidence_path TEXT NOT NULL,
                quarantine_path TEXT
            )
            """
        )
        connection.commit()


def insert_email_record(record: dict[str, Any]) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO email_records (
                received_at, sender, recipients, subject, decision,
                risk_score, reasons, sha256, evidence_path, quarantine_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["received_at"],
                record["sender"],
                json.dumps(record["recipients"]),
                record["subject"],
                record["decision"],
                record["risk_score"],
                json.dumps(record["reasons"]),
                record["sha256"],
                record["evidence_path"],
                record.get("quarantine_path"),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_email_records(limit: int = 100) -> list[sqlite3.Row]:
    with get_connection() as connection:
        return list(
            connection.execute(
                "SELECT * FROM email_records ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        )


def get_email_record(record_id: int) -> sqlite3.Row | None:
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM email_records WHERE id = ?", (record_id,)
        ).fetchone()
