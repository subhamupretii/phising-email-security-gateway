from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now_iso() -> str:
    """Return the current ISO-formatted UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EmailMessage:
    """Represents an email message inspected and stored by the security gateway."""
    sender: str
    recipient: str
    subject: str
    id: Optional[int] = None
    timestamp: str = field(default_factory=utc_now_iso)
    score: float = 0.0
    decision: str = "ALLOW"
    sha256_hash: str = ""
    eml_path: Optional[str] = None
    body: str = ""
    raw_content: Optional[bytes] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert message to dictionary representation."""
        data = asdict(self)
        if isinstance(data.get("raw_content"), bytes):
            data["raw_content"] = data["raw_content"].decode("utf-8", errors="replace")
        return data

    @classmethod
    def from_row(cls, row: sqlite3.Row | dict[str, Any]) -> EmailMessage:
        """Construct an EmailMessage from a sqlite3.Row or mapping."""
        d = dict(row)
        return cls(
            id=d.get("id"),
            timestamp=d.get("timestamp") or utc_now_iso(),
            sender=d.get("sender", ""),
            recipient=d.get("recipient", ""),
            subject=d.get("subject", ""),
            score=float(d.get("score", 0.0)),
            decision=d.get("decision", "ALLOW"),
            sha256_hash=d.get("sha256_hash", ""),
            eml_path=d.get("eml_path"),
            body=d.get("body", ""),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmailMessage:
        """Construct an EmailMessage from a dictionary."""
        return cls(
            id=data.get("id"),
            timestamp=data.get("timestamp") or utc_now_iso(),
            sender=data.get("sender", ""),
            recipient=data.get("recipient", ""),
            subject=data.get("subject", ""),
            score=float(data.get("score", 0.0)),
            decision=data.get("decision", "ALLOW"),
            sha256_hash=data.get("sha256_hash", ""),
            eml_path=data.get("eml_path"),
            body=data.get("body", ""),
            raw_content=data.get("raw_content") if isinstance(data.get("raw_content"), bytes) else None,
        )


@dataclass
class AuditRecord:
    """Represents a forensic audit log event for NIST SP 800-86 compliance."""
    action: str
    id: Optional[int] = None
    timestamp: str = field(default_factory=utc_now_iso)
    actor: str = "system"
    target: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    sha256_hash: str = ""
    status: str = "SUCCESS"

    def to_dict(self) -> dict[str, Any]:
        """Convert audit record to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditRecord:
        """Construct an AuditRecord from a dictionary."""
        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {"raw": details}
        return cls(
            id=data.get("id"),
            timestamp=data.get("timestamp") or utc_now_iso(),
            action=data.get("action", ""),
            actor=data.get("actor", "system"),
            target=data.get("target", ""),
            details=details,
            sha256_hash=data.get("sha256_hash", ""),
            status=data.get("status", "SUCCESS"),
        )


@dataclass
class UserSession:
    """Represents an authenticated user session in the gateway dashboard."""
    username: str
    user_id: Optional[int] = None
    role: str = "user"
    is_authenticated: bool = True
    created_at: str = field(default_factory=utc_now_iso)
    session_id: Optional[str] = None

    @property
    def is_admin(self) -> bool:
        """Check if the user has administrative privileges."""
        return self.role.lower() == "admin"

    def to_dict(self) -> dict[str, Any]:
        """Convert user session to dictionary representation."""
        data = asdict(self)
        data["is_admin"] = self.is_admin
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserSession:
        """Construct a UserSession from a dictionary."""
        return cls(
            user_id=data.get("user_id"),
            username=data.get("username", ""),
            role=data.get("role", "user"),
            is_authenticated=data.get("is_authenticated", True),
            created_at=data.get("created_at") or utc_now_iso(),
            session_id=data.get("session_id"),
        )

