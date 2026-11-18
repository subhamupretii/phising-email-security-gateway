from email.message import EmailMessage
from email import policy

from app.analyzer import analyse_email


def to_bytes(subject: str, body: str) -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "sender@lab.test"
    message["To"] = "recipient@lab.test"
    message["Subject"] = subject
    message.set_content(body)
    return message.as_bytes()


def test_harmless_message_is_allow():
    result = analyse_email(to_bytes("Hello", "A harmless note: https://example.com/"))
    assert result["decision"] == "ALLOW"


def test_synthetic_phishing_message_is_blocked():
    result = analyse_email(
        to_bytes(
            "URGENT: Verify your account immediately",
            "Do not visit this synthetic URL: http://login-verify.example.invalid/account",
        )
    )
    assert result["decision"] == "BLOCK"
    assert result["risk_score"] >= 40
