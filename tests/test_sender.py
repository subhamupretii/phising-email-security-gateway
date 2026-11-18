import email
from email import policy
import pytest
from unittest.mock import patch, MagicMock

from services.sender.app import create_sender_app
from services.gateway.heuristics import analyse_email


@pytest.fixture
def sender_client():
    app = create_sender_app(gateway_host="127.0.0.1", gateway_port=1025)
    app.config["TESTING"] = True
    return app.test_client()


def test_sender_index_view(sender_client):
    res = sender_client.get("/")
    assert res.status_code == 200
    assert b"Sender Webmail Simulator" in res.data
    assert b"Automated Security Test Templates" in res.data
    assert b"Clean Email" in res.data
    assert b"Phishing Email" in res.data
    assert b"High-Risk Attack" in res.data
    assert b"127.0.0.1:1025" in res.data


def test_sender_validation_missing_fields(sender_client):
    # Missing recipient
    res = sender_client.post("/send", data={
        "sender": "sender@test.local",
        "recipient": "",
        "subject": "Hello",
        "body": "Test message"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Both Sender and Recipient addresses are required" in res.data

    # Missing sender via JSON
    json_res = sender_client.post("/send", json={
        "sender": "",
        "recipient": "rcpt@test.local",
        "subject": "Hello",
        "body": "Test message"
    })
    assert json_res.status_code == 400
    assert json_res.get_json()["status"] == "error"


def test_sender_dispatch_success_form(sender_client):
    with patch("services.sender.app.smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        res = sender_client.post("/send", data={
            "sender": "alice@company.local",
            "recipient": "bob@receiverserver.lab",
            "subject": "Operations Status Update",
            "body": "All servers operational.",
            "is_html": "on"
        }, follow_redirects=True)

        assert res.status_code == 200
        assert b"Email successfully dispatched to Email Security Gateway" in res.data

        # Verify SMTP client was invoked
        assert mock_instance.send_message.called
        sent_msg = mock_instance.send_message.call_args[0][0]
        assert sent_msg["From"] == "alice@company.local"
        assert sent_msg["To"] == "bob@receiverserver.lab"
        assert sent_msg["Subject"] == "Operations Status Update"


def test_sender_dispatch_success_json(sender_client):
    with patch("services.sender.app.smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        res = sender_client.post("/send", json={
            "sender": "security@alert.lab",
            "recipient": "user@victim.lab",
            "subject": "Account Notice",
            "body": "Please review account details."
        })

        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        assert data["sender"] == "security@alert.lab"
        assert mock_instance.send_message.called


def test_sender_dispatch_gateway_offline_graceful_handling(sender_client):
    with patch("services.sender.app.smtplib.SMTP") as mock_smtp:
        mock_smtp.side_effect = ConnectionRefusedError("Connection refused by gateway")

        res = sender_client.post("/send", data={
            "sender": "user@test.local",
            "recipient": "victim@test.local",
            "subject": "Test",
            "body": "Hello world"
        }, follow_redirects=True)

        assert res.status_code == 200
        assert b"Failed to dispatch email to Gateway" in res.data

        # Same for JSON
        json_res = sender_client.post("/send", json={
            "sender": "user@test.local",
            "recipient": "victim@test.local",
            "subject": "Test",
            "body": "Hello world"
        })
        assert json_res.status_code == 502
        assert json_res.get_json()["status"] == "error"


def test_template_presets_heuristics_verdicts():
    """Verify that the 3 templates in index.html match their designated gateway verdicts."""

    # 1. Clean Template -> ALLOW (Score < 35)
    clean_body = (
        "Hi Team,\n\n"
        "Please find the quarterly infrastructure operational report summary below.\n"
        "All core cloud services, network gateways, and server nodes are operating normally.\n"
        "Best regards,\nOperations Team"
    )
    clean_bytes = (
        f"From: operations@company.local\r\n"
        f"To: team@company.local\r\n"
        f"Subject: Quarterly Infrastructure & Operations Status Update\r\n\r\n"
        f"{clean_body}"
    ).encode()
    clean_res = analyse_email(clean_bytes)
    assert clean_res["decision"] == "ALLOW"
    assert clean_res["score"] < 35

    # 2. Phishing Template with IP link -> QUARANTINE (35 - 69)
    phish_body = (
        "Dear User,\n\n"
        "Your corporate domain account has been flagged for a potential suspension warning.\n"
        "Please access your profile portal at http://192.168.1.50/login to complete the standard identity check.\n"
        "IT Administration"
    )
    phish_bytes = (
        f"From: security-notify@senderserver.lab\r\n"
        f"To: employee@receiverserver.lab\r\n"
        f"Subject: Account Notice: Suspension Warning\r\n\r\n"
        f"{phish_body}"
    ).encode()
    phish_res = analyse_email(phish_bytes)
    assert phish_res["decision"] == "QUARANTINE"
    assert 35 <= phish_res["score"] <= 69
    assert len(phish_res["ip_links"]) > 0

    # 3. High-Risk Attack Template -> BLOCK (70+)
    block_body = (
        "SECURITY ALERT: Urgent action required!\n\n"
        "Unauthorized suspicious activity was detected on your corporate account.\n"
        "You must verify and reset your password immediately at http://login-verify.example.invalid/reset "
        "or your access will be permanently compromised."
    )
    block_bytes = (
        f"From: attacker@spoofed-phish.xyz\r\n"
        f"To: victim@receiverserver.lab\r\n"
        f"Subject: URGENT SECURITY ALERT: Immediate Password Reset Required\r\n\r\n"
        f"{block_body}"
    ).encode()
    block_res = analyse_email(block_bytes)
    assert block_res["decision"] == "BLOCK"
    assert block_res["score"] >= 70
    assert len(block_res["high_risk_tld_links"]) > 0

