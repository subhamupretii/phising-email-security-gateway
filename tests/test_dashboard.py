import hashlib
import os
import pytest
from services.dashboard.app import create_app
from shared.db import init_gateway_db, get_db


@pytest.fixture
def app_and_db(tmp_path):
    test_db = str(tmp_path / "dashboard_test.db")
    evidence_dir = str(tmp_path / "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    init_gateway_db(test_db)

    # Seed a sample message with payload
    sample_content = b"From: attacker@bad.xyz\r\nTo: user@target.local\r\nSubject: Critical Alert\r\n\r\nUrgent password reset."
    sample_hash = hashlib.sha256(sample_content).hexdigest()
    eml_file = os.path.join(evidence_dir, "sample.eml")
    with open(eml_file, "wb") as f:
        f.write(sample_content)

    with get_db(test_db) as conn:
        conn.execute("""
            INSERT INTO messages (timestamp, sender, recipient, subject, score, decision, sha256_hash, eml_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "2026-11-04T00:00:00Z",
            "attacker@bad.xyz",
            "user@target.local",
            "Critical Alert",
            85.0,
            "BLOCK",
            sample_hash,
            eml_file
        ))

    app = create_app(db_path=test_db, evidence_dir=evidence_dir)
    app.config["TESTING"] = True
    return app, test_db, eml_file, sample_hash


def test_unauthenticated_access_redirects_to_login(app_and_db):
    app, _, _, _ = app_and_db
    client = app.test_client()

    # Protected routes must redirect to login
    response = client.get("/")
    assert response.status_code in (302, 303)
    assert "/login" in response.headers["Location"]

    api_resp = client.get("/api/stats")
    assert api_resp.status_code in (302, 303)
    assert "/login" in api_resp.headers["Location"]


def test_login_success_and_logout(app_and_db):
    app, _, _, _ = app_and_db
    client = app.test_client()

    # GET /login renders successfully
    get_res = client.get("/login")
    assert get_res.status_code == 200
    assert b"Threat Gateway Portal" in get_res.data

    # POST valid credentials
    post_res = client.post("/login", data={
        "username": "admin",
        "password": "Admin@123456"
    }, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"Security Gateway Audit Dashboard" in post_res.data
    assert b"admin" in post_res.data

    # Logout
    logout_res = client.get("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"Sign In to Dashboard" in logout_res.data


def test_login_invalid_credentials(app_and_db):
    app, _, _, _ = app_and_db
    client = app.test_client()

    # Wrong password
    post_res = client.post("/login", data={
        "username": "admin",
        "password": "WrongPassword!"
    }, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"Invalid username or password" in post_res.data


def test_dashboard_views_and_stats(app_and_db):
    app, _, eml_path, sample_hash = app_and_db
    client = app.test_client()

    # Log in first
    client.post("/login", data={"username": "admin", "password": "Admin@123456"})

    # 1. Main index view
    res = client.get("/")
    assert res.status_code == 200
    assert b"Critical Alert" in res.data
    assert b"BLOCK" in res.data

    # 2. API Stats JSON
    api_res = client.get("/api/stats")
    assert api_res.status_code == 200
    data = api_res.get_json()
    assert data["block"] == 1
    assert data["allow"] == 0
    assert data["total"] == 1

    # 3. Message Detail View
    detail_res = client.get("/message/1")
    assert detail_res.status_code == 200
    assert b"Raw RFC 5322 Evidence Payload" in detail_res.data
    assert b"Urgent password reset." in detail_res.data

    # 4. NIST SP 800-86 Cryptographic Hash Verification View
    verify_res = client.get("/verify/1")
    assert verify_res.status_code == 200
    assert b"FORENSIC INTEGRITY VERIFIED" in verify_res.data
    assert sample_hash.encode() in verify_res.data

    # 5. Evidence file download
    dl_res = client.get("/download/1")
    assert dl_res.status_code == 200
    assert dl_res.data == b"From: attacker@bad.xyz\r\nTo: user@target.local\r\nSubject: Critical Alert\r\n\r\nUrgent password reset."
    dl_res.close()

    # 6. Non-existent message returns 404
    assert client.get("/message/999").status_code == 404
    assert client.get("/verify/999").status_code == 404

    # 7. Forensic SHA-256 API verification endpoint tests
    # Test valid/verified state
    verify_api_res = client.get("/api/verify/1")
    assert verify_api_res.status_code == 200
    v_data = verify_api_res.get_json()
    assert v_data["status"] == "VERIFIED"
    assert v_data["stored_hash"] == sample_hash
    assert v_data["current_hash"] == sample_hash

    # Test POST request to /api/verify/1
    post_verify = client.post("/api/verify/1")
    assert post_verify.status_code == 200
    assert post_verify.get_json()["status"] == "VERIFIED"

    # Test missing message returns 404
    assert client.get("/api/verify/999").status_code == 404

    # Test tampered file
    with open(eml_path, "wb") as f:
        f.write(b"Tampered content! Malicious alteration.")
    tampered_res = client.get("/api/verify/1")
    assert tampered_res.status_code == 200
    t_data = tampered_res.get_json()
    assert t_data["status"] == "TAMPERED"
    assert t_data["stored_hash"] == sample_hash
    assert t_data["current_hash"] != sample_hash

    # Test missing file
    os.remove(eml_path)
    missing_res = client.get("/api/verify/1")
    assert missing_res.status_code == 200
    m_data = missing_res.get_json()
    assert m_data["status"] == "MISSING_FILE"
    assert m_data["stored_hash"] == sample_hash
    assert m_data["current_hash"] == ""

    # 8. Test /api/logs/<id>/inspect
    inspect_res = client.get("/api/logs/1/inspect")
    assert inspect_res.status_code == 200
    i_data = inspect_res.get_json()
    assert i_data["id"] == 1
    assert i_data["subject"] == "Critical Alert"
    assert "ai_score" in i_data
    assert "threat_score" in i_data

    # 9. Test /api/logs/<id>/verify-hash
    vh_res = client.post("/api/logs/1/verify-hash")
    assert vh_res.status_code == 200
    vh_data = vh_res.get_json()
    assert vh_data["status"] == "FILE_MISSING"  # because eml_path was removed above

    # 10. Test Soft-Delete, Restore, Delete-All, and /deleted route
    del_res = client.post("/api/logs/1/delete")
    assert del_res.status_code == 200
    assert del_res.get_json()["status"] == "deleted"

    # Main dashboard now excludes deleted case
    main_res = client.get("/")
    assert b"Critical Alert" not in main_res.data

    # Deleted page shows the soft-deleted case
    deleted_page = client.get("/deleted")
    assert deleted_page.status_code == 200
    assert b"Critical Alert" in deleted_page.data
    assert b"30 days left" in deleted_page.data or b"days left" in deleted_page.data

    # Restore case
    restore_res = client.post("/api/logs/1/restore")
    assert restore_res.status_code == 200
    assert restore_res.get_json()["status"] == "restored"

    # Restored case is back on main dashboard
    main_res2 = client.get("/")
    assert b"Critical Alert" in main_res2.data

    # Delete all
    del_all_res = client.post("/api/logs/delete-all")
    assert del_all_res.status_code == 200
    assert del_all_res.get_json()["status"] == "deleted_all"
    main_res3 = client.get("/")
    assert b"Critical Alert" not in main_res3.data


def test_stateless_hash_verification_all_states(app_and_db):
    app, test_db, eml_path, sample_hash = app_and_db
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "Admin@123456"})

    # 1. State 1: VERIFIED (stored hash matches live disk file)
    res_verified = client.post("/api/logs/1/verify-hash")
    assert res_verified.status_code == 200
    data_v = res_verified.get_json()
    assert data_v["status"] == "VERIFIED"
    assert data_v["stored_hash"] == sample_hash
    assert data_v["computed_hash"] == sample_hash

    # Confirm database remains unchanged (stateless, no status or flag cached)
    with get_db(test_db) as conn:
        row = conn.execute("SELECT * FROM messages WHERE id = 1").fetchone()
        assert "is_verified" not in row.keys()
        assert "verification_status" not in row.keys()

    # 2. State 2: TAMPERED (modify bytes on disk)
    with open(eml_path, "wb") as f:
        f.write(b"Maliciously altered content payload.")
    res_tampered = client.post("/api/logs/1/verify-hash")
    assert res_tampered.status_code == 200
    data_t = res_tampered.get_json()
    assert data_t["status"] == "TAMPERED"
    assert data_t["stored_hash"] == sample_hash
    assert data_t["computed_hash"] != sample_hash
    assert data_t["computed_hash"] == hashlib.sha256(b"Maliciously altered content payload.").hexdigest()

    # 3. State 3: FILE_MISSING (remove file from disk)
    os.remove(eml_path)
    res_missing = client.post("/api/logs/1/verify-hash")
    assert res_missing.status_code == 200
    data_m = res_missing.get_json()
    assert data_m["status"] == "FILE_MISSING"
    assert data_m["stored_hash"] == sample_hash
    assert data_m["computed_hash"] == ""


