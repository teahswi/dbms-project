"""
Authentication, Authorization, and Security Tests
Tests bcrypt hashing, failed attempt lockouts, JWT claims, and endpoint protections.
"""
import pytest
from app.services.auth_service import AuthService, MAX_FAILED_ATTEMPTS

def test_password_hashing():
    pwd = "SecureTestPassword123!"
    hashed = AuthService.hash_password(pwd)
    assert hashed != pwd
    assert AuthService.verify_password(pwd, hashed) is True
    assert AuthService.verify_password("WrongPassword", hashed) is False

def test_login_success(client):
    res = client.post("/api/auth/login", json={
        "email": "analyst@nexora.test",
        "password": "Nexora@2026"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "access_token" in data["data"]
    assert data["data"]["user"]["email"] == "analyst@nexora.test"
    assert data["data"]["user"]["role"] == "Security Analyst"

def test_login_invalid_credentials(client):
    res = client.post("/api/auth/login", json={
        "email": "analyst@nexora.test",
        "password": "IncorrectPassword999"
    })
    assert res.status_code == 401
    data = res.get_json()
    assert data["status"] == "error"
    assert "Invalid password" in data["message"]

def test_missing_credentials(client):
    res = client.post("/api/auth/login", json={"email": ""})
    assert res.status_code == 400

    res2 = client.post("/api/auth/login", json={"email": "analyst@nexora.test"})
    assert res2.status_code == 400

def test_unauthenticated_protected_route(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401
    data = res.get_json()
    assert data["status"] == "error"

def test_authenticated_me_endpoint(client, auth_headers_analyst):
    res = client.get("/api/auth/me", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert data["user"]["email"] == "analyst@nexora.test"
    assert data["user"]["role"] == "Security Analyst"
    assert "permissions" in data["user"]

def test_demo_accounts_endpoint(client):
    res = client.get("/api/auth/demo-accounts")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert len(data["accounts"]) == 5

def test_account_lockout_threshold(client):
    # Create or test on a dedicated user to avoid locking out test persona
    from app.repositories.factory import get_repository
    repo = get_repository()
    pwd_hash = AuthService.hash_password("UserSpecificPass1!")
    user = repo.create_user({
        "email": "lockout_test@nexora.test",
        "password_hash": pwd_hash,
        "full_name": "Lockout Test User",
        "title": "Tester",
        "department_id": 1,
        "role_id": 1,
        "is_active": True
    })

    # Trigger failed attempts
    for i in range(MAX_FAILED_ATTEMPTS):
        res = client.post("/api/auth/login", json={
            "email": "lockout_test@nexora.test",
            "password": "WrongPasswordAttempt"
        })
        assert res.status_code == 401

    # 6th attempt should be locked out
    locked_res = client.post("/api/auth/login", json={
        "email": "lockout_test@nexora.test",
        "password": "UserSpecificPass1!"
    })
    assert locked_res.status_code == 401
    assert "locked" in locked_res.get_json()["message"].lower()
