"""
Transactions, Segregation of Duties, and RBAC Authorization Tests
Verifies that multi-step transactions maintain integrity and RBAC policies are enforced.
"""
import pytest
from app.repositories.factory import get_repository

def test_segregation_of_duties_enforcement(client, auth_headers_infra, auth_headers_analyst):
    # Vulnerability #1 is assigned to user_id=2 (infra engineer)
    # The infra engineer attempts to verify their own remediation
    res_self = client.post("/api/vulnerabilities/1/verify", headers=auth_headers_infra, json={
        "verification_notes": "I fixed it and I verify it myself."
    })
    # Must fail due to segregation of duties violation
    assert res_self.status_code == 403
    assert "segregation of duties" in res_self.get_json()["message"].lower()

    # Now independent SOC analyst (user_id=1) verifies the remediation
    res_independent = client.post("/api/vulnerabilities/1/verify", headers=auth_headers_analyst, json={
        "verification_notes": "Validated independently via scan."
    })
    assert res_independent.status_code == 200
    assert res_independent.get_json()["status"] == "success"

def test_admin_only_user_provisioning(client, auth_headers_analyst, auth_headers_admin):
    # Security Analyst tries to provision a user -> 403 Forbidden
    res_denied = client.post("/api/users", headers=auth_headers_analyst, json={
        "email": "new_unauthorized@nexora.test",
        "full_name": "Unauthorized User",
        "title": "Engineer",
        "department_id": 1,
        "role_id": 1
    })
    assert res_denied.status_code == 403
    assert "only admin" in res_denied.get_json()["message"].lower()

    # Enterprise Admin provisions a user -> 201 Created
    res_allowed = client.post("/api/users", headers=auth_headers_admin, json={
        "email": "authorized_new@nexora.test",
        "full_name": "Authorized Provisioned User",
        "title": "Analyst",
        "department_id": 1,
        "role_id": 1
    })
    assert res_allowed.status_code == 201
    assert res_allowed.get_json()["status"] == "success"

def test_manager_only_risk_treatment_approval(client, auth_headers_analyst, auth_headers_manager):
    # Analyst attempts to authorize a risk treatment -> 403 Forbidden
    res_denied = client.post("/api/risks/treatments/1/approve", headers=auth_headers_analyst, json={
        "expiry_date": "2027-12-31"
    })
    assert res_denied.status_code == 403

    # Security Manager approves risk treatment -> 200 OK
    res_allowed = client.post("/api/risks/treatments/1/approve", headers=auth_headers_manager, json={
        "expiry_date": "2027-12-31"
    })
    assert res_allowed.status_code == 200
    assert res_allowed.get_json()["status"] == "success"


def test_user_provisioning_does_not_return_password_hash(client, auth_headers_admin):
    response = client.post(
        "/api/users",
        headers=auth_headers_admin,
        json={"email": "safe-user@nexora.test", "full_name": "Safe User", "role_id": 1},
    )
    assert response.status_code == 201
    assert "password_hash" not in response.get_json()["data"]
