"""
API Endpoints and Workflows Integration Tests
Tests all core blueprints, query parameters, cross-module workflows, state transitions, and error handling.
"""
import pytest

def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert data["database"]["active_engine"] in ["SQLite", "MySQL", "MongoDB", "Memory"]
    assert "is_fallback" in data["database"]

def test_dashboard_posture_endpoint(client, auth_headers_analyst):
    res = client.get("/api/dashboard/posture", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    posture = data["data"]
    assert "posture_score" in posture
    assert "asset_count" in posture
    assert "open_vulnerabilities" in posture
    assert "critical_vulnerabilities" in posture
    assert "department_exposure" in posture
    assert "aging_funnel" in posture

def test_assets_endpoints(client, auth_headers_analyst):
    # List assets
    res = client.get("/api/assets", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] > 0

    # Filter assets
    res_filtered = client.get("/api/assets?criticality=5", headers=auth_headers_analyst)
    assert res_filtered.status_code == 200
    assert res_filtered.get_json()["count"] > 0

    # Get single asset
    res_single = client.get("/api/assets/1", headers=auth_headers_analyst)
    assert res_single.status_code == 200
    assert res_single.get_json()["data"]["asset_id"] == 1

    # 404 on nonexistent asset
    res_missing = client.get("/api/assets/999999", headers=auth_headers_analyst)
    assert res_missing.status_code == 404

def test_vulnerabilities_endpoints(client, auth_headers_analyst):
    res = client.get("/api/vulnerabilities", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] > 0

    # Calculate score preview
    res_calc = client.post("/api/vulnerabilities/calculate-preview", headers=auth_headers_analyst, json={
        "cvss_score": 9.8,
        "asset_criticality": 5,
        "exploit_available": True
    })
    assert res_calc.status_code == 200
    calc_data = res_calc.get_json()["data"]
    assert calc_data["priority_score"] >= 80
    assert calc_data["severity"] == "CRITICAL"

def test_alerts_and_incident_escalation(client, auth_headers_analyst):
    res = client.get("/api/alerts", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] > 0

    # Cross-module workflow: escalate alert to incident
    res_esc = client.post("/api/alerts/escalate-to-incident", headers=auth_headers_analyst, json={
        "alert_ids": [1, 2],
        "title": "Correlated APT Intrusion Incident",
        "category": "MALWARE_OUTBREAK",
        "severity": "HIGH"
    })
    assert res_esc.status_code == 201
    esc_data = res_esc.get_json()["data"]
    assert "incident_id" in esc_data

def test_incident_state_transitions(client, auth_headers_analyst):
    # Retrieve an incident
    res = client.get("/api/incidents/1", headers=auth_headers_analyst)
    assert res.status_code == 200
    inc = res.get_json()["data"]

    # Valid transition from OPEN -> TRIAGE
    res_valid = client.put(f"/api/incidents/{inc['incident_id']}/status", headers=auth_headers_analyst, json={
        "status": "TRIAGE"
    })
    assert res_valid.status_code == 200
    assert res_valid.get_json()["data"]["status"] == "TRIAGE"

    # Next valid transition from TRIAGE -> CONTAINMENT
    res_contain = client.put(f"/api/incidents/{inc['incident_id']}/status", headers=auth_headers_analyst, json={
        "status": "CONTAINMENT"
    })
    assert res_contain.status_code == 200
    assert res_contain.get_json()["data"]["status"] == "CONTAINMENT"

    # Invalid transition: jumping to an illegal or nonexistent status
    res_invalid = client.put(f"/api/incidents/{inc['incident_id']}/status", headers=auth_headers_analyst, json={
        "status": "NONEXISTENT_STATUS"
    })
    assert res_invalid.status_code == 400


def test_compliance_and_traceability(client, auth_headers_auditor):
    # Frameworks
    res_f = client.get("/api/compliance/frameworks", headers=auth_headers_auditor)
    assert res_f.status_code == 200
    assert len(res_f.get_json()["data"]) >= 2

    # Traceability matrix
    res_trace = client.get("/api/compliance/traceability", headers=auth_headers_auditor)
    assert res_trace.status_code == 200
    matrix = res_trace.get_json()["data"]
    assert len(matrix) > 0
    assert "control_code" in matrix[0]
    assert "assessment_status" in matrix[0]

def test_immutable_audit_logs(client, auth_headers_admin):
    res = client.get("/api/audit-logs", headers=auth_headers_admin)
    assert res.status_code == 200
    logs = res.get_json()["data"]
    assert len(logs) > 0
    assert "action" in logs[0]
    assert "entity_type" in logs[0]
