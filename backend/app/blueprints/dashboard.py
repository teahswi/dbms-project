from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from app.repositories.factory import get_repository

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

@dashboard_bp.route("/posture", methods=["GET"])
@jwt_required()
def get_posture():
    repo = get_repository()
    posture = repo.get_executive_posture()
    return jsonify({"status": "success", "data": posture}), 200

@dashboard_bp.route("/recent-activity", methods=["GET"])
@jwt_required()
def get_recent_activity():
    repo = get_repository()
    logs = repo.list_audit_logs(limit=15)
    return jsonify({"status": "success", "data": logs}), 200

@dashboard_bp.route("/reports/executive-summary", methods=["GET"])
@jwt_required()
def get_executive_report():
    repo = get_repository()
    posture = repo.get_executive_posture()
    risks = repo.list_risks()[:5]
    incidents = repo.list_incidents()[:5]

    report = {
        "title": "Nexora Technologies - Executive Cybersecurity Risk & Posture Report",
        "generated_at": "2026-10-16T21:40:00Z",
        "posture_score": posture.get("posture_score"),
        "total_managed_assets": posture.get("asset_count"),
        "open_vulnerabilities": posture.get("open_vulnerabilities"),
        "critical_vulnerabilities": posture.get("critical_vulnerabilities"),
        "active_incidents": posture.get("open_incidents"),
        "failed_compliance_controls": posture.get("failed_controls"),
        "mean_time_to_detect_minutes": posture.get("mean_time_to_detect_minutes"),
        "mean_time_to_remediate_hours": posture.get("mean_time_to_remediate_hours"),
        "top_enterprise_risks": risks,
        "recent_incidents": incidents,
        "recommendation": "Address overdue critical finding on Finance prod payment gateway and complete remaining ISO 27001 audit plan controls."
    }
    return jsonify({"status": "success", "data": report}), 200
