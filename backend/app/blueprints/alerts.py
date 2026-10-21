from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.repositories.factory import get_repository
from app.services.audit_service import AuditService
from app.constants import AlertStatus
from app.validation import query_int

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")

@alerts_bp.route("", methods=["GET"])
@jwt_required()
def list_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    repo = get_repository()
    alerts = repo.list_alerts(status=status, severity=severity)
    return jsonify({"status": "success", "count": len(alerts), "data": alerts}), 200

@alerts_bp.route("/<alert_id>", methods=["GET"])
@jwt_required()
def get_alert(alert_id):
    repo = get_repository()
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": "Alert not found"}), 404
    return jsonify({"status": "success", "data": alert}), 200

@alerts_bp.route("/<alert_id>/status", methods=["PUT"])
@jwt_required()
def update_status(alert_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"status": "error", "message": "status is required"}), 400
    if new_status not in {
        value for name, value in vars(AlertStatus).items()
        if not name.startswith("_") and isinstance(value, str)
    }:
        return jsonify({"status": "error", "message": "Invalid alert status"}), 400

    repo = get_repository()
    user_id = get_jwt_identity()
    claims = get_jwt()
    updated = repo.update_alert_status(alert_id, new_status, user_id)
    if not updated:
        return jsonify({"status": "error", "message": "Alert not found"}), 404

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="ALERT_STATUS_CHANGED",
        entity_type="ALERT",
        entity_id=str(alert_id),
        new_values={"status": new_status}
    )
    return jsonify({"status": "success", "data": updated}), 200

@alerts_bp.route("/events", methods=["GET"])
@jwt_required()
def list_events():
    limit = query_int("limit", 100, 1, 500)
    repo = get_repository()
    events = repo.list_security_events(limit=limit)
    return jsonify({"status": "success", "count": len(events), "data": events}), 200

@alerts_bp.route("/escalate-to-incident", methods=["POST"])
@jwt_required()
def escalate_to_incident():
    """
    Cross-module workflow: One-click creation of an Incident from selected alerts,
    automatically linking the asset and open vulnerability posture.
    """
    data = request.get_json() or {}
    alert_ids = data.get("alert_ids", [])
    title = data.get("title", "Escalated Security Incident")
    category = data.get("category", "MALWARE_OUTBREAK")
    severity = data.get("severity", "HIGH")

    if not isinstance(alert_ids, list) or not alert_ids:
        return jsonify({"status": "error", "message": "alert_ids must be a non-empty list"}), 400

    repo = get_repository()
    alerts = [repo.get_alert_by_id(alert_id) for alert_id in alert_ids]
    if any(alert is None for alert in alerts):
        return jsonify({"status": "error", "message": "One or more alerts were not found"}), 404
    first_alert = alerts[0]
    asset_id = first_alert.get("asset_id") if first_alert else None

    user_id = get_jwt_identity()
    claims = get_jwt()

    incident_data = {
        "title": title,
        "description": f"Incident auto-escalated from {len(alert_ids)} correlated security alerts.",
        "category": category,
        "severity": severity,
        "lead_analyst_id": user_id,
        "asset_id": asset_id
    }
    incident = repo.create_incident(incident_data)

    # Mark alerts as ESCALATED
    for aid in alert_ids:
        repo.update_alert_status(aid, "ESCALATED", user_id)

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="ALERTS_ESCALATED_TO_INCIDENT",
        entity_type="INCIDENT",
        entity_id=str(incident.get("incident_id")),
        new_values={"alert_ids": alert_ids, "incident_id": incident.get("incident_id")}
    )

    return jsonify({"status": "success", "data": incident}), 201
