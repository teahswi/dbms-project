from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.repositories.factory import get_repository
from app.services.audit_service import AuditService
from app.constants import IncidentStatus

incidents_bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")

@incidents_bp.route("", methods=["GET"])
@jwt_required()
def list_incidents():
    status = request.args.get("status")
    severity = request.args.get("severity")
    repo = get_repository()
    incidents = repo.list_incidents(status=status, severity=severity)
    return jsonify({"status": "success", "count": len(incidents), "data": incidents}), 200

@incidents_bp.route("/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident(incident_id):
    repo = get_repository()
    incident = repo.get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"status": "error", "message": "Incident not found"}), 404
    return jsonify({"status": "success", "data": incident}), 200

@incidents_bp.route("", methods=["POST"])
@jwt_required()
def create_incident():
    data = request.get_json() or {}
    if not data.get("title") or not data.get("description"):
        return jsonify({"status": "error", "message": "Title and description are required"}), 400

    claims = get_jwt()
    data["lead_analyst_id"] = get_jwt_identity()
    repo = get_repository()
    incident = repo.create_incident(data)

    AuditService.log_action(
        user_id=get_jwt_identity(),
        user_email=claims.get("email"),
        action="INCIDENT_CREATED",
        entity_type="INCIDENT",
        entity_id=str(incident.get("incident_id")),
        new_values={"title": incident.get("title"), "severity": incident.get("severity")}
    )
    return jsonify({"status": "success", "data": incident}), 201

@incidents_bp.route("/<incident_id>/status", methods=["PUT"])
@jwt_required()
def update_status(incident_id):
    data = request.get_json() or {}
    new_status = data.get("status")

    if not new_status:
        return jsonify({"status": "error", "message": "status is required"}), 400

    repo = get_repository()
    current = repo.get_incident_by_id(incident_id)
    if not current:
        return jsonify({"status": "error", "message": "Incident not found"}), 404

    # Enforce state machine transitions
    valid_next = IncidentStatus.VALID_TRANSITIONS.get(current.get("status"), [])
    if new_status not in valid_next and new_status != current.get("status"):
        return jsonify({
            "status": "error",
            "message": f"Illegal incident transition from {current.get('status')} to {new_status}. Allowed: {valid_next}"
        }), 400

    user_id = get_jwt_identity()
    claims = get_jwt()
    updated = repo.update_incident_status(incident_id, new_status, user_id)

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="INCIDENT_STATUS_CHANGED",
        entity_type="INCIDENT",
        entity_id=str(incident_id),
        old_values={"status": current.get("status")},
        new_values={"status": new_status}
    )
    return jsonify({"status": "success", "data": updated}), 200

@incidents_bp.route("/<incident_id>/tasks", methods=["POST"])
@jwt_required()
def add_task(incident_id):
    data = request.get_json() or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"status": "error", "message": "Task title is required"}), 400

    repo = get_repository()
    task = repo.add_incident_task(incident_id, title)
    return jsonify({"status": "success", "data": task}), 201

@incidents_bp.route("/<incident_id>/tasks/<task_id>/toggle", methods=["PUT"])
@jwt_required()
def toggle_task(incident_id, task_id):
    data = request.get_json() or {}
    is_completed = bool(data.get("is_completed", True))

    repo = get_repository()
    incident = repo.toggle_incident_task(incident_id, task_id, is_completed)
    return jsonify({"status": "success", "data": incident}), 200

@incidents_bp.route("/<incident_id>/notes", methods=["POST"])
@jwt_required()
def add_note(incident_id):
    data = request.get_json() or {}
    note_text = data.get("note_text", "").strip()
    if not note_text:
        return jsonify({"status": "error", "message": "Note text is required"}), 400

    claims = get_jwt()
    repo = get_repository()
    note = repo.add_investigation_note(incident_id, claims.get("email"), note_text)
    return jsonify({"status": "success", "data": note}), 201

@incidents_bp.route("/<incident_id>/close", methods=["POST"])
@jwt_required()
def close_incident(incident_id):
    """
    Enforces post-incident summary and verification that all response tasks are completed.
    """
    data = request.get_json() or {}
    summary = data.get("resolution_summary", "").strip()

    claims = get_jwt()
    user_id = get_jwt_identity()
    user_email = claims.get("email")

    repo = get_repository()
    try:
        closed = repo.close_incident(incident_id, summary, user_id)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    AuditService.log_action(
        user_id=user_id,
        user_email=user_email,
        action="INCIDENT_CLOSED",
        entity_type="INCIDENT",
        entity_id=str(incident_id),
        new_values={"resolution_summary": summary, "mttr_seconds": closed.get("mttr_seconds")}
    )

    return jsonify({"status": "success", "data": closed}), 200
