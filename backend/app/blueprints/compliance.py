from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.repositories.factory import get_repository
from app.services.audit_service import AuditService

compliance_bp = Blueprint("compliance", __name__, url_prefix="/api/compliance")

@compliance_bp.route("/frameworks", methods=["GET"])
@jwt_required()
def list_frameworks():
    repo = get_repository()
    frameworks = repo.list_frameworks()
    return jsonify({"status": "success", "count": len(frameworks), "data": frameworks}), 200

@compliance_bp.route("/controls", methods=["GET"])
@jwt_required()
def list_controls():
    framework_id = request.args.get("framework_id")
    repo = get_repository()
    controls = repo.list_controls(framework_id=framework_id)
    return jsonify({"status": "success", "count": len(controls), "data": controls}), 200

@compliance_bp.route("/plans", methods=["GET"])
@jwt_required()
def list_audit_plans():
    repo = get_repository()
    plans = repo.list_audit_plans()
    return jsonify({"status": "success", "count": len(plans), "data": plans}), 200

@compliance_bp.route("/plans/<plan_id>", methods=["GET"])
@jwt_required()
def get_audit_plan(plan_id):
    repo = get_repository()
    plan = repo.get_audit_plan(plan_id)
    if not plan:
        return jsonify({"status": "error", "message": "Audit plan not found"}), 404
    return jsonify({"status": "success", "data": plan}), 200

@compliance_bp.route("/assess", methods=["POST"])
@jwt_required()
def assess_control():
    data = request.get_json() or {}
    plan_id = data.get("plan_id")
    control_id = data.get("control_id")
    status = data.get("status") # PASS, FAIL, PARTIAL, NOT_APPLICABLE
    notes = data.get("notes", "")

    if not plan_id or not control_id or not status:
        return jsonify({"status": "error", "message": "plan_id, control_id, and status are required"}), 400

    user_id = get_jwt_identity()
    claims = get_jwt()
    repo = get_repository()
    assessment = repo.assess_control(plan_id, control_id, status, notes, user_id)

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="COMPLIANCE_CONTROL_ASSESSED",
        entity_type="CONTROL_ASSESSMENT",
        entity_id=f"{plan_id}-{control_id}",
        new_values={"status": status, "notes": notes}
    )
    return jsonify({"status": "success", "data": assessment}), 200

@compliance_bp.route("/traceability", methods=["GET"])
@jwt_required()
def get_traceability():
    """
    End-to-end traceability query: Control -> Assessment -> Finding -> Corrective Action -> User
    """
    repo = get_repository()
    matrix = repo.get_traceability_matrix()
    return jsonify({"status": "success", "count": len(matrix), "data": matrix}), 200
