from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.repositories.factory import get_repository
from app.services.audit_service import AuditService

risks_bp = Blueprint("risks", __name__, url_prefix="/api/risks")

@risks_bp.route("", methods=["GET"])
@jwt_required()
def list_risks():
    status = request.args.get("status")
    repo = get_repository()
    risks = repo.list_risks(status=status)
    return jsonify({"status": "success", "count": len(risks), "data": risks}), 200

@risks_bp.route("/<risk_id>", methods=["GET"])
@jwt_required()
def get_risk(risk_id):
    repo = get_repository()
    risk = repo.get_risk_by_id(risk_id)
    if not risk:
        return jsonify({"status": "error", "message": "Risk record not found"}), 404
    return jsonify({"status": "success", "data": risk}), 200

@risks_bp.route("/heatmap", methods=["GET"])
@jwt_required()
def get_heatmap():
    repo = get_repository()
    matrix = repo.get_risk_heatmap()
    return jsonify({"status": "success", "data": matrix}), 200

@risks_bp.route("", methods=["POST"])
@jwt_required()
def create_risk():
    data = request.get_json() or {}
    if not data.get("title") or not data.get("threat_description"):
        return jsonify({"status": "error", "message": "Title and threat_description are required"}), 400

    user_id = get_jwt_identity()
    claims = get_jwt()
    data["assessed_by_user_id"] = user_id

    repo = get_repository()
    new_risk = repo.create_risk(data)

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="RISK_CREATED",
        entity_type="RISK",
        entity_id=str(new_risk.get("risk_id")),
        new_values={"title": new_risk.get("title"), "residual_score": new_risk.get("residual_score")}
    )
    return jsonify({"status": "success", "data": new_risk}), 201

@risks_bp.route("/<risk_id>/treatment", methods=["POST"])
@jwt_required()
def record_treatment(risk_id):
    data = request.get_json() or {}
    strategy = data.get("strategy") # MITIGATE, ACCEPT, TRANSFER, AVOID
    justification = data.get("justification", "")
    target_date = data.get("target_date")

    if not strategy or not target_date:
        return jsonify({"status": "error", "message": "Strategy and target_date are required"}), 400

    user_id = get_jwt_identity()
    claims = get_jwt()
    repo = get_repository()
    updated = repo.record_risk_treatment(risk_id, strategy, justification, user_id, target_date)

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="RISK_TREATMENT_PROPOSED",
        entity_type="RISK",
        entity_id=str(risk_id),
        new_values={"strategy": strategy, "target_date": target_date}
    )
    return jsonify({"status": "success", "data": updated}), 200

@risks_bp.route("/treatments/<treatment_id>/approve", methods=["POST"])
@jwt_required()
def approve_treatment(treatment_id):
    claims = get_jwt()
    # Check permission: Security Manager or Admin role required
    if claims.get("role") not in ["Security Manager", "Admin"]:
        return jsonify({"status": "error", "message": "Only Security Manager or Admin can authorize risk acceptance/treatment"}), 403

    data = request.get_json() or {}
    expiry_date = data.get("expiry_date")
    if not expiry_date:
        return jsonify({"status": "error", "message": "An expiry/review date is required for risk treatment authorization"}), 400

    user_id = get_jwt_identity()
    repo = get_repository()
    updated = repo.approve_risk_treatment(treatment_id, user_id, expiry_date)

    AuditService.log_action(
        user_id=user_id,
        user_email=claims.get("email"),
        action="RISK_TREATMENT_APPROVED",
        entity_type="RISK_TREATMENT",
        entity_id=str(treatment_id),
        new_values={"approved_by": claims.get("email"), "expiry_date": expiry_date}
    )
    return jsonify({"status": "success", "data": updated}), 200
