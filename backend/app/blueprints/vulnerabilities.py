from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.repositories.factory import get_repository
from app.services.risk_engine import calculate_priority_score
from app.services.audit_service import AuditService
from app.constants import VulnerabilityStatus

vulns_bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")

@vulns_bp.route("", methods=["GET"])
@jwt_required()
def list_vulnerabilities():
    status = request.args.get("status")
    severity = request.args.get("severity")
    asset_id = request.args.get("asset_id")

    repo = get_repository()
    vulns = repo.list_vulnerabilities(status=status, severity=severity, asset_id=asset_id)
    return jsonify({"status": "success", "count": len(vulns), "data": vulns}), 200

@vulns_bp.route("/<finding_id>", methods=["GET"])
@jwt_required()
def get_vulnerability(finding_id):
    repo = get_repository()
    vuln = repo.get_vulnerability_by_id(finding_id)
    if not vuln:
        return jsonify({"status": "error", "message": "Vulnerability finding not found"}), 404
    return jsonify({"status": "success", "data": vuln}), 200

@vulns_bp.route("/calculate-priority", methods=["POST"])
@jwt_required()
def calculate_score_preview():
    data = request.get_json() or {}
    cvss = float(data.get("cvss_score", 7.5))
    crit = int(data.get("asset_criticality", 3))
    exploit = bool(data.get("exploit_available", False))
    eff = float(data.get("control_effectiveness", 0.0))

    score, bucket, breakdown = calculate_priority_score(cvss, crit, exploit, eff)
    return jsonify({"status": "success", "data": breakdown}), 200

@vulns_bp.route("", methods=["POST"])
@jwt_required()
def create_vulnerability():
    data = request.get_json() or {}
    if not data.get("cve_id") or not data.get("asset_id"):
        return jsonify({"status": "error", "message": "cve_id and asset_id are required"}), 400

    claims = get_jwt()
    repo = get_repository()
    finding = repo.create_vulnerability(data)

    AuditService.log_action(
        user_id=get_jwt_identity(),
        user_email=claims.get("email"),
        action="VULNERABILITY_FINDING_CREATED",
        entity_type="VULNERABILITY",
        entity_id=str(finding.get("finding_id")),
        new_values={"cve_id": finding.get("cve_id"), "asset_id": finding.get("asset_id"), "priority": finding.get("priority_score")}
    )
    return jsonify({"status": "success", "data": finding}), 201

@vulns_bp.route("/<finding_id>/status", methods=["PUT"])
@jwt_required()
def update_status(finding_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    notes = data.get("fix_notes")

    if not new_status:
        return jsonify({"status": "error", "message": "New status is required"}), 400

    repo = get_repository()
    current = repo.get_vulnerability_by_id(finding_id)
    if not current:
        return jsonify({"status": "error", "message": "Vulnerability not found"}), 404

    # Enforce state machine transitions
    valid_next = VulnerabilityStatus.VALID_TRANSITIONS.get(current.get("status"), [])
    if new_status not in valid_next and new_status != current.get("status"):
        return jsonify({
            "status": "error",
            "message": f"Illegal status transition from {current.get('status')} to {new_status}. Allowed: {valid_next}"
        }), 400

    claims = get_jwt()
    updated = repo.update_vulnerability_status(finding_id, new_status, get_jwt_identity(), notes)

    AuditService.log_action(
        user_id=get_jwt_identity(),
        user_email=claims.get("email"),
        action="VULNERABILITY_STATUS_CHANGED",
        entity_type="VULNERABILITY",
        entity_id=str(finding_id),
        old_values={"status": current.get("status")},
        new_values={"status": new_status, "notes": notes}
    )
    return jsonify({"status": "success", "data": updated}), 200

@vulns_bp.route("/<finding_id>/verify", methods=["POST"])
@jwt_required()
def verify_resolution(finding_id):
    """
    Independent verification of a remediated vulnerability.
    Segregation of duties: The verifier cannot be the fixer who submitted the task.
    """
    data = request.get_json() or {}
    notes = data.get("verification_notes", "Verified via independent validation scan.")

    claims = get_jwt()
    user_id = get_jwt_identity()
    user_email = claims.get("email")

    repo = get_repository()
    try:
        updated = repo.verify_vulnerability_remediation(finding_id, user_id, user_email, notes)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 403

    AuditService.log_action(
        user_id=user_id,
        user_email=user_email,
        action="VULNERABILITY_VERIFIED_RESOLVED",
        entity_type="VULNERABILITY",
        entity_id=str(finding_id),
        new_values={"verified_by": user_email, "notes": notes}
    )
    return jsonify({"status": "success", "data": updated}), 200
