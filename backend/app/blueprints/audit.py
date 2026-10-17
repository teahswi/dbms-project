from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from app.services.audit_service import AuditService

audit_bp = Blueprint("audit", __name__, url_prefix="/api/audit-logs")

@audit_bp.route("", methods=["GET"])
@jwt_required()
def list_audit_logs():
    limit = int(request.args.get("limit", 100))
    entity_type = request.args.get("entity_type")
    logs = AuditService.get_logs(limit=limit, entity_type=entity_type)
    return jsonify({"status": "success", "count": len(logs), "data": logs}), 200
