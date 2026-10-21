from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from app.repositories.factory import get_repository
from app.services.auth_service import AuthService
from app.services.audit_service import AuditService
from app.validation import query_int

users_bp = Blueprint("users", __name__, url_prefix="/api/users")

@users_bp.route("", methods=["GET"])
@jwt_required()
def list_users():
    search = request.args.get("search")
    role = request.args.get("role")
    repo = get_repository()
    users = repo.list_users(search=search, role=role)
    return jsonify({"status": "success", "count": len(users), "data": users}), 200

@users_bp.route("/matrix", methods=["GET"])
@jwt_required()
def get_rbac_matrix():
    repo = get_repository()
    matrix = repo.get_rbac_matrix()
    return jsonify({"status": "success", "data": matrix}), 200

@users_bp.route("/login-history", methods=["GET"])
@jwt_required()
def get_login_history():
    limit = query_int("limit", 50, 1, 500)
    repo = get_repository()
    history = repo.get_login_history(limit=limit)
    return jsonify({"status": "success", "count": len(history), "data": history}), 200

@users_bp.route("", methods=["POST"])
@jwt_required()
def create_user():
    claims = get_jwt()
    if claims.get("role") != "Admin":
        return jsonify({"status": "error", "message": "Only Admin users can provision new accounts"}), 403

    data = request.get_json() or {}
    if not data.get("email") or not data.get("full_name"):
        return jsonify({"status": "error", "message": "Email and Full Name are required"}), 400

    data["password_hash"] = AuthService.hash_password(data.get("password", "Nexora@2026"))
    repo = get_repository()
    new_user = repo.create_user(data)

    AuditService.log_action(
        user_id=claims.get("sub"),
        user_email=claims.get("email"),
        action="USER_CREATED",
        entity_type="USER",
        entity_id=str(new_user.get("user_id")),
        new_values={"email": new_user.get("email"), "name": new_user.get("full_name")}
    )

    public_user = {key: value for key, value in new_user.items() if key not in {"password_hash", "failed_login_attempts", "lockout_until"}}
    return jsonify({"status": "success", "data": public_user}), 201
