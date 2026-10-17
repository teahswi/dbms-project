from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.services.auth_service import AuthService

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/demo-accounts", methods=["GET"])
def get_demo_accounts():
    """Returns quick switcher accounts for testing all five personas."""
    return jsonify({
        "status": "success",
        "accounts": AuthService.get_demo_accounts(),
        "default_password": "Nexora@2026"
    }), 200

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    user_agent = request.headers.get("User-Agent", "Unknown")

    result, error = AuthService.authenticate_user(email, password, ip_address, user_agent)
    if error:
        return jsonify({"status": "error", "message": error}), 401

    return jsonify({"status": "success", "data": result}), 200

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    claims = get_jwt()
    identity = get_jwt_identity()
    return jsonify({
        "status": "success",
        "user": {
            "user_id": identity,
            "email": claims.get("email"),
            "full_name": claims.get("full_name"),
            "role": claims.get("role"),
            "department": claims.get("department"),
            "permissions": claims.get("permissions", [])
        }
    }), 200
