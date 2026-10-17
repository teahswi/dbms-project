from flask import Blueprint, jsonify
from app.config import Config
from app.repositories.factory import get_repository

health_bp = Blueprint("health", __name__, url_prefix="/api/health")

@health_bp.route("", methods=["GET"])
def health_check():
    repo = get_repository()
    backend_type = Config.DB_BACKEND
    is_sqlite = getattr(repo, "is_sqlite", False)
    is_fallback = getattr(repo, "is_fallback", False)

    return jsonify({
        "status": "healthy",
        "service": "CyberShield API",
        "version": "1.0.0",
        "database_backend": backend_type,
        "is_sqlite_fallback": is_sqlite,
        "is_mongo_fallback": is_fallback,
        "organization": "Nexora Technologies"
    }), 200
