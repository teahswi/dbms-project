from flask import Blueprint, jsonify
from app.config import Config
from app.repositories.factory import get_repository

health_bp = Blueprint("health", __name__, url_prefix="/api/health")

@health_bp.route("", methods=["GET"])
def health_check():
    repo = get_repository()
    backend_info = repo.get_backend_info()

    return jsonify({
        "status": "healthy",
        "service": "CyberShield API",
        "version": "1.0.0",
        "organization": "Nexora Technologies",
        "database": backend_info,
        "database_backend": backend_info.get("configured_backend"),
        "active_engine": backend_info.get("active_engine"),
        "display_name": backend_info.get("display_name"),
        "is_fallback": backend_info.get("is_fallback", False),
        "is_sqlite_fallback": backend_info.get("is_fallback", False) and backend_info.get("active_engine") == "SQLite",
        "is_mongo_fallback": backend_info.get("is_fallback", False) and backend_info.get("active_engine") == "Memory"
    }), 200
