"""
CyberShield Flask Application Factory
"""
import logging
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.config import Config
from app.repositories.factory import get_repository

jwt = JWTManager()
logger = logging.getLogger(__name__)

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    CORS(app, resources={r"/api/*": {"origins": [origin.strip() for origin in allowed_origins if origin.strip()]}}, supports_credentials=True)

    # Initialize JWT
    jwt.init_app(app)

    # JWT Error handlers
    @jwt.unauthorized_loader
    def unauthorized_response(callback):
        return jsonify({
            "status": "error",
            "message": "Missing or invalid authorization bearer token"
        }), 401

    @jwt.expired_token_loader
    def expired_token_response(jwt_header, jwt_payload):
        return jsonify({
            "status": "error",
            "message": "Authorization token has expired. Please log in again."
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_response(reason):
        return jsonify({"status": "error", "message": "Invalid authorization token"}), 401

    # Standard error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"status": "error", "message": getattr(e, "description", str(e))}), 400

    @app.errorhandler(IntegrityError)
    def integrity_error(e):
        logger.warning("Database integrity error: %s", e.orig)
        return jsonify({"status": "error", "message": "The request conflicts with existing or related data"}), 409

    @app.errorhandler(SQLAlchemyError)
    def database_error(e):
        logger.exception("Database operation failed")
        return jsonify({"status": "error", "message": "Database operation failed"}), 503

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Requested endpoint not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        logger.exception("Unhandled application error")
        return jsonify({"status": "error", "message": "Internal server error occurred"}), 500

    # Initialize repository
    with app.app_context():
        get_repository()

    # Register Blueprints
    from app.blueprints.health import health_bp
    from app.blueprints.auth import auth_bp
    from app.blueprints.assets import assets_bp
    from app.blueprints.users import users_bp
    from app.blueprints.audit import audit_bp
    from app.blueprints.vulnerabilities import vulns_bp
    from app.blueprints.alerts import alerts_bp
    from app.blueprints.incidents import incidents_bp
    from app.blueprints.compliance import compliance_bp
    from app.blueprints.risks import risks_bp
    from app.blueprints.dashboard import dashboard_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(risks_bp)
    app.register_blueprint(dashboard_bp)

    # OpenAPI / Swagger Specification Endpoint
    @app.route("/api/docs/openapi.json", methods=["GET"])
    def get_openapi_spec():
        return jsonify({
            "openapi": "3.0.3",
            "info": {
                "title": "CyberShield Enterprise Cybersecurity API",
                "version": "1.0.0",
                "description": "REST API for Nexora Technologies Cybersecurity Risk and Operations Management System"
            },
            "servers": [{"url": "http://localhost:5000"}],
            "paths": {
                "/api/health": {"get": {"summary": "Health check and backend database metadata"}},
                "/api/auth/login": {"post": {"summary": "Authenticate with email and password"}},
                "/api/auth/demo-accounts": {"get": {"summary": "List quick persona switcher accounts"}},
                "/api/assets": {"get": {"summary": "List assets with filters"}, "post": {"summary": "Create new asset"}},
                "/api/assets/bulk-import-csv": {"post": {"summary": "Bulk ingest assets from CSV"}},
                "/api/users": {"get": {"summary": "List enterprise users"}, "post": {"summary": "Provision new user"}},
                "/api/users/matrix": {"get": {"summary": "Get RBAC permission matrix"}},
                "/api/audit-logs": {"get": {"summary": "View immutable application audit logs"}}
            }
        }), 200

    return app
