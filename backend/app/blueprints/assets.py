from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.services.asset_service import AssetService
from app.repositories.factory import get_repository
from app.validation import optional_query_int

assets_bp = Blueprint("assets", __name__, url_prefix="/api/assets")

@assets_bp.route("", methods=["GET"])
@jwt_required()
def list_assets():
    search = request.args.get("search")
    environment = request.args.get("environment")
    criticality = optional_query_int("criticality", 1, 5)
    department = request.args.get("department")

    assets = AssetService.list_assets(
        search=search,
        environment=environment,
        criticality=criticality,
        department=department
    )
    return jsonify({"status": "success", "count": len(assets), "data": assets}), 200

@assets_bp.route("/<asset_id>", methods=["GET"])
@jwt_required()
def get_asset(asset_id):
    asset = AssetService.get_asset(asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404
    return jsonify({"status": "success", "data": asset}), 200

@assets_bp.route("", methods=["POST"])
@jwt_required()
def create_asset():
    data = request.get_json() or {}
    if not data.get("hostname") or not data.get("ip_address"):
        return jsonify({"status": "error", "message": "Hostname and IP address are required"}), 400

    claims = get_jwt()
    current_user = {"user_id": get_jwt_identity(), "email": claims.get("email")}
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

    new_asset = AssetService.create_asset(data, current_user, ip_address)
    return jsonify({"status": "success", "data": new_asset}), 201

@assets_bp.route("/<asset_id>", methods=["PUT"])
@jwt_required()
def update_asset(asset_id):
    data = request.get_json() or {}
    claims = get_jwt()
    current_user = {"user_id": get_jwt_identity(), "email": claims.get("email")}
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

    updated = AssetService.update_asset(asset_id, data, current_user, ip_address)
    if not updated:
        return jsonify({"status": "error", "message": "Asset not found"}), 404
    return jsonify({"status": "success", "data": updated}), 200

@assets_bp.route("/bulk-import-csv", methods=["POST"])
@jwt_required()
def bulk_import_csv():
    content = ""
    if "file" in request.files:
        file = request.files["file"]
        try:
            content = file.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            return jsonify({"status": "error", "message": "CSV file must be UTF-8 encoded"}), 400
    else:
        content = request.get_data(as_text=True)

    if not content.strip():
        return jsonify({"status": "error", "message": "CSV data or file is required"}), 400

    claims = get_jwt()
    current_user = {"user_id": get_jwt_identity(), "email": claims.get("email")}
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

    result = AssetService.parse_and_import_csv(content, current_user, ip_address)
    return jsonify({"status": "success", "data": result}), 200

@assets_bp.route("/<asset_id>/exposure", methods=["GET"])
@jwt_required()
def get_asset_exposure(asset_id):
    repo = get_repository()
    summary = repo.get_asset_exposure_summary(asset_id)
    return jsonify({"status": "success", "data": summary}), 200
