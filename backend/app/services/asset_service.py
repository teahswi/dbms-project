"""
Asset Management Service for CyberShield
Handles asset inventory, hardware/software specifications, bulk CSV processing,
and cross-module exposure tracking.
"""
import csv
import io
from typing import List, Dict, Any, Optional
from app.repositories.factory import get_repository
from app.services.audit_service import AuditService

class AssetService:

    @staticmethod
    def list_assets(search: Optional[str] = None, environment: Optional[str] = None, criticality: Optional[int] = None, department: Optional[str] = None):
        repo = get_repository()
        return repo.list_assets(search=search, environment=environment, criticality=criticality, department=department)

    @staticmethod
    def get_asset(asset_id: Any):
        repo = get_repository()
        return repo.get_asset_by_id(asset_id)

    @staticmethod
    def create_asset(asset_data: Dict[str, Any], current_user: Dict[str, Any], ip_address: str = "127.0.0.1"):
        repo = get_repository()
        new_asset = repo.create_asset(asset_data)
        AuditService.log_action(
            user_id=current_user.get("user_id"),
            user_email=current_user.get("email", "system"),
            action="ASSET_CREATED",
            entity_type="ASSET",
            entity_id=str(new_asset.get("asset_id")),
            new_values=new_asset,
            ip_address=ip_address
        )
        return new_asset

    @staticmethod
    def update_asset(asset_id: Any, updates: Dict[str, Any], current_user: Dict[str, Any], ip_address: str = "127.0.0.1"):
        repo = get_repository()
        old_asset = repo.get_asset_by_id(asset_id)
        updated_asset = repo.update_asset(asset_id, updates)
        AuditService.log_action(
            user_id=current_user.get("user_id"),
            user_email=current_user.get("email", "system"),
            action="ASSET_UPDATED",
            entity_type="ASSET",
            entity_id=str(asset_id),
            old_values=old_asset,
            new_values=updated_asset,
            ip_address=ip_address
        )
        return updated_asset

    @staticmethod
    def parse_and_import_csv(csv_content: str, current_user: Dict[str, Any], ip_address: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Parses CSV input with columns: hostname, ip_address, asset_type, criticality, environment, os_name
        """
        repo = get_repository()
        reader = csv.DictReader(io.StringIO(csv_content))
        assets_to_import = []
        errors = []

        row_idx = 1
        for row in reader:
            row_idx += 1
            hostname = row.get("hostname", "").strip()
            ip = row.get("ip_address", "").strip()
            if not hostname or not ip:
                errors.append(f"Row {row_idx}: Missing hostname or IP address.")
                continue

            try:
                crit = int(row.get("criticality", 3))
                crit = max(1, min(5, crit))
            except ValueError:
                crit = 3

            assets_to_import.append({
                "hostname": hostname,
                "ip_address": ip,
                "asset_type_id": 1,
                "department_id": 1,
                "criticality": crit,
                "environment": row.get("environment", "PRODUCTION").upper(),
                "os_name": row.get("os_name", "Linux Ubuntu 22.04 LTS"),
                "lifecycle_status": "ACTIVE"
            })

        imported_count = repo.bulk_create_assets(assets_to_import)

        AuditService.log_action(
            user_id=current_user.get("user_id"),
            user_email=current_user.get("email", "system"),
            action="ASSETS_BULK_IMPORTED_CSV",
            entity_type="ASSET",
            entity_id="BULK",
            new_values={"count": imported_count, "errors_count": len(errors)},
            ip_address=ip_address
        )

        return {
            "imported_count": imported_count,
            "total_rows": len(assets_to_import) + len(errors),
            "errors": errors
        }
