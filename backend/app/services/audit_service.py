"""
Audit Service for CyberShield
Enforces strict append-only immutable logging of all state modifications across all modules.
"""
from typing import Optional, Dict, Any
from app.repositories.factory import get_repository

class AuditService:
    @staticmethod
    def log_action(
        user_id: Optional[Any],
        user_email: str,
        action: str,
        entity_type: str,
        entity_id: str,
        old_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        repo = get_repository()
        return repo.create_audit_log(
            user_id=user_id,
            user_email=user_email,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id),
            old_values=old_values,
            new_values=new_values,
            ip_address=ip_address
        )

    @staticmethod
    def get_logs(limit: int = 100, entity_type: Optional[str] = None):
        repo = get_repository()
        return repo.list_audit_logs(limit=limit, entity_type=entity_type)
