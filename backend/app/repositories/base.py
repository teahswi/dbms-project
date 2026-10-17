"""
Base Repository Interfaces for CyberShield
Defines contract for both MySQL and MongoDB implementations.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any

class BaseRepository(ABC):

    # -------------------------------------------------------------------------
    # Authentication & RBAC
    # -------------------------------------------------------------------------
    @abstractmethod
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_user_by_id(self, user_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_users(self, search: Optional[str] = None, role: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def update_user(self, user_id: Any, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def record_login(self, user_id: Optional[Any], email: str, ip_address: str, user_agent: str, status: str, failure_reason: Optional[str] = None) -> None:
        pass

    @abstractmethod
    def get_login_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_rbac_matrix(self) -> Dict[str, Any]:
        pass

    # -------------------------------------------------------------------------
    # Application Audit Logs (Append-Only)
    # -------------------------------------------------------------------------
    @abstractmethod
    def create_audit_log(self, user_id: Optional[Any], user_email: str, action: str, entity_type: str, entity_id: str, old_values: Optional[Dict], new_values: Optional[Dict], ip_address: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def list_audit_logs(self, limit: int = 100, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    # -------------------------------------------------------------------------
    # Asset & Inventory Management
    # -------------------------------------------------------------------------
    @abstractmethod
    def list_assets(self, search: Optional[str] = None, environment: Optional[str] = None, criticality: Optional[int] = None, department: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_asset_by_id(self, asset_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def update_asset(self, asset_id: Any, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def bulk_create_assets(self, assets: List[Dict[str, Any]]) -> int:
        pass

    @abstractmethod
    def get_asset_exposure_summary(self, asset_id: Any) -> Dict[str, Any]:
        pass

    # -------------------------------------------------------------------------
    # Vulnerabilities & Remediation
    # -------------------------------------------------------------------------
    @abstractmethod
    def list_vulnerabilities(self, status: Optional[str] = None, severity: Optional[str] = None, asset_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_vulnerability_by_id(self, finding_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def update_vulnerability_status(self, finding_id: Any, new_status: str, user_id: Any, notes: Optional[str] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def verify_vulnerability_remediation(self, finding_id: Any, verifier_id: Any, verifier_email: str, notes: str) -> Dict[str, Any]:
        pass

    # -------------------------------------------------------------------------
    # Alerts & Security Events
    # -------------------------------------------------------------------------
    @abstractmethod
    def list_alerts(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_alert_by_id(self, alert_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def update_alert_status(self, alert_id: Any, new_status: str, user_id: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    def list_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_security_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    # -------------------------------------------------------------------------
    # Incidents
    # -------------------------------------------------------------------------
    @abstractmethod
    def list_incidents(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_incident_by_id(self, incident_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def update_incident_status(self, incident_id: Any, new_status: str, user_id: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    def add_incident_task(self, incident_id: Any, task_title: str, assigned_to: Optional[str] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def toggle_incident_task(self, incident_id: Any, task_id: Any, is_completed: bool) -> Dict[str, Any]:
        pass

    @abstractmethod
    def add_investigation_note(self, incident_id: Any, author: str, note_text: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def close_incident(self, incident_id: Any, resolution_summary: str, user_id: Any) -> Dict[str, Any]:
        pass

    # -------------------------------------------------------------------------
    # Compliance & Audit
    # -------------------------------------------------------------------------
    @abstractmethod
    def list_frameworks(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_controls(self, framework_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_audit_plans(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_audit_plan(self, plan_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def assess_control(self, plan_id: Any, control_id: Any, status: str, notes: str, assessor_id: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_traceability_matrix(self) -> List[Dict[str, Any]]:
        pass

    # -------------------------------------------------------------------------
    # Risk Register
    # -------------------------------------------------------------------------
    @abstractmethod
    def list_risks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_risk_by_id(self, risk_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_risk(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def record_risk_treatment(self, risk_id: Any, strategy: str, justification: str, owner_id: Any, target_date: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def approve_risk_treatment(self, treatment_id: Any, approver_id: Any, expiry_date: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_risk_heatmap(self) -> List[Dict[str, Any]]:
        pass

    # -------------------------------------------------------------------------
    # Dashboard & Posture Metrics
    # -------------------------------------------------------------------------
    @abstractmethod
    def get_executive_posture(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_backend_info(self) -> Dict[str, Any]:
        """Returns details about the active database engine, connection state, and fallback status."""
        pass

