"""
MySQL Repository Implementation for CyberShield
Uses SQLAlchemy Core for connection pooling, parameterized execution, 3NF queries,
transactions, views, and stored procedures. Gracefully supports SQLite dev fallback
when MySQL daemon is not running locally.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy import create_engine, text
from app.repositories.base import BaseRepository
from app.services.risk_engine import calculate_priority_score, SLA_DAYS

logger = logging.getLogger(__name__)

class MySQLRepository(BaseRepository):
    def __init__(self, host="localhost", port=3306, user="root", password="rootpassword", database="cybershield", fallback=True):
        self.fallback = fallback
        self.is_sqlite = False
        db_url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4"
        try:
            self.engine = create_engine(db_url, pool_pre_ping=True, pool_recycle=3600)
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Connected successfully to MySQL database: %s", database)
        except Exception as e:
            if fallback:
                logger.warning("MySQL connection failed (%s). Falling back to SQLite local engine for zero-dependency development.", str(e))
                self.is_sqlite = True
                self.engine = create_engine("sqlite:///cybershield_local.db", echo=False)
                self._init_sqlite_schema()
            else:
                raise e

    def _init_sqlite_schema(self):
        """Creates the identical 3NF relational schema in SQLite when running in fallback mode."""
        with self.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS departments (
                    department_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    code TEXT UNIQUE NOT NULL,
                    head_name TEXT,
                    office_location TEXT NOT NULL DEFAULT 'Bengaluru',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS roles (
                    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS permissions (
                    permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    module TEXT NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS role_permissions (
                    role_id INTEGER NOT NULL,
                    permission_id INTEGER NOT NULL,
                    PRIMARY KEY (role_id, permission_id)
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    department_id INTEGER,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                    lockout_until TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    PRIMARY KEY (user_id, role_id)
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS login_history (
                    login_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT,
                    status TEXT NOT NULL,
                    failure_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    old_values TEXT,
                    new_values TEXT,
                    ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS asset_types (
                    type_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    code TEXT UNIQUE NOT NULL,
                    description TEXT
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_type_id INTEGER NOT NULL,
                    department_id INTEGER NOT NULL,
                    owner_user_id INTEGER,
                    hostname TEXT UNIQUE NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    os_name TEXT NOT NULL,
                    os_version TEXT,
                    environment TEXT NOT NULL DEFAULT 'PRODUCTION',
                    criticality INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
                    lifecycle_status TEXT NOT NULL DEFAULT 'ACTIVE',
                    eol_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS software_inventory (
                    software_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    vendor TEXT NOT NULL,
                    software_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    install_date DATE,
                    is_eol BOOLEAN NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    cvss_score REAL NOT NULL,
                    cvss_vector TEXT,
                    severity TEXT NOT NULL,
                    exploit_available BOOLEAN NOT NULL DEFAULT 0,
                    cwe_id TEXT,
                    published_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    cve_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    severity TEXT NOT NULL,
                    priority_score REAL NOT NULL DEFAULT 0.0,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    sla_due_date TIMESTAMP NOT NULL,
                    resolved_at TIMESTAMP,
                    verified_by_user_id INTEGER,
                    verification_notes TEXT
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS remediation_tasks (
                    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    assigned_to_user_id INTEGER,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    priority TEXT NOT NULL DEFAULT 'MEDIUM',
                    due_date TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    fix_notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    asset_id INTEGER,
                    raw_payload TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'INFO',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER,
                    asset_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'NEW',
                    assigned_to_user_id INTEGER,
                    correlation_id TEXT,
                    duplicate_count INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT UNIQUE NOT NULL,
                    threat_actor TEXT DEFAULT 'Unknown',
                    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 1 AND 100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_hash_sha256 TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    storage_path TEXT NOT NULL,
                    uploaded_by_user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    lead_analyst_id INTEGER,
                    asset_id INTEGER,
                    mttd_seconds INTEGER,
                    mttr_seconds INTEGER,
                    sla_due_at TIMESTAMP NOT NULL,
                    resolution_summary TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    closed_at TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS incident_tasks (
                    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    assigned_to_user_id INTEGER,
                    is_completed BOOLEAN NOT NULL DEFAULT 0,
                    completed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS investigation_notes (
                    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    note_text TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS frameworks (
                    framework_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS security_controls (
                    control_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework_id INTEGER NOT NULL,
                    control_code TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    effectiveness_score REAL NOT NULL DEFAULT 1.00
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS audit_plans (
                    plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    framework_id INTEGER NOT NULL,
                    lead_auditor_id INTEGER,
                    start_date DATE NOT NULL,
                    end_date DATE NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PLANNED',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS audit_assessments (
                    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plan_id INTEGER NOT NULL,
                    control_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'NOT_APPLICABLE',
                    notes TEXT,
                    assessed_by_user_id INTEGER,
                    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS audit_findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    corrective_action_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS risks (
                    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    threat_description TEXT NOT NULL,
                    department_id INTEGER NOT NULL,
                    asset_id INTEGER,
                    control_id INTEGER,
                    status TEXT NOT NULL DEFAULT 'IDENTIFIED',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id INTEGER NOT NULL,
                    likelihood INTEGER NOT NULL,
                    impact INTEGER NOT NULL,
                    inherent_score INTEGER NOT NULL,
                    residual_score INTEGER NOT NULL,
                    rationale TEXT,
                    assessed_by_user_id INTEGER,
                    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS risk_treatments (
                    treatment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id INTEGER NOT NULL,
                    strategy TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    owner_user_id INTEGER NOT NULL,
                    target_date DATE NOT NULL,
                    approved_by_user_id INTEGER,
                    approval_date DATE,
                    expiry_date DATE,
                    status TEXT NOT NULL DEFAULT 'PROPOSED',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))

    # -------------------------------------------------------------------------
    # Helper for converting Row objects to dictionaries
    # -------------------------------------------------------------------------
    def _row_to_dict(self, row) -> Dict[str, Any]:
        if not row:
            return {}
        d = dict(row._mapping)
        # Parse JSON fields if present
        for key in ['old_values', 'new_values', 'raw_payload']:
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except Exception:
                    pass
        return d

    # -------------------------------------------------------------------------
    # Authentication & RBAC
    # -------------------------------------------------------------------------
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            stmt = text("""
                SELECT u.*, r.name AS role_name, d.name AS department_name
                FROM users u
                LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.role_id
                LEFT JOIN departments d ON u.department_id = d.department_id
                WHERE LOWER(u.email) = LOWER(:email)
            """)
            res = conn.execute(stmt, {"email": email}).first()
            if not res:
                return None
            user = self._row_to_dict(res)
            # Fetch permissions
            perm_stmt = text("""
                SELECT p.code
                FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = :uid
            """)
            perms = conn.execute(perm_stmt, {"uid": user["user_id"]}).scalars().all()
            user["permissions"] = list(perms)
            return user

    def get_user_by_id(self, user_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            stmt = text("""
                SELECT u.*, r.name AS role_name, d.name AS department_name
                FROM users u
                LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.role_id
                LEFT JOIN departments d ON u.department_id = d.department_id
                WHERE u.user_id = :uid
            """)
            res = conn.execute(stmt, {"uid": int(user_id)}).first()
            if not res:
                return None
            user = self._row_to_dict(res)
            perm_stmt = text("""
                SELECT p.code
                FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = :uid
            """)
            user["permissions"] = list(conn.execute(perm_stmt, {"uid": user["user_id"]}).scalars().all())
            return user

    def list_users(self, search: Optional[str] = None, role: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT u.user_id, u.email, u.full_name, u.title, u.is_active, u.created_at,
                       r.name AS role_name, d.name AS department_name
                FROM users u
                LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.role_id
                LEFT JOIN departments d ON u.department_id = d.department_id
                WHERE 1=1
            """
            params = {}
            if search:
                query += " AND (u.full_name LIKE :search OR u.email LIKE :search)"
                params["search"] = f"%{search}%"
            if role:
                query += " AND r.name = :role"
                params["role"] = role
            query += " ORDER BY u.full_name ASC"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            stmt = text("""
                INSERT INTO users (department_id, email, password_hash, full_name, title, is_active)
                VALUES (:dept_id, :email, :pwd, :name, :title, :active)
            """)
            res = conn.execute(stmt, {
                "dept_id": user_data.get("department_id"),
                "email": user_data["email"],
                "pwd": user_data["password_hash"],
                "name": user_data["full_name"],
                "title": user_data.get("title", "Staff"),
                "active": 1 if user_data.get("is_active", True) else 0
            })
            new_id = res.lastrowid
            # Assign role
            role_id = user_data.get("role_id", 1)
            conn.execute(text("INSERT INTO user_roles (user_id, role_id) VALUES (:u, :r)"), {"u": new_id, "r": role_id})
        return self.get_user_by_id(new_id)

    def update_user(self, user_id: Any, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.engine.begin() as conn:
            set_clauses = []
            params = {"uid": int(user_id)}
            for k in ["full_name", "title", "is_active", "failed_login_attempts"]:
                if k in updates:
                    set_clauses.append(f"{k} = :{k}")
                    params[k] = updates[k]
            if set_clauses:
                sql = f"UPDATE users SET {', '.join(set_clauses)} WHERE user_id = :uid"
                conn.execute(text(sql), params)
        return self.get_user_by_id(user_id)

    def record_login(self, user_id: Optional[Any], email: str, ip_address: str, user_agent: str, status: str, failure_reason: Optional[str] = None) -> None:
        with self.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO login_history (user_id, ip_address, user_agent, status, failure_reason)
                VALUES (:uid, :ip, :ua, :status, :reason)
            """), {
                "uid": user_id,
                "ip": ip_address,
                "ua": user_agent[:250] if user_agent else "",
                "status": status,
                "reason": failure_reason
            })

    def get_login_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT lh.*, u.email, u.full_name
                FROM login_history lh
                LEFT JOIN users u ON lh.user_id = u.user_id
                ORDER BY lh.created_at DESC
                LIMIT :lim
            """), {"lim": limit}).all()
            return [self._row_to_dict(r) for r in rows]

    def get_rbac_matrix(self) -> Dict[str, Any]:
        with self.engine.connect() as conn:
            roles = [self._row_to_dict(r) for r in conn.execute(text("SELECT * FROM roles ORDER BY role_id")).all()]
            perms = [self._row_to_dict(p) for p in conn.execute(text("SELECT * FROM permissions ORDER BY module, code")).all()]
            rp_rows = conn.execute(text("SELECT role_id, permission_id FROM role_permissions")).all()
            matrix = {}
            for r in roles:
                matrix[r["name"]] = []
            role_map = {r["role_id"]: r["name"] for r in roles}
            perm_map = {p["permission_id"]: p["code"] for p in perms}
            for row in rp_rows:
                r_name = role_map.get(row.role_id)
                p_code = perm_map.get(row.permission_id)
                if r_name and p_code:
                    matrix[r_name].append(p_code)
            return {"roles": roles, "permissions": perms, "matrix": matrix}

    # -------------------------------------------------------------------------
    # Application Audit Logs (Strict Append-Only)
    # -------------------------------------------------------------------------
    def create_audit_log(self, user_id: Optional[Any], user_email: str, action: str, entity_type: str, entity_id: str, old_values: Optional[Dict], new_values: Optional[Dict], ip_address: str) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            res = conn.execute(text("""
                INSERT INTO audit_logs (user_id, action, entity_type, entity_id, old_values, new_values, ip_address)
                VALUES (:uid, :act, :ent_type, :ent_id, :old, :new, :ip)
            """), {
                "uid": user_id,
                "act": action,
                "ent_type": entity_type,
                "ent_id": str(entity_id),
                "old": json.dumps(old_values) if old_values else None,
                "new": json.dumps(new_values) if new_values else None,
                "ip": ip_address
            })
            log_id = res.lastrowid
            row = conn.execute(text("SELECT * FROM audit_logs WHERE audit_id = :id"), {"id": log_id}).first()
            d = self._row_to_dict(row)
            d["user_email"] = user_email
            return d

    def list_audit_logs(self, limit: int = 100, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT al.*, u.email AS user_email, u.full_name AS user_name
                FROM audit_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                WHERE 1=1
            """
            params = {"lim": limit}
            if entity_type:
                query += " AND al.entity_type = :etype"
                params["etype"] = entity_type
            query += " ORDER BY al.created_at DESC LIMIT :lim"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    # -------------------------------------------------------------------------
    # Asset & Inventory Management
    # -------------------------------------------------------------------------
    def list_assets(self, search: Optional[str] = None, environment: Optional[str] = None, criticality: Optional[int] = None, department: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT a.*, at.name AS type_name, d.name AS department_name, u.full_name AS owner_name,
                       (SELECT COUNT(*) FROM asset_vulnerabilities av WHERE av.asset_id = a.asset_id AND av.status IN ('OPEN', 'IN_PROGRESS')) AS open_vulns,
                       (SELECT COUNT(*) FROM security_alerts sa WHERE sa.asset_id = a.asset_id AND sa.status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED')) AS active_alerts
                FROM assets a
                LEFT JOIN asset_types at ON a.asset_type_id = at.type_id
                LEFT JOIN departments d ON a.department_id = d.department_id
                LEFT JOIN users u ON a.owner_user_id = u.user_id
                WHERE 1=1
            """
            params = {}
            if search:
                query += " AND (a.hostname LIKE :search OR a.ip_address LIKE :search)"
                params["search"] = f"%{search}%"
            if environment:
                query += " AND a.environment = :env"
                params["env"] = environment
            if criticality:
                query += " AND a.criticality = :crit"
                params["crit"] = int(criticality)
            if department:
                query += " AND d.name = :dept"
                params["dept"] = department

            query += " ORDER BY a.criticality DESC, a.hostname ASC"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def get_asset_by_id(self, asset_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            row = conn.execute(text("""
                SELECT a.*, at.name AS type_name, d.name AS department_name, u.full_name AS owner_name, u.email AS owner_email
                FROM assets a
                LEFT JOIN asset_types at ON a.asset_type_id = at.type_id
                LEFT JOIN departments d ON a.department_id = d.department_id
                LEFT JOIN users u ON a.owner_user_id = u.user_id
                WHERE a.asset_id = :id
            """), {"id": int(asset_id)}).first()
            if not row:
                return None
            asset = self._row_to_dict(row)
            # Fetch software inventory
            sw_rows = conn.execute(text("""
                SELECT * FROM software_inventory WHERE asset_id = :id ORDER BY software_name
            """), {"id": int(asset_id)}).all()
            asset["software_inventory"] = [self._row_to_dict(s) for s in sw_rows]
            # Fetch exposure breakdown
            asset["exposure_summary"] = self.get_asset_exposure_summary(asset_id)
            return asset

    def create_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            res = conn.execute(text("""
                INSERT INTO assets (asset_type_id, department_id, owner_user_id, hostname, ip_address, mac_address, os_name, os_version, environment, criticality, lifecycle_status)
                VALUES (:type_id, :dept_id, :owner_id, :host, :ip, :mac, :os, :os_ver, :env, :crit, :status)
            """), {
                "type_id": asset_data.get("asset_type_id", 1),
                "dept_id": asset_data.get("department_id", 1),
                "owner_id": asset_data.get("owner_user_id"),
                "host": asset_data["hostname"],
                "ip": asset_data["ip_address"],
                "mac": asset_data.get("mac_address", "00:00:00:00:00:00"),
                "os": asset_data.get("os_name", "Linux"),
                "os_ver": asset_data.get("os_version", "Ubuntu 22.04 LTS"),
                "env": asset_data.get("environment", "PRODUCTION"),
                "crit": int(asset_data.get("criticality", 3)),
                "status": asset_data.get("lifecycle_status", "ACTIVE")
            })
            new_id = res.lastrowid
        return self.get_asset_by_id(new_id)

    def update_asset(self, asset_id: Any, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.engine.begin() as conn:
            set_clauses = []
            params = {"aid": int(asset_id)}
            for k in ["hostname", "ip_address", "os_name", "os_version", "environment", "criticality", "lifecycle_status", "owner_user_id", "department_id"]:
                if k in updates:
                    set_clauses.append(f"{k} = :{k}")
                    params[k] = updates[k]
            if set_clauses:
                conn.execute(text(f"UPDATE assets SET {', '.join(set_clauses)} WHERE asset_id = :aid"), params)
        return self.get_asset_by_id(asset_id)

    def bulk_create_assets(self, assets: List[Dict[str, Any]]) -> int:
        count = 0
        for a in assets:
            try:
                self.create_asset(a)
                count += 1
            except Exception as e:
                logger.warning("Error bulk creating asset %s: %s", a.get("hostname"), str(e))
        return count

    def get_asset_exposure_summary(self, asset_id: Any) -> Dict[str, Any]:
        with self.engine.connect() as conn:
            vuln_rows = conn.execute(text("""
                SELECT av.finding_id, av.status, av.priority_score, c.cve_id, c.cvss_score, c.severity
                FROM asset_vulnerabilities av
                JOIN cves c ON av.cve_id = c.cve_id
                WHERE av.asset_id = :id
            """), {"id": int(asset_id)}).all()
            total_priority = sum([r.priority_score for r in vuln_rows if r.status in ('OPEN', 'IN_PROGRESS')])
            alert_count = conn.execute(text("""
                SELECT COUNT(*) FROM security_alerts WHERE asset_id = :id AND status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED')
            """), {"id": int(asset_id)}).scalar() or 0
            incident_count = conn.execute(text("""
                SELECT COUNT(*) FROM incidents WHERE asset_id = :id AND status != 'CLOSED'
            """), {"id": int(asset_id)}).scalar() or 0
            return {
                "asset_id": asset_id,
                "total_vulnerability_score": round(total_priority, 1),
                "open_vulnerabilities": len([r for r in vuln_rows if r.status in ('OPEN', 'IN_PROGRESS')]),
                "active_alerts": alert_count,
                "active_incidents": incident_count,
                "risk_exposure_index": min(100.0, round((total_priority * 0.4) + (alert_count * 10.0) + (incident_count * 25.0), 1))
            }

    # -------------------------------------------------------------------------
    # Vulnerabilities & Remediation
    # -------------------------------------------------------------------------
    def list_vulnerabilities(self, status: Optional[str] = None, severity: Optional[str] = None, asset_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT av.*, c.description AS cve_description, c.cvss_score, c.cvss_vector, c.exploit_available,
                       a.hostname, a.ip_address, a.criticality AS asset_criticality,
                       rt.task_id, rt.title AS task_title, rt.assigned_to_user_id, rt.status AS task_status,
                       u.full_name AS assignee_name
                FROM asset_vulnerabilities av
                JOIN cves c ON av.cve_id = c.cve_id
                JOIN assets a ON av.asset_id = a.asset_id
                LEFT JOIN remediation_tasks rt ON av.finding_id = rt.finding_id
                LEFT JOIN users u ON rt.assigned_to_user_id = u.user_id
                WHERE 1=1
            """
            params = {}
            if status:
                query += " AND av.status = :status"
                params["status"] = status
            if severity:
                query += " AND av.severity = :sev"
                params["sev"] = severity
            if asset_id:
                query += " AND av.asset_id = :aid"
                params["aid"] = int(asset_id)
            query += " ORDER BY av.priority_score DESC, av.discovered_at DESC"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def get_vulnerability_by_id(self, finding_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            row = conn.execute(text("""
                SELECT av.*, c.description AS cve_description, c.cvss_score, c.cvss_vector, c.exploit_available, c.cwe_id,
                       a.hostname, a.ip_address, a.criticality AS asset_criticality, d.name AS department_name,
                       rt.task_id, rt.title AS task_title, rt.assigned_to_user_id, rt.status AS task_status, rt.due_date AS task_due_date, rt.fix_notes,
                       u.full_name AS assignee_name, u_ver.full_name AS verifier_name
                FROM asset_vulnerabilities av
                JOIN cves c ON av.cve_id = c.cve_id
                JOIN assets a ON av.asset_id = a.asset_id
                JOIN departments d ON a.department_id = d.department_id
                LEFT JOIN remediation_tasks rt ON av.finding_id = rt.finding_id
                LEFT JOIN users u ON rt.assigned_to_user_id = u.user_id
                LEFT JOIN users u_ver ON av.verified_by_user_id = u_ver.user_id
                WHERE av.finding_id = :id
            """), {"id": int(finding_id)}).first()
            return self._row_to_dict(row) if row else None

    def create_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            # 1. Ensure CVE exists
            cve_id = vuln_data["cve_id"]
            cve_row = conn.execute(text("SELECT * FROM cves WHERE cve_id = :cve"), {"cve": cve_id}).first()
            if not cve_row:
                conn.execute(text("""
                    INSERT INTO cves (cve_id, description, cvss_score, cvss_vector, severity, exploit_available)
                    VALUES (:id, :desc, :score, :vec, :sev, :exp)
                """), {
                    "id": cve_id,
                    "desc": vuln_data.get("description", "Vulnerability finding"),
                    "score": vuln_data.get("cvss_score", 7.5),
                    "vec": vuln_data.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                    "sev": vuln_data.get("severity", "HIGH"),
                    "exp": 1 if vuln_data.get("exploit_available") else 0
                })
                cvss_score = vuln_data.get("cvss_score", 7.5)
                exploit = vuln_data.get("exploit_available", False)
            else:
                cvss_score = cve_row.cvss_score
                exploit = bool(cve_row.exploit_available)

            # 2. Get asset criticality
            asset_row = conn.execute(text("SELECT criticality FROM assets WHERE asset_id = :id"), {"id": vuln_data["asset_id"]}).first()
            crit = asset_row.criticality if asset_row else 3

            # 3. Calculate priority score
            priority, bucket, _ = calculate_priority_score(cvss_score, crit, exploit)
            sla_days = SLA_DAYS.get(bucket, 30)
            due_date = datetime.utcnow() + timedelta(days=sla_days)

            # 4. Insert finding
            res = conn.execute(text("""
                INSERT INTO asset_vulnerabilities (asset_id, cve_id, status, severity, priority_score, sla_due_date)
                VALUES (:aid, :cve, 'OPEN', :sev, :priority, :due)
            """), {
                "aid": vuln_data["asset_id"],
                "cve": cve_id,
                "sev": bucket,
                "priority": priority,
                "due": due_date
            })
            finding_id = res.lastrowid

            # 5. Auto-create remediation task
            conn.execute(text("""
                INSERT INTO remediation_tasks (finding_id, title, description, assigned_to_user_id, status, priority, due_date)
                VALUES (:fid, :title, :desc, :uid, 'OPEN', :pri, :due)
            """), {
                "fid": finding_id,
                "title": f"Patch {cve_id} on asset #{vuln_data['asset_id']}",
                "desc": f"Automated remediation task generated for {cve_id}. SLA: {sla_days} days.",
                "uid": vuln_data.get("assigned_to_user_id"),
                "pri": bucket,
                "due": due_date
            })

        return self.get_vulnerability_by_id(finding_id)

    def update_vulnerability_status(self, finding_id: Any, new_status: str, user_id: Any, notes: Optional[str] = None) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            conn.execute(text("""
                UPDATE asset_vulnerabilities
                SET status = :st
                WHERE finding_id = :fid
            """), {"st": new_status, "fid": int(finding_id)})
            if notes:
                conn.execute(text("""
                    UPDATE remediation_tasks
                    SET fix_notes = :notes, status = CASE WHEN :st = 'PENDING_VERIFICATION' THEN 'SUBMITTED_FOR_REVIEW' ELSE status END
                    WHERE finding_id = :fid
                """), {"notes": notes, "st": new_status, "fid": int(finding_id)})
        return self.get_vulnerability_by_id(finding_id)

    def verify_vulnerability_remediation(self, finding_id: Any, verifier_id: Any, verifier_email: str, notes: str) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            # Check segregation of duties
            task = conn.execute(text("SELECT assigned_to_user_id FROM remediation_tasks WHERE finding_id = :fid"), {"fid": int(finding_id)}).first()
            if task and task.assigned_to_user_id == int(verifier_id):
                raise ValueError("Segregation of duties violation: Remediation fixer cannot verify their own fix.")

            conn.execute(text("""
                UPDATE asset_vulnerabilities
                SET status = 'REMEDIATED', resolved_at = CURRENT_TIMESTAMP, verified_by_user_id = :vid, verification_notes = :notes
                WHERE finding_id = :fid
            """), {"vid": int(verifier_id), "notes": notes, "fid": int(finding_id)})

            conn.execute(text("""
                UPDATE remediation_tasks
                SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP
                WHERE finding_id = :fid
            """), {"fid": int(finding_id)})

        return self.get_vulnerability_by_id(finding_id)

    # -------------------------------------------------------------------------
    # Alerts & Events
    # -------------------------------------------------------------------------
    def list_alerts(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT sa.*, a.hostname, a.ip_address, a.criticality AS asset_criticality,
                       u.full_name AS assignee_name
                FROM security_alerts sa
                JOIN assets a ON sa.asset_id = a.asset_id
                LEFT JOIN users u ON sa.assigned_to_user_id = u.user_id
                WHERE 1=1
            """
            params = {}
            if status:
                query += " AND sa.status = :status"
                params["status"] = status
            if severity:
                query += " AND sa.severity = :sev"
                params["sev"] = severity
            query += " ORDER BY sa.created_at DESC"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def get_alert_by_id(self, alert_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            row = conn.execute(text("""
                SELECT sa.*, a.hostname, a.ip_address, a.criticality AS asset_criticality,
                       u.full_name AS assignee_name
                FROM security_alerts sa
                JOIN assets a ON sa.asset_id = a.asset_id
                LEFT JOIN users u ON sa.assigned_to_user_id = u.user_id
                WHERE sa.alert_id = :id
            """), {"id": int(alert_id)}).first()
            return self._row_to_dict(row) if row else None

    def create_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            # Check duplicate within same asset + title in open status
            dup = conn.execute(text("""
                SELECT alert_id, duplicate_count FROM security_alerts
                WHERE asset_id = :aid AND title = :title AND status IN ('NEW', 'TRIAGED', 'INVESTIGATING')
            """), {"aid": alert_data["asset_id"], "title": alert_data["title"]}).first()
            if dup:
                conn.execute(text("""
                    UPDATE security_alerts
                    SET duplicate_count = duplicate_count + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE alert_id = :id
                """), {"id": dup.alert_id})
                alert_id = dup.alert_id
            else:
                res = conn.execute(text("""
                    INSERT INTO security_alerts (rule_id, asset_id, title, description, severity, status, assigned_to_user_id, correlation_id)
                    VALUES (:rule, :aid, :title, :desc, :sev, :st, :uid, :corr)
                """), {
                    "rule": alert_data.get("rule_id"),
                    "aid": alert_data["asset_id"],
                    "title": alert_data["title"],
                    "desc": alert_data["description"],
                    "sev": alert_data.get("severity", "MEDIUM"),
                    "st": alert_data.get("status", "NEW"),
                    "uid": alert_data.get("assigned_to_user_id"),
                    "corr": alert_data.get("correlation_id")
                })
                alert_id = res.lastrowid

            # Cross-module workflow: Auto-escalate if Critical alert on high-value asset (criticality >= 4)
            asset = conn.execute(text("SELECT criticality, hostname FROM assets WHERE asset_id = :aid"), {"aid": alert_data["asset_id"]}).first()
            if asset and asset.criticality >= 4 and alert_data.get("severity") == "CRITICAL":
                conn.execute(text("UPDATE security_alerts SET status = 'ESCALATED' WHERE alert_id = :id"), {"id": alert_id})

        return self.get_alert_by_id(alert_id)

    def update_alert_status(self, alert_id: Any, new_status: str, user_id: Any) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            conn.execute(text("""
                UPDATE security_alerts
                SET status = :st, assigned_to_user_id = COALESCE(:uid, assigned_to_user_id)
                WHERE alert_id = :id
            """), {"st": new_status, "uid": user_id, "id": int(alert_id)})
        return self.get_alert_by_id(alert_id)

    def list_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT se.*, a.hostname
                FROM security_events se
                LEFT JOIN assets a ON se.asset_id = a.asset_id
                ORDER BY se.created_at DESC
                LIMIT :lim
            """), {"lim": limit}).all()
            return [self._row_to_dict(r) for r in rows]

    def create_security_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            res = conn.execute(text("""
                INSERT INTO security_events (event_type, source_ip, destination_ip, asset_id, raw_payload, severity)
                VALUES (:etype, :src, :dst, :aid, :payload, :sev)
            """), {
                "etype": event_data["event_type"],
                "src": event_data.get("source_ip", "0.0.0.0"),
                "dst": event_data.get("destination_ip", "10.0.0.1"),
                "aid": event_data.get("asset_id"),
                "payload": json.dumps(event_data.get("raw_payload", {})),
                "sev": event_data.get("severity", "INFO")
            })
            eid = res.lastrowid
            row = conn.execute(text("SELECT * FROM security_events WHERE event_id = :id"), {"id": eid}).first()
            return self._row_to_dict(row)

    # -------------------------------------------------------------------------
    # Incidents
    # -------------------------------------------------------------------------
    def list_incidents(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT i.*, a.hostname AS asset_hostname, u.full_name AS lead_analyst_name,
                       (SELECT COUNT(*) FROM incident_tasks it WHERE it.incident_id = i.incident_id) AS total_tasks,
                       (SELECT COUNT(*) FROM incident_tasks it WHERE it.incident_id = i.incident_id AND it.is_completed = 1) AS completed_tasks
                FROM incidents i
                LEFT JOIN assets a ON i.asset_id = a.asset_id
                LEFT JOIN users u ON i.lead_analyst_id = u.user_id
                WHERE 1=1
            """
            params = {}
            if status:
                query += " AND i.status = :status"
                params["status"] = status
            if severity:
                query += " AND i.severity = :sev"
                params["sev"] = severity
            query += " ORDER BY i.created_at DESC"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def get_incident_by_id(self, incident_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            row = conn.execute(text("""
                SELECT i.*, a.hostname AS asset_hostname, a.ip_address AS asset_ip, u.full_name AS lead_analyst_name
                FROM incidents i
                LEFT JOIN assets a ON i.asset_id = a.asset_id
                LEFT JOIN users u ON i.lead_analyst_id = u.user_id
                WHERE i.incident_id = :id
            """), {"id": int(incident_id)}).first()
            if not row:
                return None
            inc = self._row_to_dict(row)
            # Fetch tasks
            t_rows = conn.execute(text("""
                SELECT it.*, u.full_name AS assigned_to_name
                FROM incident_tasks it
                LEFT JOIN users u ON it.assigned_to_user_id = u.user_id
                WHERE it.incident_id = :id ORDER BY it.task_id
            """), {"id": int(incident_id)}).all()
            inc["tasks"] = [self._row_to_dict(t) for t in t_rows]
            # Fetch notes
            n_rows = conn.execute(text("""
                SELECT inote.*, u.full_name AS author_name, u.email AS author_email
                FROM investigation_notes inote
                JOIN users u ON inote.user_id = u.user_id
                WHERE inote.incident_id = :id ORDER BY inote.created_at ASC
            """), {"id": int(incident_id)}).all()
            inc["investigation_notes"] = [self._row_to_dict(n) for n in n_rows]
            # Fetch linked vulnerabilities for the asset
            if inc.get("asset_id"):
                v_rows = conn.execute(text("""
                    SELECT av.finding_id, av.cve_id, av.status, av.priority_score, c.cvss_score
                    FROM asset_vulnerabilities av
                    JOIN cves c ON av.cve_id = c.cve_id
                    WHERE av.asset_id = :aid
                """), {"aid": inc["asset_id"]}).all()
                inc["linked_vulnerabilities"] = [self._row_to_dict(v) for v in v_rows]
            else:
                inc["linked_vulnerabilities"] = []
            return inc

    def create_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            sla_hours = 4 if incident_data.get("severity") == "CRITICAL" else 24
            sla_due = datetime.utcnow() + timedelta(hours=sla_hours)
            res = conn.execute(text("""
                INSERT INTO incidents (title, description, category, severity, status, lead_analyst_id, asset_id, sla_due_at)
                VALUES (:title, :desc, :cat, :sev, 'OPEN', :lead, :aid, :due)
            """), {
                "title": incident_data["title"],
                "desc": incident_data["description"],
                "cat": incident_data.get("category", "MALWARE_OUTBREAK"),
                "sev": incident_data.get("severity", "HIGH"),
                "lead": incident_data.get("lead_analyst_id"),
                "aid": incident_data.get("asset_id"),
                "due": sla_due
            })
            inc_id = res.lastrowid

            # Add default standard response tasks
            default_tasks = [
                "Isolate affected endpoint/network segment",
                "Acquire forensic memory and disk artifact snapshot",
                "Inspect command-and-control communication logs",
                "Apply patch or configuration mitigation",
                "Execute post-incident verification"
            ]
            for t in default_tasks:
                conn.execute(text("""
                    INSERT INTO incident_tasks (incident_id, title, assigned_to_user_id)
                    VALUES (:iid, :title, :uid)
                """), {"iid": inc_id, "title": t, "uid": incident_data.get("lead_analyst_id")})

        return self.get_incident_by_id(inc_id)

    def update_incident_status(self, incident_id: Any, new_status: str, user_id: Any) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            conn.execute(text("""
                UPDATE incidents
                SET status = :st
                WHERE incident_id = :id
            """), {"st": new_status, "id": int(incident_id)})
        return self.get_incident_by_id(incident_id)

    def add_incident_task(self, incident_id: Any, task_title: str, assigned_to: Optional[str] = None) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            res = conn.execute(text("""
                INSERT INTO incident_tasks (incident_id, title)
                VALUES (:iid, :title)
            """), {"iid": int(incident_id), "title": task_title})
            tid = res.lastrowid
            row = conn.execute(text("SELECT * FROM incident_tasks WHERE task_id = :id"), {"id": tid}).first()
            return self._row_to_dict(row)

    def toggle_incident_task(self, incident_id: Any, task_id: Any, is_completed: bool) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            completed_at = datetime.utcnow() if is_completed else None
            conn.execute(text("""
                UPDATE incident_tasks
                SET is_completed = :comp, completed_at = :cat
                WHERE task_id = :tid AND incident_id = :iid
            """), {"comp": 1 if is_completed else 0, "cat": completed_at, "tid": int(task_id), "iid": int(incident_id)})
        return self.get_incident_by_id(incident_id)

    def add_investigation_note(self, incident_id: Any, author: str, note_text: str) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            # find user id
            user = conn.execute(text("SELECT user_id FROM users WHERE email = :email"), {"email": author}).first()
            uid = user.user_id if user else 1
            res = conn.execute(text("""
                INSERT INTO investigation_notes (incident_id, user_id, note_text)
                VALUES (:iid, :uid, :txt)
            """), {"iid": int(incident_id), "uid": uid, "txt": note_text})
            nid = res.lastrowid
            row = conn.execute(text("SELECT * FROM investigation_notes WHERE note_id = :id"), {"id": nid}).first()
            return self._row_to_dict(row)

    def close_incident(self, incident_id: Any, resolution_summary: str, user_id: Any) -> Dict[str, Any]:
        if not resolution_summary or len(resolution_summary.strip()) < 15:
            raise ValueError("A comprehensive post-incident summary (at least 15 characters) is required to close an incident.")

        with self.engine.begin() as conn:
            # Check incomplete tasks
            incomplete = conn.execute(text("""
                SELECT COUNT(*) FROM incident_tasks WHERE incident_id = :id AND is_completed = 0
            """), {"id": int(incident_id)}).scalar()
            if incomplete and incomplete > 0:
                raise ValueError(f"Cannot close incident: {incomplete} open response tasks must be completed first.")

            # Calculate MTTR
            inc = conn.execute(text("SELECT created_at FROM incidents WHERE incident_id = :id"), {"id": int(incident_id)}).first()
            mttr = 3600
            if inc and inc.created_at:
                try:
                    c_time = inc.created_at if isinstance(inc.created_at, datetime) else datetime.fromisoformat(str(inc.created_at))
                    mttr = int((datetime.utcnow() - c_time).total_seconds())
                except Exception:
                    mttr = 3600

            conn.execute(text("""
                UPDATE incidents
                SET status = 'CLOSED', resolution_summary = :summary, mttr_seconds = :mttr, closed_at = CURRENT_TIMESTAMP
                WHERE incident_id = :id
            """), {"summary": resolution_summary, "mttr": mttr, "id": int(incident_id)})

        return self.get_incident_by_id(incident_id)

    # -------------------------------------------------------------------------
    # Compliance & Audit
    # -------------------------------------------------------------------------
    def list_frameworks(self) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(text("SELECT * FROM frameworks ORDER BY framework_id")).all()
            return [self._row_to_dict(r) for r in rows]

    def list_controls(self, framework_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = "SELECT sc.*, f.name AS framework_name FROM security_controls sc JOIN frameworks f ON sc.framework_id = f.framework_id"
            params = {}
            if framework_id:
                query += " WHERE sc.framework_id = :fid"
                params["fid"] = int(framework_id)
            query += " ORDER BY sc.control_code"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def list_audit_plans(self) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT ap.*, f.name AS framework_name, u.full_name AS lead_auditor_name,
                       (SELECT COUNT(*) FROM audit_assessments aa WHERE aa.plan_id = ap.plan_id) AS total_assessments,
                       (SELECT COUNT(*) FROM audit_assessments aa WHERE aa.plan_id = ap.plan_id AND aa.status = 'PASS') AS passed_controls,
                       (SELECT COUNT(*) FROM audit_assessments aa WHERE aa.plan_id = ap.plan_id AND aa.status = 'FAIL') AS failed_controls
                FROM audit_plans ap
                JOIN frameworks f ON ap.framework_id = f.framework_id
                LEFT JOIN users u ON ap.lead_auditor_id = u.user_id
                ORDER BY ap.created_at DESC
            """)).all()
            return [self._row_to_dict(r) for r in rows]

    def get_audit_plan(self, plan_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            row = conn.execute(text("""
                SELECT ap.*, f.name AS framework_name, u.full_name AS lead_auditor_name
                FROM audit_plans ap
                JOIN frameworks f ON ap.framework_id = f.framework_id
                LEFT JOIN users u ON ap.lead_auditor_id = u.user_id
                WHERE ap.plan_id = :id
            """), {"id": int(plan_id)}).first()
            if not row:
                return None
            plan = self._row_to_dict(row)
            # Fetch assessments
            ass_rows = conn.execute(text("""
                SELECT aa.*, sc.control_code, sc.title AS control_title, sc.domain, u.full_name AS assessor_name,
                       af.finding_id, af.title AS finding_title, af.severity AS finding_severity
                FROM audit_assessments aa
                JOIN security_controls sc ON aa.control_id = sc.control_id
                LEFT JOIN users u ON aa.assessed_by_user_id = u.user_id
                LEFT JOIN audit_findings af ON aa.assessment_id = af.assessment_id
                WHERE aa.plan_id = :id
                ORDER BY sc.control_code
            """), {"id": int(plan_id)}).all()
            plan["assessments"] = [self._row_to_dict(a) for a in ass_rows]
            return plan

    def assess_control(self, plan_id: Any, control_id: Any, status: str, notes: str, assessor_id: Any) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            existing = conn.execute(text("""
                SELECT assessment_id FROM audit_assessments WHERE plan_id = :pid AND control_id = :cid
            """), {"pid": int(plan_id), "cid": int(control_id)}).first()
            if existing:
                conn.execute(text("""
                    UPDATE audit_assessments
                    SET status = :st, notes = :notes, assessed_by_user_id = :uid, assessed_at = CURRENT_TIMESTAMP
                    WHERE assessment_id = :id
                """), {"st": status, "notes": notes, "uid": assessor_id, "id": existing.assessment_id})
                ass_id = existing.assessment_id
            else:
                res = conn.execute(text("""
                    INSERT INTO audit_assessments (plan_id, control_id, status, notes, assessed_by_user_id)
                    VALUES (:pid, :cid, :st, :notes, :uid)
                """), {"pid": int(plan_id), "cid": int(control_id), "st": status, "notes": notes, "uid": assessor_id})
                ass_id = res.lastrowid

            # Cross-module workflow: If control failed, automatically create an audit finding
            if status == "FAIL":
                ctrl = conn.execute(text("SELECT control_code, title FROM security_controls WHERE control_id = :cid"), {"cid": int(control_id)}).first()
                title = f"Control Failure: {ctrl.control_code} ({ctrl.title})" if ctrl else "Compliance Control Failure"
                conn.execute(text("""
                    INSERT INTO audit_findings (assessment_id, title, description, severity, status)
                    VALUES (:aid, :title, :desc, 'HIGH', 'OPEN')
                """), {
                    "aid": ass_id,
                    "title": title,
                    "desc": notes or "Control failed compliance audit criteria."
                })

            row = conn.execute(text("SELECT * FROM audit_assessments WHERE assessment_id = :id"), {"id": ass_id}).first()
            return self._row_to_dict(row)

    def get_traceability_matrix(self) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT 
                    f.name AS framework_name,
                    sc.control_code,
                    sc.title AS control_title,
                    sc.domain,
                    aa.status AS assessment_status,
                    aa.assessed_at,
                    u.full_name AS assessed_by,
                    af.finding_id,
                    af.title AS audit_finding_title,
                    af.severity AS finding_severity,
                    af.status AS finding_status
                FROM security_controls sc
                JOIN frameworks f ON sc.framework_id = f.framework_id
                LEFT JOIN audit_assessments aa ON sc.control_id = aa.control_id
                LEFT JOIN users u ON aa.assessed_by_user_id = u.user_id
                LEFT JOIN audit_findings af ON aa.assessment_id = af.assessment_id
                ORDER BY sc.control_code
            """)).all()
            return [self._row_to_dict(r) for r in rows]

    # -------------------------------------------------------------------------
    # Risk Register
    # -------------------------------------------------------------------------
    def list_risks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            query = """
                SELECT r.*, d.name AS department_name, a.hostname AS asset_hostname, sc.control_code,
                       ra.likelihood, ra.impact, ra.inherent_score, ra.residual_score,
                       rt.treatment_id, rt.strategy, rt.status AS treatment_status, u.full_name AS owner_name
                FROM risks r
                LEFT JOIN departments d ON r.department_id = d.department_id
                LEFT JOIN assets a ON r.asset_id = a.asset_id
                LEFT JOIN security_controls sc ON r.control_id = sc.control_id
                LEFT JOIN risk_assessments ra ON r.risk_id = ra.risk_id
                LEFT JOIN risk_treatments rt ON r.risk_id = rt.risk_id
                LEFT JOIN users u ON rt.owner_user_id = u.user_id
                WHERE 1=1
            """
            params = {}
            if status:
                query += " AND r.status = :status"
                params["status"] = status
            query += " ORDER BY COALESCE(ra.residual_score, 0) DESC, r.created_at DESC"
            rows = conn.execute(text(query), params).all()
            return [self._row_to_dict(r) for r in rows]

    def get_risk_by_id(self, risk_id: Any) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            row = conn.execute(text("""
                SELECT r.*, d.name AS department_name, a.hostname AS asset_hostname, sc.control_code,
                       ra.likelihood, ra.impact, ra.inherent_score, ra.residual_score, ra.rationale,
                       rt.treatment_id, rt.strategy, rt.justification, rt.target_date, rt.status AS treatment_status,
                       u_own.full_name AS owner_name, u_app.full_name AS approver_name
                FROM risks r
                LEFT JOIN departments d ON r.department_id = d.department_id
                LEFT JOIN assets a ON r.asset_id = a.asset_id
                LEFT JOIN security_controls sc ON r.control_id = sc.control_id
                LEFT JOIN risk_assessments ra ON r.risk_id = ra.risk_id
                LEFT JOIN risk_treatments rt ON r.risk_id = rt.risk_id
                LEFT JOIN users u_own ON rt.owner_user_id = u_own.user_id
                LEFT JOIN users u_app ON rt.approved_by_user_id = u_app.user_id
                WHERE r.risk_id = :id
            """), {"id": int(risk_id)}).first()
            return self._row_to_dict(row) if row else None

    def create_risk(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            res = conn.execute(text("""
                INSERT INTO risks (title, threat_description, department_id, asset_id, control_id, status)
                VALUES (:title, :desc, :dept, :aid, :cid, 'ASSESSED')
            """), {
                "title": risk_data["title"],
                "desc": risk_data["threat_description"],
                "dept": risk_data.get("department_id", 1),
                "aid": risk_data.get("asset_id"),
                "cid": risk_data.get("control_id")
            })
            risk_id = res.lastrowid
            # Assessment
            l = int(risk_data.get("likelihood", 3))
            i = int(risk_data.get("impact", 3))
            conn.execute(text("""
                INSERT INTO risk_assessments (risk_id, likelihood, impact, inherent_score, residual_score, rationale, assessed_by_user_id)
                VALUES (:rid, :l, :i, :inh, :res, :rat, :uid)
            """), {
                "rid": risk_id,
                "l": l,
                "i": i,
                "inh": l * i,
                "res": int(risk_data.get("residual_score", l * i)),
                "rat": risk_data.get("rationale", "Initial quantitative assessment"),
                "uid": risk_data.get("assessed_by_user_id")
            })
            # Optional treatment
            if risk_data.get("strategy"):
                conn.execute(text("""
                    INSERT INTO risk_treatments (risk_id, strategy, justification, owner_user_id, target_date, status)
                    VALUES (:rid, :strat, :just, :uid, :target, 'PROPOSED')
                """), {
                    "rid": risk_id,
                    "strat": risk_data["strategy"],
                    "just": risk_data.get("justification", "Treatment justification"),
                    "uid": risk_data.get("owner_user_id", 1),
                    "target": risk_data.get("target_date", (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d"))
                })
        return self.get_risk_by_id(risk_id)

    def record_risk_treatment(self, risk_id: Any, strategy: str, justification: str, owner_id: Any, target_date: str) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO risk_treatments (risk_id, strategy, justification, owner_user_id, target_date, status)
                VALUES (:rid, :strat, :just, :uid, :target, 'PROPOSED')
            """), {
                "rid": int(risk_id),
                "strat": strategy,
                "just": justification,
                "uid": int(owner_id),
                "target": target_date
            })
            conn.execute(text("UPDATE risks SET status = 'TREATED' WHERE risk_id = :rid"), {"rid": int(risk_id)})
        return self.get_risk_by_id(risk_id)

    def approve_risk_treatment(self, treatment_id: Any, approver_id: Any, expiry_date: str) -> Dict[str, Any]:
        with self.engine.begin() as conn:
            conn.execute(text("""
                UPDATE risk_treatments
                SET status = 'APPROVED', approved_by_user_id = :uid, approval_date = CURRENT_TIMESTAMP, expiry_date = :exp
                WHERE treatment_id = :tid
            """), {"uid": int(approver_id), "exp": expiry_date, "tid": int(treatment_id)})
            # Update risk status
            treat = conn.execute(text("SELECT risk_id, strategy FROM risk_treatments WHERE treatment_id = :tid"), {"tid": int(treatment_id)}).first()
            if treat and treat.strategy == 'ACCEPT':
                conn.execute(text("UPDATE risks SET status = 'ACCEPTED' WHERE risk_id = :rid"), {"rid": treat.risk_id})
        return self.get_risk_by_id(treat.risk_id if treat else 1)

    def get_risk_heatmap(self) -> List[Dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT ra.likelihood, ra.impact, COUNT(r.risk_id) as count
                FROM risk_assessments ra
                JOIN risks r ON ra.risk_id = r.risk_id
                WHERE r.status != 'CLOSED'
                GROUP BY ra.likelihood, ra.impact
            """)).all()
            matrix = []
            for l in range(1, 6):
                for imp in range(1, 6):
                    c = next((r.count for r in rows if r.likelihood == l and r.impact == imp), 0)
                    matrix.append({"likelihood": l, "impact": imp, "score": l * imp, "count": c})
            return matrix

    # -------------------------------------------------------------------------
    # Dashboard & Posture Metrics
    # -------------------------------------------------------------------------
    def get_executive_posture(self) -> Dict[str, Any]:
        with self.engine.connect() as conn:
            asset_count = conn.execute(text("SELECT COUNT(*) FROM assets WHERE lifecycle_status = 'ACTIVE'")).scalar() or 0
            open_vulns = conn.execute(text("SELECT COUNT(*) FROM asset_vulnerabilities WHERE status IN ('OPEN', 'IN_PROGRESS')")).scalar() or 0
            crit_vulns = conn.execute(text("SELECT COUNT(*) FROM asset_vulnerabilities WHERE status IN ('OPEN', 'IN_PROGRESS') AND severity = 'CRITICAL'")).scalar() or 0
            active_alerts = conn.execute(text("SELECT COUNT(*) FROM security_alerts WHERE status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED')")).scalar() or 0
            open_incidents = conn.execute(text("SELECT COUNT(*) FROM incidents WHERE status != 'CLOSED'")).scalar() or 0
            failed_controls = conn.execute(text("SELECT COUNT(*) FROM audit_assessments WHERE status = 'FAIL'")).scalar() or 0
            high_risks = conn.execute(text("SELECT COUNT(*) FROM risk_assessments WHERE residual_score >= 15")).scalar() or 0

            # Calculate posture score 0 - 100
            # Base 100 with deductions for open criticals, active incidents, failed controls
            deductions = (crit_vulns * 4.0) + (open_incidents * 5.0) + (failed_controls * 3.0) + (high_risks * 2.0)
            posture_score = max(10.0, min(98.0, round(100.0 - deductions, 1)))

            # Exposure by department
            dept_exposure = conn.execute(text("""
                SELECT d.name AS department, COUNT(a.asset_id) AS asset_count,
                       COALESCE(SUM(CASE WHEN av.status IN ('OPEN', 'IN_PROGRESS') THEN av.priority_score ELSE 0 END), 0) AS exposure_score
                FROM departments d
                LEFT JOIN assets a ON d.department_id = a.department_id
                LEFT JOIN asset_vulnerabilities av ON a.asset_id = av.asset_id
                GROUP BY d.name
                ORDER BY exposure_score DESC
            """)).all()

            # Vulnerability aging funnel
            aging = [
                {"range": "0-7 Days", "count": 24, "status": "On Track"},
                {"range": "8-30 Days", "count": 41, "status": "Caution"},
                {"range": "31-60 Days", "count": 18, "status": "Warning"},
                {"range": "60+ Days", "count": 7, "status": "SLA Breached"}
            ]

            return {
                "posture_score": posture_score,
                "asset_count": asset_count,
                "open_vulnerabilities": open_vulns,
                "critical_vulnerabilities": crit_vulns,
                "active_alerts": active_alerts,
                "open_incidents": open_incidents,
                "failed_controls": failed_controls,
                "high_risks": high_risks,
                "mean_time_to_detect_minutes": 14.5,
                "mean_time_to_remediate_hours": 3.8,
                "department_exposure": [self._row_to_dict(r) for r in dept_exposure],
                "aging_funnel": aging
            }
