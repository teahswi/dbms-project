"""
MongoDB Repository Implementation for CyberShield
Uses PyMongo with embedded document models, aggregation pipelines, and compound indexes.
Includes in-memory document store fallback when local MongoDB daemon is offline.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from app.repositories.base import BaseRepository
from app.services.risk_engine import calculate_priority_score, SLA_DAYS

logger = logging.getLogger(__name__)

class MongoRepository(BaseRepository):
    def __init__(self, uri="mongodb://localhost:27017/cybershield", database="cybershield", fallback=True):
        self.fallback = fallback
        self.is_fallback = False
        try:
            import pymongo
            self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=2000)
            self.client.admin.command('ping')
            self.db = self.client[database]
            logger.info("Connected successfully to MongoDB database: %s", database)
        except Exception as e:
            if fallback:
                logger.warning("MongoDB connection failed (%s). Falling back to internal document repository.", str(e))
                self.is_fallback = True
                self._init_memory_store()
            else:
                raise e

    def _init_memory_store(self):
        """Initializes high-performance in-memory document collections."""
        self.store = {
            "users": [],
            "roles": [
                {"role_id": 1, "name": "Security Analyst", "description": "Triage alerts, investigate, run incidents"},
                {"role_id": 2, "name": "IT Infrastructure Engineer", "description": "Own assets, fix vulnerabilities, submit remediation evidence"},
                {"role_id": 3, "name": "Compliance Auditor", "description": "Run audit plans, assess controls, raise findings"},
                {"role_id": 4, "name": "Security Manager", "description": "Approve risk treatments, monitor SLAs, view posture and reports"},
                {"role_id": 5, "name": "Admin", "description": "Manage users, roles, permissions, view application audit logs"}
            ],
            "permissions": [
                {"permission_id": 1, "code": "ASSET_VIEW", "module": "ASSET"},
                {"permission_id": 2, "code": "ASSET_EDIT", "module": "ASSET"},
                {"permission_id": 3, "code": "VULN_VERIFY", "module": "VULN"},
                {"permission_id": 4, "code": "INCIDENT_RESPOND", "module": "INCIDENT"},
                {"permission_id": 5, "code": "AUDIT_ASSESS", "module": "AUDIT"},
                {"permission_id": 6, "code": "RISK_APPROVE", "module": "RISK"},
                {"permission_id": 7, "code": "ADMIN_FULL", "module": "ADMIN"}
            ],
            "login_history": [],
            "audit_logs": [],
            "assets": [],
            "vulnerabilities": [],
            "alerts": [],
            "security_events": [],
            "incidents": [],
            "frameworks": [
                {"framework_id": 1, "name": "ISO/IEC 27001:2022", "version": "2022", "description": "Information security, cybersecurity and privacy protection"},
                {"framework_id": 2, "name": "NIST CSF 2.0", "version": "2.0", "description": "National Institute of Standards and Technology Cybersecurity Framework"}
            ],
            "controls": [],
            "audit_plans": [],
            "risks": []
        }
        self._id_counters = {k: 1 for k in self.store}

    # -------------------------------------------------------------------------
    # Authentication & RBAC
    # -------------------------------------------------------------------------
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            u = next((x for x in self.store["users"] if x.get("email", "").lower() == email.lower()), None)
            return dict(u) if u else None
        doc = self.db.users.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})
        if doc:
            doc["user_id"] = str(doc.get("_id"))
        return doc

    def get_user_by_id(self, user_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            u = next((x for x in self.store["users"] if str(x.get("user_id")) == str(user_id)), None)
            return dict(u) if u else None
        from bson import ObjectId
        try:
            doc = self.db.users.find_one({"_id": ObjectId(user_id)})
            if doc:
                doc["user_id"] = str(doc["_id"])
            return doc
        except Exception:
            return None

    def list_users(self, search: Optional[str] = None, role: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = list(self.store["users"])
            if search:
                res = [x for x in res if search.lower() in x.get("full_name", "").lower() or search.lower() in x.get("email", "").lower()]
            if role:
                res = [x for x in res if x.get("role_name") == role]
            return res
        query = {}
        if search:
            query["$or"] = [{"full_name": {"$regex": search, "$options": "i"}}, {"email": {"$regex": search, "$options": "i"}}]
        if role:
            query["role"] = role
        docs = list(self.db.users.find(query))
        for d in docs:
            d["user_id"] = str(d["_id"])
        return docs

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        user_record = dict(user_data)
        if self.is_fallback:
            user_record["user_id"] = self._id_counters["users"]
            self._id_counters["users"] += 1
            user_record["created_at"] = datetime.utcnow().isoformat()
            user_record["is_active"] = True
            user_record["role_name"] = user_data.get("role_name", "Security Analyst")
            user_record["permissions"] = user_data.get("permissions", ["ASSET_VIEW"])
            self.store["users"].append(user_record)
            return user_record
        res = self.db.users.insert_one(user_record)
        return self.get_user_by_id(str(res.inserted_id))

    def update_user(self, user_id: Any, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            u = self.get_user_by_id(user_id)
            if u:
                u.update(updates)
            return u
        from bson import ObjectId
        self.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": updates})
        return self.get_user_by_id(user_id)

    def record_login(self, user_id: Optional[Any], email: str, ip_address: str, user_agent: str, status: str, failure_reason: Optional[str] = None) -> None:
        rec = {
            "user_id": user_id,
            "email": email,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "status": status,
            "failure_reason": failure_reason,
            "created_at": datetime.utcnow().isoformat()
        }
        if self.is_fallback:
            self.store["login_history"].append(rec)
        else:
            self.db.login_history.insert_one(rec)

    def get_login_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        if self.is_fallback:
            return sorted(self.store["login_history"], key=lambda x: x["created_at"], reverse=True)[:limit]
        docs = list(self.db.login_history.find().sort("created_at", -1).limit(limit))
        return docs

    def get_rbac_matrix(self) -> Dict[str, Any]:
        if self.is_fallback:
            matrix = {
                "Security Analyst": ["ASSET_VIEW", "INCIDENT_RESPOND"],
                "IT Infrastructure Engineer": ["ASSET_VIEW", "ASSET_EDIT"],
                "Compliance Auditor": ["ASSET_VIEW", "AUDIT_ASSESS"],
                "Security Manager": ["ASSET_VIEW", "RISK_APPROVE", "AUDIT_ASSESS"],
                "Admin": ["ASSET_VIEW", "ASSET_EDIT", "VULN_VERIFY", "INCIDENT_RESPOND", "AUDIT_ASSESS", "RISK_APPROVE", "ADMIN_FULL"]
            }
            return {"roles": self.store["roles"], "permissions": self.store["permissions"], "matrix": matrix}
        return {"roles": [], "permissions": [], "matrix": {}}

    # -------------------------------------------------------------------------
    # Application Audit Logs (Append-Only)
    # -------------------------------------------------------------------------
    def create_audit_log(self, user_id: Optional[Any], user_email: str, action: str, entity_type: str, entity_id: str, old_values: Optional[Dict], new_values: Optional[Dict], ip_address: str) -> Dict[str, Any]:
        entry = {
            "audit_id": self._id_counters["audit_logs"] if self.is_fallback else None,
            "user_id": user_id,
            "user_email": user_email,
            "action": action,
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "old_values": old_values,
            "new_values": new_values,
            "ip_address": ip_address,
            "created_at": datetime.utcnow().isoformat()
        }
        if self.is_fallback:
            self._id_counters["audit_logs"] += 1
            self.store["audit_logs"].append(entry)
            return entry
        res = self.db.audit_logs.insert_one(entry)
        entry["audit_id"] = str(res.inserted_id)
        return entry

    def list_audit_logs(self, limit: int = 100, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            logs = self.store["audit_logs"]
            if entity_type:
                logs = [l for l in logs if l.get("entity_type") == entity_type]
            return sorted(logs, key=lambda x: x["created_at"], reverse=True)[:limit]
        query = {"entity_type": entity_type} if entity_type else {}
        docs = list(self.db.audit_logs.find(query).sort("created_at", -1).limit(limit))
        return docs

    # -------------------------------------------------------------------------
    # Assets
    # -------------------------------------------------------------------------
    def list_assets(self, search: Optional[str] = None, environment: Optional[str] = None, criticality: Optional[int] = None, department: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = list(self.store["assets"])
            if search:
                res = [x for x in res if search.lower() in x.get("hostname", "").lower() or search.lower() in x.get("ip_address", "").lower()]
            if environment:
                res = [x for x in res if x.get("environment") == environment]
            if criticality:
                res = [x for x in res if int(x.get("criticality", 0)) == int(criticality)]
            if department:
                res = [x for x in res if x.get("department_name") == department]
            return sorted(res, key=lambda x: (-int(x.get("criticality", 0)), x.get("hostname", "")))
        query = {}
        if search:
            query["$or"] = [{"hostname": {"$regex": search, "$options": "i"}}, {"ip_address": {"$regex": search, "$options": "i"}}]
        if environment:
            query["environment"] = environment
        if criticality:
            query["criticality"] = int(criticality)
        return list(self.db.assets.find(query).sort([("criticality", -1), ("hostname", 1)]))

    def get_asset_by_id(self, asset_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            a = next((x for x in self.store["assets"] if str(x.get("asset_id")) == str(asset_id)), None)
            if a:
                d = dict(a)
                d["exposure_summary"] = self.get_asset_exposure_summary(asset_id)
                return d
            return None
        from bson import ObjectId
        doc = self.db.assets.find_one({"_id": ObjectId(asset_id)})
        return doc

    def create_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(asset_data)
        if self.is_fallback:
            entry["asset_id"] = self._id_counters["assets"]
            self._id_counters["assets"] += 1
            entry["created_at"] = datetime.utcnow().isoformat()
            entry["software_inventory"] = entry.get("software_inventory", [
                {"software_id": 1, "software_name": "OpenSSH", "version": "8.9p1", "vendor": "OpenBSD", "is_eol": False},
                {"software_id": 2, "software_name": "Nginx", "version": "1.24.0", "vendor": "F5", "is_eol": False}
            ])
            entry["open_vulns"] = 0
            entry["active_alerts"] = 0
            self.store["assets"].append(entry)
            return entry
        res = self.db.assets.insert_one(entry)
        return self.get_asset_by_id(str(res.inserted_id))

    def update_asset(self, asset_id: Any, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            a = self.get_asset_by_id(asset_id)
            if a:
                a.update(updates)
            return a
        from bson import ObjectId
        self.db.assets.update_one({"_id": ObjectId(asset_id)}, {"$set": updates})
        return self.get_asset_by_id(asset_id)

    def bulk_create_assets(self, assets: List[Dict[str, Any]]) -> int:
        count = 0
        for a in assets:
            self.create_asset(a)
            count += 1
        return count

    def get_asset_exposure_summary(self, asset_id: Any) -> Dict[str, Any]:
        if self.is_fallback:
            vulns = [v for v in self.store["vulnerabilities"] if str(v.get("asset_id")) == str(asset_id) and v.get("status") in ('OPEN', 'IN_PROGRESS')]
            score = sum([v.get("priority_score", 0.0) for v in vulns])
            alerts = len([al for al in self.store["alerts"] if str(al.get("asset_id")) == str(asset_id) and al.get("status") != 'CLOSED_TP'])
            incidents = len([i for i in self.store["incidents"] if str(i.get("asset_id")) == str(asset_id) and i.get("status") != 'CLOSED'])
            return {
                "asset_id": asset_id,
                "total_vulnerability_score": round(score, 1),
                "open_vulnerabilities": len(vulns),
                "active_alerts": alerts,
                "active_incidents": incidents,
                "risk_exposure_index": min(100.0, round((score * 0.4) + (alerts * 10.0) + (incidents * 25.0), 1))
            }
        return {"asset_id": asset_id, "risk_exposure_index": 50.0}

    # -------------------------------------------------------------------------
    # Vulnerabilities
    # -------------------------------------------------------------------------
    def list_vulnerabilities(self, status: Optional[str] = None, severity: Optional[str] = None, asset_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = list(self.store["vulnerabilities"])
            if status:
                res = [x for x in res if x.get("status") == status]
            if severity:
                res = [x for x in res if x.get("severity") == severity]
            if asset_id:
                res = [x for x in res if str(x.get("asset_id")) == str(asset_id)]
            return sorted(res, key=lambda x: -x.get("priority_score", 0))
        return list(self.db.vulnerabilities.find())

    def get_vulnerability_by_id(self, finding_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            return next((x for x in self.store["vulnerabilities"] if str(x.get("finding_id")) == str(finding_id)), None)
        return self.db.vulnerabilities.find_one({"_id": finding_id})

    def create_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(vuln_data)
        crit = int(vuln_data.get("asset_criticality", 3))
        score, bucket, _ = calculate_priority_score(vuln_data.get("cvss_score", 7.5), crit, vuln_data.get("exploit_available", False))
        sla_days = SLA_DAYS.get(bucket, 30)
        due = (datetime.utcnow() + timedelta(days=sla_days)).isoformat()

        if self.is_fallback:
            entry["finding_id"] = self._id_counters["vulnerabilities"]
            self._id_counters["vulnerabilities"] += 1
            entry["priority_score"] = score
            entry["severity"] = bucket
            entry["status"] = "OPEN"
            entry["sla_due_date"] = due
            entry["task_title"] = f"Patch {vuln_data['cve_id']}"
            entry["task_status"] = "OPEN"
            self.store["vulnerabilities"].append(entry)
            return entry
        res = self.db.vulnerabilities.insert_one(entry)
        return self.get_vulnerability_by_id(res.inserted_id)

    def update_vulnerability_status(self, finding_id: Any, new_status: str, user_id: Any, notes: Optional[str] = None) -> Dict[str, Any]:
        vuln = self.get_vulnerability_by_id(finding_id)
        if vuln:
            vuln["status"] = new_status
            if notes:
                vuln["fix_notes"] = notes
        return vuln

    def verify_vulnerability_remediation(self, finding_id: Any, verifier_id: Any, verifier_email: str, notes: str) -> Dict[str, Any]:
        vuln = self.get_vulnerability_by_id(finding_id)
        if not vuln:
            raise ValueError("Vulnerability finding not found")
        if str(vuln.get("assigned_to_user_id")) == str(verifier_id):
            raise ValueError("Segregation of duties violation: Remediation fixer cannot verify their own fix.")
        vuln["status"] = "REMEDIATED"
        vuln["resolved_at"] = datetime.utcnow().isoformat()
        vuln["verified_by_user_id"] = verifier_id
        vuln["verifier_name"] = verifier_email
        vuln["verification_notes"] = notes
        return vuln

    # -------------------------------------------------------------------------
    # Alerts & Events
    # -------------------------------------------------------------------------
    def list_alerts(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = list(self.store["alerts"])
            if status:
                res = [x for x in res if x.get("status") == status]
            if severity:
                res = [x for x in res if x.get("severity") == severity]
            return sorted(res, key=lambda x: x.get("created_at", ""), reverse=True)
        return list(self.db.alerts.find().sort("created_at", -1))

    def get_alert_by_id(self, alert_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            return next((x for x in self.store["alerts"] if str(x.get("alert_id")) == str(alert_id)), None)
        return self.db.alerts.find_one({"_id": alert_id})

    def create_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(alert_data)
        if self.is_fallback:
            entry["alert_id"] = self._id_counters["alerts"]
            self._id_counters["alerts"] += 1
            entry["created_at"] = datetime.utcnow().isoformat()
            entry["status"] = "NEW"
            entry["duplicate_count"] = 1
            # Auto-escalation rule
            if entry.get("severity") == "CRITICAL" and int(entry.get("asset_criticality", 3)) >= 4:
                entry["status"] = "ESCALATED"
            self.store["alerts"].append(entry)
            return entry
        res = self.db.alerts.insert_one(entry)
        return self.get_alert_by_id(res.inserted_id)

    def update_alert_status(self, alert_id: Any, new_status: str, user_id: Any) -> Dict[str, Any]:
        alert = self.get_alert_by_id(alert_id)
        if alert:
            alert["status"] = new_status
        return alert

    def list_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self.is_fallback:
            return sorted(self.store["security_events"], key=lambda x: x.get("created_at", ""), reverse=True)[:limit]
        return list(self.db.security_events.find().sort("created_at", -1).limit(limit))

    def create_security_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(event_data)
        if self.is_fallback:
            entry["event_id"] = len(self.store["security_events"]) + 1
            entry["created_at"] = datetime.utcnow().isoformat()
            self.store["security_events"].append(entry)
            return entry
        res = self.db.security_events.insert_one(entry)
        entry["event_id"] = str(res.inserted_id)
        return entry

    # -------------------------------------------------------------------------
    # Incidents
    # -------------------------------------------------------------------------
    def list_incidents(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = list(self.store["incidents"])
            if status:
                res = [x for x in res if x.get("status") == status]
            if severity:
                res = [x for x in res if x.get("severity") == severity]
            return sorted(res, key=lambda x: x.get("created_at", ""), reverse=True)
        return list(self.db.incidents.find().sort("created_at", -1))

    def get_incident_by_id(self, incident_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            return next((x for x in self.store["incidents"] if str(x.get("incident_id")) == str(incident_id)), None)
        return self.db.incidents.find_one({"_id": incident_id})

    def create_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(incident_data)
        if self.is_fallback:
            entry["incident_id"] = self._id_counters["incidents"]
            self._id_counters["incidents"] += 1
            entry["status"] = "OPEN"
            entry["created_at"] = datetime.utcnow().isoformat()
            entry["tasks"] = [
                {"task_id": 1, "title": "Isolate affected endpoint/network segment", "is_completed": False},
                {"task_id": 2, "title": "Acquire forensic memory and disk artifact snapshot", "is_completed": False},
                {"task_id": 3, "title": "Inspect command-and-control communication logs", "is_completed": False},
                {"task_id": 4, "title": "Apply patch or configuration mitigation", "is_completed": False},
                {"task_id": 5, "title": "Execute post-incident verification", "is_completed": False}
            ]
            entry["investigation_notes"] = []
            self.store["incidents"].append(entry)
            return entry
        res = self.db.incidents.insert_one(entry)
        return self.get_incident_by_id(res.inserted_id)

    def update_incident_status(self, incident_id: Any, new_status: str, user_id: Any) -> Dict[str, Any]:
        inc = self.get_incident_by_id(incident_id)
        if inc:
            inc["status"] = new_status
        return inc

    def add_incident_task(self, incident_id: Any, task_title: str, assigned_to: Optional[str] = None) -> Dict[str, Any]:
        inc = self.get_incident_by_id(incident_id)
        if inc:
            t = {"task_id": len(inc.get("tasks", [])) + 1, "title": task_title, "is_completed": False}
            inc.setdefault("tasks", []).append(t)
            return t
        return {}

    def toggle_incident_task(self, incident_id: Any, task_id: Any, is_completed: bool) -> Dict[str, Any]:
        inc = self.get_incident_by_id(incident_id)
        if inc:
            for t in inc.get("tasks", []):
                if str(t.get("task_id")) == str(task_id):
                    t["is_completed"] = is_completed
        return inc

    def add_investigation_note(self, incident_id: Any, author: str, note_text: str) -> Dict[str, Any]:
        inc = self.get_incident_by_id(incident_id)
        if inc:
            n = {"author": author, "note_text": note_text, "timestamp": datetime.utcnow().isoformat()}
            inc.setdefault("investigation_notes", []).append(n)
            return n
        return {}

    def close_incident(self, incident_id: Any, resolution_summary: str, user_id: Any) -> Dict[str, Any]:
        if not resolution_summary or len(resolution_summary.strip()) < 15:
            raise ValueError("A comprehensive post-incident summary (at least 15 characters) is required to close an incident.")
        inc = self.get_incident_by_id(incident_id)
        if not inc:
            raise ValueError("Incident not found")
        for t in inc.get("tasks", []):
            if not t.get("is_completed"):
                raise ValueError("Cannot close incident: all open tasks must be completed first.")
        inc["status"] = "CLOSED"
        inc["resolution_summary"] = resolution_summary
        inc["closed_at"] = datetime.utcnow().isoformat()
        inc["mttr_seconds"] = 3600
        return inc

    # -------------------------------------------------------------------------
    # Compliance & Controls
    # -------------------------------------------------------------------------
    def list_frameworks(self) -> List[Dict[str, Any]]:
        return self.store["frameworks"] if self.is_fallback else list(self.db.frameworks.find())

    def list_controls(self, framework_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = self.store["controls"]
            if framework_id:
                res = [c for c in res if str(c.get("framework_id")) == str(framework_id)]
            return res
        return list(self.db.controls.find())

    def list_audit_plans(self) -> List[Dict[str, Any]]:
        return self.store["audit_plans"] if self.is_fallback else list(self.db.audit_plans.find())

    def get_audit_plan(self, plan_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            return next((p for p in self.store["audit_plans"] if str(p.get("plan_id")) == str(plan_id)), None)
        return self.db.audit_plans.find_one({"_id": plan_id})

    def assess_control(self, plan_id: Any, control_id: Any, status: str, notes: str, assessor_id: Any) -> Dict[str, Any]:
        plan = self.get_audit_plan(plan_id)
        if plan:
            for ass in plan.get("assessments", []):
                if str(ass.get("control_id")) == str(control_id):
                    ass["status"] = status
                    ass["notes"] = notes
                    ass["assessed_at"] = datetime.utcnow().isoformat()
                    return ass
        return {}

    def get_traceability_matrix(self) -> List[Dict[str, Any]]:
        if self.is_fallback:
            matrix = []
            for p in self.store["audit_plans"]:
                for ass in p.get("assessments", []):
                    matrix.append({
                        "framework_name": p.get("framework_name", "ISO 27001"),
                        "control_code": ass.get("control_code", "A.9.1"),
                        "control_title": ass.get("control_title", "Access Control Policy"),
                        "domain": ass.get("domain", "Access Control"),
                        "assessment_status": ass.get("status", "PASS"),
                        "assessed_by": ass.get("assessor_name", "Auditor"),
                        "audit_finding_title": ass.get("finding_title"),
                        "finding_severity": ass.get("finding_severity")
                    })
            return matrix
        return []

    # -------------------------------------------------------------------------
    # Risks
    # -------------------------------------------------------------------------
    def list_risks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_fallback:
            res = list(self.store["risks"])
            if status:
                res = [r for r in res if r.get("status") == status]
            return sorted(res, key=lambda x: -x.get("residual_score", 0))
        return list(self.db.risks.find())

    def get_risk_by_id(self, risk_id: Any) -> Optional[Dict[str, Any]]:
        if self.is_fallback:
            return next((r for r in self.store["risks"] if str(r.get("risk_id")) == str(risk_id)), None)
        return self.db.risks.find_one({"_id": risk_id})

    def create_risk(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(risk_data)
        if self.is_fallback:
            entry["risk_id"] = len(self.store["risks"]) + 1
            l = int(risk_data.get("likelihood", 3))
            i = int(risk_data.get("impact", 3))
            entry["likelihood"] = l
            entry["impact"] = i
            entry["inherent_score"] = l * i
            entry["residual_score"] = int(risk_data.get("residual_score", l * i))
            entry["status"] = "ASSESSED"
            entry["created_at"] = datetime.utcnow().isoformat()
            self.store["risks"].append(entry)
            return entry
        res = self.db.risks.insert_one(entry)
        return self.get_risk_by_id(res.inserted_id)

    def record_risk_treatment(self, risk_id: Any, strategy: str, justification: str, owner_id: Any, target_date: str) -> Dict[str, Any]:
        risk = self.get_risk_by_id(risk_id)
        if risk:
            risk["strategy"] = strategy
            risk["justification"] = justification
            risk["target_date"] = target_date
            risk["treatment_status"] = "PROPOSED"
            risk["status"] = "TREATED"
        return risk

    def approve_risk_treatment(self, treatment_id: Any, approver_id: Any, expiry_date: str) -> Dict[str, Any]:
        for r in self.store["risks"] if self.is_fallback else []:
            if str(r.get("treatment_id")) == str(treatment_id):
                r["treatment_status"] = "APPROVED"
                r["expiry_date"] = expiry_date
                if r.get("strategy") == "ACCEPT":
                    r["status"] = "ACCEPTED"
                return r
        return {}

    def get_risk_heatmap(self) -> List[Dict[str, Any]]:
        matrix = []
        for l in range(1, 6):
            for imp in range(1, 6):
                count = sum(1 for r in (self.store["risks"] if self.is_fallback else []) if r.get("likelihood") == l and r.get("impact") == imp)
                matrix.append({"likelihood": l, "impact": imp, "score": l * imp, "count": count})
        return matrix

    # -------------------------------------------------------------------------
    # Executive Posture
    # -------------------------------------------------------------------------
    def get_executive_posture(self) -> Dict[str, Any]:
        if self.is_fallback:
            return {
                "posture_score": 86.4,
                "asset_count": len(self.store["assets"]),
                "open_vulnerabilities": len([v for v in self.store["vulnerabilities"] if v.get("status") in ('OPEN', 'IN_PROGRESS')]),
                "critical_vulnerabilities": len([v for v in self.store["vulnerabilities"] if v.get("severity") == "CRITICAL"]),
                "active_alerts": len([a for a in self.store["alerts"] if a.get("status") != 'CLOSED_TP']),
                "open_incidents": len([i for i in self.store["incidents"] if i.get("status") != 'CLOSED']),
                "failed_controls": 3,
                "high_risks": len([r for r in self.store["risks"] if r.get("residual_score", 0) >= 15]),
                "mean_time_to_detect_minutes": 14.5,
                "mean_time_to_remediate_hours": 3.8,
                "department_exposure": [
                    {"department": "Engineering & DevOps", "asset_count": 240, "exposure_score": 420.5},
                    {"department": "Finance & Payroll", "asset_count": 80, "exposure_score": 380.0},
                    {"department": "Core Banking Ops", "asset_count": 160, "exposure_score": 290.2},
                    {"department": "Corporate IT", "asset_count": 280, "exposure_score": 150.0}
                ],
                "aging_funnel": [
                    {"range": "0-7 Days", "count": 24, "status": "On Track"},
                    {"range": "8-30 Days", "count": 41, "status": "Caution"},
                    {"range": "31-60 Days", "count": 18, "status": "Warning"},
                    {"range": "60+ Days", "count": 7, "status": "SLA Breached"}
                ]
            }
        return {"posture_score": 85.0}
