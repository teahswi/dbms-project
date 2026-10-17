export type Role =
  | 'Security Analyst'
  | 'IT Infrastructure Engineer'
  | 'Compliance Auditor'
  | 'Security Manager'
  | 'Admin';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface User {
  user_id: string | number;
  email: string;
  full_name: string;
  title?: string;
  role: Role;
  department?: string;
  permissions?: string[];
  is_active?: boolean;
}

export interface SoftwareItem {
  software_id?: number;
  software_name: string;
  version: string;
  vendor: string;
  is_eol?: boolean;
}

export interface Asset {
  asset_id: number;
  hostname: string;
  ip_address: string;
  mac_address?: string;
  os_name: string;
  os_version?: string;
  environment: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT' | 'DISASTER_RECOVERY';
  criticality: number; // 1 - 5
  lifecycle_status: 'ACTIVE' | 'MAINTENANCE' | 'DECOMMISSIONED' | 'PROVISIONING';
  department_name?: string;
  owner_name?: string;
  open_vulns?: number;
  active_alerts?: number;
  software_inventory?: SoftwareItem[];
  exposure_summary?: {
    total_vulnerability_score: number;
    open_vulnerabilities: number;
    active_alerts: number;
    active_incidents: number;
    risk_exposure_index: number;
  };
}

export interface VulnerabilityFinding {
  finding_id: number;
  asset_id: number;
  cve_id: string;
  cve_description?: string;
  cvss_score: number;
  cvss_vector?: string;
  exploit_available?: boolean;
  status: 'OPEN' | 'IN_PROGRESS' | 'PENDING_VERIFICATION' | 'REMEDIATED' | 'RISK_ACCEPTED' | 'FALSE_POSITIVE';
  severity: SeverityLevel;
  priority_score: number;
  discovered_at: string;
  sla_due_date: string;
  hostname?: string;
  asset_criticality?: number;
  task_title?: string;
  task_status?: string;
  assignee_name?: string;
  fix_notes?: string;
  verifier_name?: string;
  verification_notes?: string;
}

export interface SecurityAlert {
  alert_id: number;
  asset_id: number;
  hostname?: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'ESCALATED' | 'CLOSED_TP' | 'CLOSED_FP' | 'SUPPRESSED';
  assigned_to_user_id?: number;
  assignee_name?: string;
  correlation_id?: string;
  duplicate_count: number;
  created_at: string;
}

export interface IncidentTask {
  task_id: number;
  title: string;
  assigned_to_user_id?: number;
  assigned_to_name?: string;
  is_completed: boolean;
  completed_at?: string;
}

export interface InvestigationNote {
  note_id?: number;
  author_name?: string;
  author_email?: string;
  note_text: string;
  created_at?: string;
}

export interface Incident {
  incident_id: number;
  title: string;
  description: string;
  category: string;
  severity: SeverityLevel;
  status: 'OPEN' | 'TRIAGE' | 'CONTAINMENT' | 'ERADICATION' | 'RECOVERY' | 'CLOSED';
  lead_analyst_name?: string;
  asset_hostname?: string;
  sla_due_at: string;
  created_at: string;
  closed_at?: string;
  resolution_summary?: string;
  tasks?: IncidentTask[];
  investigation_notes?: InvestigationNote[];
  total_tasks?: number;
  completed_tasks?: number;
}

export interface SecurityControl {
  control_id: number;
  framework_id: number;
  control_code: string;
  title: string;
  description: string;
  domain: string;
  effectiveness_score: number;
  framework_name?: string;
}

export interface AuditPlan {
  plan_id: number;
  title: string;
  framework_name: string;
  lead_auditor_name?: string;
  start_date: string;
  end_date: string;
  status: string;
  total_assessments?: number;
  passed_controls?: number;
  failed_controls?: number;
}

export interface RiskItem {
  risk_id: number;
  title: string;
  threat_description: string;
  department_name?: string;
  asset_hostname?: string;
  control_code?: string;
  likelihood: number; // 1 - 5
  impact: number;     // 1 - 5
  inherent_score: number;
  residual_score: number;
  status: 'IDENTIFIED' | 'ASSESSED' | 'TREATED' | 'ACCEPTED' | 'CLOSED';
  strategy?: 'MITIGATE' | 'ACCEPT' | 'TRANSFER' | 'AVOID';
  justification?: string;
  treatment_status?: string;
  owner_name?: string;
  approver_name?: string;
}

export interface AuditLogEntry {
  audit_id: number;
  user_email?: string;
  user_name?: string;
  action: string;
  entity_type: string;
  entity_id: string;
  old_values?: any;
  new_values?: any;
  ip_address: string;
  created_at: string;
}

export interface BackendInfo {
  configured_backend: string;
  active_engine: string;
  display_name: string;
  is_fallback: boolean;
  fallback_reason?: string;
  status: string;
}

export interface PostureMetrics {
  posture_score: number;
  asset_count: number;
  open_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities?: number;
  medium_vulnerabilities?: number;
  low_vulnerabilities?: number;
  active_alerts: number;
  open_incidents: number;
  failed_controls: number;
  high_risks: number;
  mean_time_to_detect_minutes: number;
  mean_time_to_remediate_hours: number;
  department_exposure: Array<{
    department: string;
    asset_count: number;
    exposure_score: number;
  }>;
  aging_funnel: Array<{
    range: string;
    count: number;
    status: string;
  }>;
  backend_info?: BackendInfo;
}

export interface SystemHealth {
  status: string;
  service: string;
  version: string;
  organization: string;
  database: BackendInfo;
  database_backend: string;
  active_engine: string;
  display_name: string;
  is_fallback: boolean;
  is_sqlite_fallback: boolean;
  is_mongo_fallback: boolean;
}

