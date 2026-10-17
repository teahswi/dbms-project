const API_BASE = '/api';

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('cybershield_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    // If token expired, clear and notify
    localStorage.removeItem('cybershield_token');
    localStorage.removeItem('cybershield_user');
  }
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.message || `Request failed with status ${res.status}`);
  }
  return data;
}

export const api = {
  // Auth
  async getDemoAccounts() {
    const res = await fetch(`${API_BASE}/auth/demo-accounts`);
    return handleResponse<{ status: string; accounts: any[]; default_password: string }>(res);
  },

  async login(email: string, password: string) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return handleResponse<{ status: string; data: { access_token: string; user: any } }>(res);
  },

  async getCurrentUser() {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; user: any }>(res);
  },

  // Assets
  async getAssets(params?: { search?: string; environment?: string; criticality?: number; department?: string }) {
    const q = new URLSearchParams();
    if (params?.search) q.append('search', params.search);
    if (params?.environment) q.append('environment', params.environment);
    if (params?.criticality) q.append('criticality', params.criticality.toString());
    if (params?.department) q.append('department', params.department);

    const res = await fetch(`${API_BASE}/assets?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getAsset(assetId: number | string) {
    const res = await fetch(`${API_BASE}/assets/${assetId}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async createAsset(assetData: any) {
    const res = await fetch(`${API_BASE}/assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(assetData)
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async updateAsset(assetId: number | string, updates: any) {
    const res = await fetch(`${API_BASE}/assets/${assetId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(updates)
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async bulkImportCsv(csvContent: string) {
    const res = await fetch(`${API_BASE}/assets/bulk-import-csv`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', ...getAuthHeader() },
      body: csvContent
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  // Vulnerabilities
  async getVulnerabilities(params?: { status?: string; severity?: string; asset_id?: number | string }) {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.asset_id) q.append('asset_id', params.asset_id.toString());

    const res = await fetch(`${API_BASE}/vulnerabilities?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getVulnerability(findingId: number | string) {
    const res = await fetch(`${API_BASE}/vulnerabilities/${findingId}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async previewPriorityScore(payload: { cvss_score: number; asset_criticality: number; exploit_available?: boolean; control_effectiveness?: number }) {
    const res = await fetch(`${API_BASE}/vulnerabilities/calculate-priority`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(payload)
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async updateVulnerabilityStatus(findingId: number | string, status: string, fixNotes?: string) {
    const res = await fetch(`${API_BASE}/vulnerabilities/${findingId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ status, fix_notes: fixNotes })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async verifyVulnerability(findingId: number | string, verificationNotes: string) {
    const res = await fetch(`${API_BASE}/vulnerabilities/${findingId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ verification_notes: verificationNotes })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  // Alerts
  async getAlerts(params?: { status?: string; severity?: string }) {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.severity) q.append('severity', params.severity);

    const res = await fetch(`${API_BASE}/alerts?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async updateAlertStatus(alertId: number | string, status: string) {
    const res = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ status })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async getSecurityEvents(limit = 100) {
    const res = await fetch(`${API_BASE}/alerts/events?limit=${limit}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async escalateAlertsToIncident(alertIds: number[], title?: string, severity?: string) {
    const res = await fetch(`${API_BASE}/alerts/escalate-to-incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ alert_ids: alertIds, title, severity })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  // Incidents
  async getIncidents(params?: { status?: string; severity?: string }) {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.severity) q.append('severity', params.severity);

    const res = await fetch(`${API_BASE}/incidents?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getIncident(incidentId: number | string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async updateIncidentStatus(incidentId: number | string, status: string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ status })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async addIncidentTask(incidentId: number | string, title: string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ title })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async toggleIncidentTask(incidentId: number | string, taskId: number | string, isCompleted: boolean) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/tasks/${taskId}/toggle`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ is_completed: isCompleted })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async addInvestigationNote(incidentId: number | string, noteText: string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ note_text: noteText })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async closeIncident(incidentId: number | string, resolutionSummary: string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ resolution_summary: resolutionSummary })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  // Compliance & Audit
  async getComplianceFrameworks() {
    const res = await fetch(`${API_BASE}/compliance/frameworks`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getComplianceControls(frameworkId?: number | string) {
    const url = frameworkId ? `${API_BASE}/compliance/controls?framework_id=${frameworkId}` : `${API_BASE}/compliance/controls`;
    const res = await fetch(url, { headers: { ...getAuthHeader() } });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getAuditPlans() {
    const res = await fetch(`${API_BASE}/compliance/plans`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getAuditPlan(planId: number | string) {
    const res = await fetch(`${API_BASE}/compliance/plans/${planId}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async assessControl(planId: number | string, controlId: number | string, status: string, notes?: string) {
    const res = await fetch(`${API_BASE}/compliance/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ plan_id: planId, control_id: controlId, status, notes })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async getTraceabilityMatrix() {
    const res = await fetch(`${API_BASE}/compliance/traceability`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  // Risk Register & Heatmap
  async getRisks(params?: { status?: string }) {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    const res = await fetch(`${API_BASE}/risks?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getRiskHeatmap() {
    const res = await fetch(`${API_BASE}/risks/heatmap`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any[] }>(res);
  },

  async recordRiskTreatment(riskId: number | string, strategy: string, justification: string, targetDate: string) {
    const res = await fetch(`${API_BASE}/risks/${riskId}/treatment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ strategy, justification, target_date: targetDate })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async approveRiskTreatment(treatmentId: number | string, expiryDate: string) {
    const res = await fetch(`${API_BASE}/risks/treatments/${treatmentId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ expiry_date: expiryDate })
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  // Executive Dashboard & Posture
  async getPostureMetrics() {
    const res = await fetch(`${API_BASE}/dashboard/posture`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async getRecentActivity() {
    const res = await fetch(`${API_BASE}/dashboard/recent-activity`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any[] }>(res);
  },

  async getExecutiveReport() {
    const res = await fetch(`${API_BASE}/dashboard/reports/executive-summary`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  // Users & RBAC
  async getUsers(params?: { search?: string; role?: string }) {
    const q = new URLSearchParams();
    if (params?.search) q.append('search', params.search);
    if (params?.role) q.append('role', params.role);
    const res = await fetch(`${API_BASE}/users?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  async getRbacMatrix() {
    const res = await fetch(`${API_BASE}/users/matrix`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; data: any }>(res);
  },

  async getLoginHistory(limit = 50) {
    const res = await fetch(`${API_BASE}/users/login-history?limit=${limit}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  },

  // Audit Logs
  async getAuditLogs(params?: { limit?: number; entity_type?: string }) {
    const q = new URLSearchParams();
    if (params?.limit) q.append('limit', params.limit.toString());
    if (params?.entity_type) q.append('entity_type', params.entity_type);
    const res = await fetch(`${API_BASE}/audit-logs?${q.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    return handleResponse<{ status: string; count: number; data: any[] }>(res);
  }
};
