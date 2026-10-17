import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { VulnerabilityFinding } from '../types';
import { useAuth } from '../context/AuthContext';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { SlideOverDrawer } from '../components/SlideOverDrawer';
import {
  Bug,
  AlertTriangle,
  Clock,
  CheckCircle2,
  Calculator,
  ShieldCheck,
  Search,
  ExternalLink,
  Info,
  UserCheck
} from 'lucide-react';

export const Vulnerabilities: React.FC = () => {
  const { user } = useAuth();
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);

  // Remediation Action Modal State
  const [showRemediateModal, setShowRemediateModal] = useState(false);
  const [fixNotes, setFixNotes] = useState('');

  // Verification Modal State
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verificationNotes, setVerificationNotes] = useState('');
  const [verifyError, setVerifyError] = useState<string | null>(null);

  // Formula Breakdown Popup State
  const [showFormulaModal, setShowFormulaModal] = useState(false);
  const [formulaBreakdown, setFormulaBreakdown] = useState<any>(null);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const res = await api.getVulnerabilities({
        status: statusFilter || undefined,
        severity: severityFilter || undefined
      });
      setFindings(res.data || []);
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [statusFilter, severityFilter]);

  const handleOpenDetail = async (findingId: number) => {
    try {
      const res = await api.getVulnerability(findingId);
      setSelectedFinding(res.data);
    } catch (err) {
      console.error('Failed to load finding details:', err);
    }
  };

  const handleInspectFormula = async (f: VulnerabilityFinding) => {
    try {
      const res = await api.previewPriorityScore({
        cvss_score: f.cvss_score,
        asset_criticality: f.asset_criticality || 3,
        exploit_available: f.exploit_available,
        control_effectiveness: 0.1
      });
      setFormulaBreakdown(res.data);
      setShowFormulaModal(true);
    } catch (err) {
      console.error('Failed to calculate formula breakdown:', err);
    }
  };

  const handleSubmitFix = async () => {
    if (!selectedFinding) return;
    try {
      await api.updateVulnerabilityStatus(selectedFinding.finding_id, 'PENDING_VERIFICATION', fixNotes);
      setShowRemediateModal(false);
      handleOpenDetail(selectedFinding.finding_id);
      loadFindings();
    } catch (err: any) {
      alert('Error submitting remediation: ' + err.message);
    }
  };

  const handleVerifyResolution = async () => {
    if (!selectedFinding) return;
    setVerifyError(null);
    try {
      await api.verifyVulnerability(selectedFinding.finding_id, verificationNotes);
      setShowVerifyModal(false);
      handleOpenDetail(selectedFinding.finding_id);
      loadFindings();
    } catch (err: any) {
      setVerifyError(err.message || 'Segregation of duties violation: fixer cannot verify their own fix.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Bug className="w-5 h-5 text-orange-400" /> Vulnerability & Remediation Management
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Prioritized Risk Queue &bull; Dual-Party Verification &bull; Enforced SLA Deadlines
          </p>
        </div>
      </div>

      {/* SLA Alert Callout: Deliberate Breach Case */}
      <div className="p-4 rounded-2xl bg-red-950/40 border border-red-500/50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 glow-critical">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0">
            <AlertTriangle className="w-5 h-5 animate-bounce" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold bg-red-500 text-slate-950 px-2 py-0.5 rounded">
                SLA BREACH ALERT
              </span>
              <span className="text-xs font-bold text-white font-mono">
                CVE-2021-44228 on nx-payment-gw-005.nexora.corp
              </span>
            </div>
            <p className="text-xs text-red-300 font-mono mt-0.5">
              Finance Production Server &bull; Overdue by 12 Days &bull; Critical Priority Score: 97.5 / 100
            </p>
          </div>
        </div>
        <button
          onClick={() => handleOpenDetail(1)}
          className="px-3.5 py-1.5 rounded-xl bg-red-500 hover:bg-red-400 text-slate-950 font-bold font-mono text-xs shadow-lg shadow-red-500/30 whitespace-nowrap"
        >
          Remediate Now &rarr;
        </button>
      </div>

      {/* Filter Bar */}
      <div className="glass-panel rounded-2xl p-4 border border-slate-800 flex flex-wrap items-center gap-3">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="PENDING_VERIFICATION">Pending Verification</option>
          <option value="REMEDIATED">Remediated</option>
        </select>

        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <span className="text-xs font-mono text-slate-400 ml-auto">
          Queue: {findings.length} findings sorted by Computed Priority
        </span>
      </div>

      {/* Vulnerabilities Table */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Priority Score</th>
                <th className="py-3 px-4">CVE Identifier</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Affected Asset</th>
                <th className="py-3 px-4">Exploit Available</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">SLA Due Date</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-mono">
                    Loading vulnerability queue...
                  </td>
                </tr>
              ) : (
                findings.slice(0, 50).map(f => {
                  const isBreached = f.finding_id === 1 || new Date(f.sla_due_date) < new Date() && f.status !== 'REMEDIATED';
                  return (
                    <tr
                      key={f.finding_id}
                      className={`hover:bg-slate-900/60 transition-colors group cursor-pointer ${
                        isBreached ? 'bg-red-950/20' : ''
                      }`}
                      onClick={() => handleOpenDetail(f.finding_id)}
                    >
                      <td className="py-3 px-4 font-mono">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectFormula(f);
                          }}
                          className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors"
                          title="Click to view transparent priority formula calculation"
                        >
                          <Calculator className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{f.priority_score}</span>
                        </button>
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {f.cve_id}
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300 truncate max-w-[200px]">
                        {f.hostname || `Asset #${f.asset_id}`}
                      </td>
                      <td className="py-3 px-4 font-mono text-center">
                        {f.exploit_available ? (
                          <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 font-bold text-[10px] border border-red-800">
                            Weaponized
                          </span>
                        ) : (
                          <span className="text-slate-600 text-[11px]">None</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <StatusBadge status={f.status} />
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px]">
                        {isBreached ? (
                          <span className="text-red-400 font-bold flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5 animate-pulse" /> Overdue
                          </span>
                        ) : (
                          <span className="text-slate-400">
                            {new Date(f.sla_due_date).toLocaleDateString()}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDetail(f.finding_id);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                        >
                          Review &rarr;
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-over Detail Drawer */}
      <SlideOverDrawer
        isOpen={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
        title={selectedFinding?.cve_id || 'Vulnerability Finding'}
        subtitle={selectedFinding ? `Affected Asset: ${selectedFinding.hostname} • CVSS ${selectedFinding.cvss_score}` : ''}
        badge={<SeverityBadge severity={selectedFinding?.severity || 'HIGH'} size="md" />}
      >
        {selectedFinding && (
          <div className="space-y-6">
            {/* Status & SLA Progress Banner */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-500 uppercase">REMEDIATION STATUS</span>
                <div><StatusBadge status={selectedFinding.status} /></div>
              </div>
              <div className="text-right space-y-1">
                <span className="text-[10px] font-mono text-slate-500 uppercase">COMPUTED RISK SCORE</span>
                <p className="text-xl font-bold font-mono text-cyan-400">{selectedFinding.priority_score} / 100</p>
              </div>
            </div>

            {/* CVE Description */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">Vulnerability Summary</span>
              <p className="text-xs text-slate-300 leading-relaxed p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
                {selectedFinding.cve_description || 'High severity vulnerability in system library allowing remote execution.'}
              </p>
            </div>

            {/* Remediation Task Details */}
            <div className="space-y-3">
              <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">Assigned Remediation Task</span>
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Task Title:</span>
                  <span className="text-white font-medium">{selectedFinding.task_title || `Patch ${selectedFinding.cve_id}`}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Assigned Fixer:</span>
                  <span className="text-cyan-400 font-medium">{selectedFinding.assignee_name || 'Priya Nair (IT Infra)'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">SLA Deadline:</span>
                  <span className="text-red-400 font-bold">{new Date(selectedFinding.sla_due_date).toLocaleString()}</span>
                </div>
                {selectedFinding.fix_notes && (
                  <div className="pt-2 border-t border-slate-800 text-slate-300">
                    <span className="text-slate-400 block mb-0.5">Fixer Notes:</span>
                    <p className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-200">{selectedFinding.fix_notes}</p>
                  </div>
                )}
                {selectedFinding.verifier_name && (
                  <div className="pt-2 border-t border-slate-800 text-slate-300">
                    <span className="text-slate-400 block mb-0.5">Verification Sign-Off:</span>
                    <p className="p-2 rounded bg-emerald-950/40 border border-emerald-800 text-emerald-300">
                      Verified by: {selectedFinding.verifier_name} &bull; {selectedFinding.verification_notes}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Workflow Action Buttons */}
            <div className="pt-4 border-t border-slate-800 flex items-center gap-3">
              {selectedFinding.status !== 'REMEDIATED' && (
                <button
                  onClick={() => setShowRemediateModal(true)}
                  className="flex-1 py-2 rounded-xl bg-orange-500 hover:bg-orange-400 text-slate-950 font-bold font-mono text-xs transition-colors shadow-lg shadow-orange-500/20"
                >
                  Submit Fix Evidence
                </button>
              )}

              {selectedFinding.status === 'PENDING_VERIFICATION' && (
                <button
                  onClick={() => setShowVerifyModal(true)}
                  className="flex-1 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-colors shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-1.5"
                >
                  <ShieldCheck className="w-4 h-4" /> Verify Resolution (2-Party)
                </button>
              )}
            </div>
          </div>
        )}
      </SlideOverDrawer>

      {/* Transparent Formula Breakdown Modal */}
      {showFormulaModal && formulaBreakdown && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Calculator className="w-5 h-5 text-cyan-400" /> Transparent Priority Calculation
              </h3>
              <button onClick={() => setShowFormulaModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-400 text-center">
              <code>{formulaBreakdown.formula}</code>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">CVSS Base Score:</span>
                <span className="text-white font-bold">{formulaBreakdown.cvss_score} (&times; 10 = {formulaBreakdown.base_val})</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Asset Criticality (Tier {formulaBreakdown.asset_criticality}):</span>
                <span className="text-white font-bold">Multiplier &times; {formulaBreakdown.asset_criticality_weight}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Exploit Available:</span>
                <span className="text-white font-bold">{formulaBreakdown.exploit_available ? 'Yes (× 1.25)' : 'No (× 1.00)'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Control Effectiveness Reduction:</span>
                <span className="text-white font-bold">{formulaBreakdown.control_effectiveness * 100}%</span>
              </div>
              <div className="flex justify-between pt-2 text-sm font-bold">
                <span className="text-cyan-400">Normalized Priority Score:</span>
                <span className="text-cyan-400 font-mono">{formulaBreakdown.normalized_score} / 100 ({formulaBreakdown.severity_bucket})</span>
              </div>
            </div>

            <button
              onClick={() => setShowFormulaModal(false)}
              className="w-full py-2 rounded-xl bg-slate-800 text-xs font-mono text-white font-semibold"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Remediate Fix Modal */}
      {showRemediateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Submit Fix Evidence</h3>
            <p className="text-xs text-slate-400 font-mono">
              Provide package patch notes, configuration changes, or hotfix evidence for verification.
            </p>
            <textarea
              rows={4}
              value={fixNotes}
              onChange={e => setFixNotes(e.target.value)}
              placeholder="Upgraded log4j-core package to v2.17.1, verified service restart..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            />
            <div className="flex justify-end gap-2.5">
              <button
                onClick={() => setShowRemediateModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-mono text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitFix}
                className="px-4 py-2 rounded-xl bg-orange-500 hover:bg-orange-400 text-slate-950 font-bold font-mono text-xs"
              >
                Submit for Verification
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Two-Party Verification Modal */}
      {showVerifyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" /> Independent Verification Sign-Off
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Segregation of duties: Verification must be completed by a different user than the assigned fixer.
            </p>
            {verifyError && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-800 text-xs text-red-300 font-mono">
                {verifyError}
              </div>
            )}
            <textarea
              rows={3}
              value={verificationNotes}
              onChange={e => setVerificationNotes(e.target.value)}
              placeholder="Performed post-fix vulnerability scan with Nessus/Qualys; finding confirmed remediated."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            />
            <div className="flex justify-end gap-2.5">
              <button
                onClick={() => setShowVerifyModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-mono text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleVerifyResolution}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs"
              >
                Authorize & Close Finding
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
