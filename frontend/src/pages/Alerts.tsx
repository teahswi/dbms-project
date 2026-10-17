import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { SecurityAlert } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import {
  BellRing,
  Flame,
  LayoutGrid,
  Table as TableIcon,
  ShieldAlert,
  Activity,
  Layers,
  CheckCircle2,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';

export const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'table' | 'kanban' | 'events'>('kanban');
  const [selectedAlerts, setSelectedAlerts] = useState<number[]>([]);
  const [showEscalateModal, setShowEscalateModal] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState('Escalated Incident from Alerts');

  const loadData = async () => {
    setLoading(true);
    try {
      const [alertRes, eventRes] = await Promise.all([
        api.getAlerts(),
        api.getSecurityEvents(40)
      ]);
      setAlerts(alertRes.data || []);
      setEvents(eventRes.data || []);
    } catch (err) {
      console.error('Failed to load alert telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleStatusChange = async (alertId: number, status: string) => {
    try {
      await api.updateAlertStatus(alertId, status);
      loadData();
    } catch (err) {
      alert('Error updating alert status: ' + err);
    }
  };

  const handleToggleSelect = (id: number) => {
    setSelectedAlerts(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleEscalateToIncident = async () => {
    if (selectedAlerts.length === 0) return;
    try {
      await api.escalateAlertsToIncident(selectedAlerts, incidentTitle, 'HIGH');
      setShowEscalateModal(false);
      setSelectedAlerts([]);
      loadData();
      alert('Successfully created new incident and linked alerts!');
    } catch (err: any) {
      alert('Error creating incident: ' + err.message);
    }
  };

  const kanbanColumns = [
    { id: 'NEW', title: 'New Alerts', border: 'border-blue-500/30' },
    { id: 'TRIAGED', title: 'Triaged', border: 'border-cyan-500/30' },
    { id: 'INVESTIGATING', title: 'Investigating', border: 'border-amber-500/30' },
    { id: 'ESCALATED', title: 'Escalated to Incident', border: 'border-red-500/30' }
  ];

  return (
    <div className="space-y-6">
      {/* Header & View Switcher */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <BellRing className="w-5 h-5 text-cyan-400" /> Security Alerts & Event Monitoring
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time Threat Telemetry &bull; Correlation Engine &bull; Automated Escalations
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {selectedAlerts.length > 0 && (
            <button
              onClick={() => setShowEscalateModal(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-red-500 hover:bg-red-400 text-slate-950 font-bold font-mono text-xs shadow-lg shadow-red-500/20"
            >
              <Flame className="w-3.5 h-3.5" />
              Create Incident ({selectedAlerts.length})
            </button>
          )}

          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-xl p-1 text-xs">
            <button
              onClick={() => setViewMode('kanban')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-mono transition-colors ${
                viewMode === 'kanban' ? 'bg-cyan-500/20 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" /> Kanban
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-mono transition-colors ${
                viewMode === 'table' ? 'bg-cyan-500/20 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <TableIcon className="w-3.5 h-3.5" /> Table
            </button>
            <button
              onClick={() => setViewMode('events')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-mono transition-colors ${
                viewMode === 'events' ? 'bg-cyan-500/20 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" /> Raw Events (5k)
            </button>
          </div>
        </div>
      </div>

      {/* Kanban Board View */}
      {viewMode === 'kanban' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {kanbanColumns.map(col => {
            const columnAlerts = alerts.filter(a => a.status === col.id);
            return (
              <div key={col.id} className="space-y-3">
                <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                  <span className="text-xs font-bold font-mono text-slate-300 uppercase">{col.title}</span>
                  <span className="text-xs font-mono text-cyan-400 font-bold px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                    {columnAlerts.length}
                  </span>
                </div>

                <div className="space-y-3 max-h-[calc(100vh-280px)] overflow-y-auto pr-1">
                  {columnAlerts.map(alert => (
                    <div
                      key={alert.alert_id}
                      onClick={() => handleToggleSelect(alert.alert_id)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                        selectedAlerts.includes(alert.alert_id)
                          ? 'bg-cyan-950/40 border-cyan-500/80 shadow-lg shadow-cyan-500/10'
                          : 'bg-slate-900/60 hover:bg-slate-900 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <SeverityBadge severity={alert.severity} size="sm" />
                        {alert.duplicate_count > 1 && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            &times;{alert.duplicate_count} dups
                          </span>
                        )}
                      </div>

                      <h4 className="text-xs font-bold text-white leading-snug line-clamp-2 mb-1.5">
                        {alert.title}
                      </h4>

                      <p className="text-[11px] text-slate-400 line-clamp-2 mb-2">
                        {alert.description}
                      </p>

                      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
                        <span className="truncate max-w-[120px]">{alert.hostname || `Asset #${alert.asset_id}`}</span>
                        <span className="text-cyan-400">{alert.correlation_id}</span>
                      </div>

                      {/* Quick Move Action */}
                      {col.id === 'NEW' && (
                        <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex justify-end">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleStatusChange(alert.alert_id, 'TRIAGED');
                            }}
                            className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 font-semibold"
                          >
                            Mark Triaged &rarr;
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Table View */}
      {viewMode === 'table' && (
        <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4 w-10">Select</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Alert Title</th>
                <th className="py-3 px-4">Affected Asset</th>
                <th className="py-3 px-4">Correlation Group</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Detected At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {alerts.slice(0, 50).map(alert => (
                <tr
                  key={alert.alert_id}
                  onClick={() => handleToggleSelect(alert.alert_id)}
                  className={`hover:bg-slate-900/60 cursor-pointer ${
                    selectedAlerts.includes(alert.alert_id) ? 'bg-cyan-950/20' : ''
                  }`}
                >
                  <td className="py-3 px-4 text-center">
                    <input
                      type="checkbox"
                      checked={selectedAlerts.includes(alert.alert_id)}
                      onChange={() => handleToggleSelect(alert.alert_id)}
                      className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                    />
                  </td>
                  <td className="py-3 px-4"><SeverityBadge severity={alert.severity} /></td>
                  <td className="py-3 px-4 font-medium text-white max-w-xs truncate">{alert.title}</td>
                  <td className="py-3 px-4 font-mono text-slate-400">{alert.hostname || `Asset #${alert.asset_id}`}</td>
                  <td className="py-3 px-4 font-mono text-cyan-400">{alert.correlation_id}</td>
                  <td className="py-3 px-4"><StatusBadge status={alert.status} /></td>
                  <td className="py-3 px-4 font-mono text-slate-500">{new Date(alert.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Raw Synthetic Events View */}
      {viewMode === 'events' && (
        <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
            <span className="text-xs font-bold text-white font-mono uppercase">
              High-Velocity Synthetic Security Telemetry Stream (90d TTL)
            </span>
            <span className="text-[10px] font-mono text-emerald-400">Stream Connected</span>
          </div>
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-[11px] text-slate-400 uppercase">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Payload Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {events.map((ev, i) => (
                <tr key={i} className="hover:bg-slate-900/60">
                  <td className="py-2.5 px-4 text-slate-500">{new Date(ev.created_at).toLocaleTimeString()}</td>
                  <td className="py-2.5 px-4 font-bold text-cyan-400">{ev.event_type}</td>
                  <td className="py-2.5 px-4 text-slate-400">{ev.source_ip}</td>
                  <td className="py-2.5 px-4 text-slate-400">{ev.destination_ip}</td>
                  <td className="py-2.5 px-4"><SeverityBadge severity={ev.severity} size="sm" /></td>
                  <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs">{JSON.stringify(ev.raw_payload)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Escalate to Incident Modal */}
      {showEscalateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Flame className="w-5 h-5 text-red-500" /> Escalate Selected Alerts to Incident
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Auto-links {selectedAlerts.length} correlated alerts and will attach the affected asset's open vulnerability findings.
            </p>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">INCIDENT TITLE</label>
              <input
                type="text"
                value={incidentTitle}
                onChange={e => setIncidentTitle(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => setShowEscalateModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-mono text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleEscalateToIncident}
                className="px-4 py-2 rounded-xl bg-red-500 hover:bg-red-400 text-slate-950 font-bold font-mono text-xs"
              >
                Launch Incident
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
