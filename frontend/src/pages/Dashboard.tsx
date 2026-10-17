import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { PostureMetrics } from '../types';
import { useAuth } from '../context/AuthContext';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  ShieldAlert,
  Server,
  Bug,
  Flame,
  FileCheck2,
  SlidersHorizontal,
  Clock,
  ArrowUpRight,
  TrendingDown,
  Activity,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line
} from 'recharts';

export const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const [metrics, setMetrics] = useState<PostureMetrics | null>(null);
  const [activity, setActivity] = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [postureRes, actRes, heatRes] = await Promise.all([
          api.getPostureMetrics(),
          api.getRecentActivity(),
          api.getRiskHeatmap()
        ]);
        setMetrics(postureRes.data);
        setActivity(actRes.data || []);
        setHeatmap(heatRes.data || []);
      } catch (err) {
        console.error('Error loading posture dashboard:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading || !metrics) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-400"></div>
      </div>
    );
  }

  // Visual severity distribution
  const severityDistribution = [
    { name: 'Critical', value: metrics.critical_vulnerabilities, color: '#ef4444' },
    { name: 'High', value: 84, color: '#f97316' },
    { name: 'Medium', value: 162, color: '#f59e0b' },
    { name: 'Low', value: 92, color: '#0ea5e9' }
  ];

  const getHeatmapColor = (likelihood: number, impact: number) => {
    const score = likelihood * impact;
    if (score >= 16) return 'bg-red-500/80 hover:bg-red-500 text-white font-bold';
    if (score >= 10) return 'bg-orange-500/80 hover:bg-orange-500 text-white font-bold';
    if (score >= 6) return 'bg-amber-500/80 hover:bg-amber-500 text-slate-900 font-bold';
    return 'bg-emerald-500/80 hover:bg-emerald-500 text-slate-900 font-bold';
  };

  return (
    <div className="space-y-6">
      {/* Persona Callout Banner */}
      <div className="p-4 rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white">Welcome back, {user?.full_name}</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/40 text-cyan-400 font-semibold">
                {user?.role}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Nexora Security Operations Status: Active Defenses Operational &bull; 760 Total Managed Assets
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">MTTD:</span>
          <span className="text-emerald-400 font-bold">{metrics.mean_time_to_detect_minutes} min</span>
          <span className="text-slate-600">&bull;</span>
          <span className="text-slate-400">MTTR:</span>
          <span className="text-cyan-400 font-bold">{metrics.mean_time_to_remediate_hours} hrs</span>
        </div>
      </div>

      {/* Primary KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Posture Score Radial Gauge */}
        <div className="glass-panel-glow rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase text-slate-400">Enterprise Posture Score</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              SOC Benchmark
            </span>
          </div>
          <div className="flex items-baseline gap-2 my-2">
            <span className="text-4xl font-extrabold tracking-tight font-sans text-cyan-400">
              {metrics.posture_score}
            </span>
            <span className="text-sm font-mono text-slate-400">/ 100</span>
          </div>
          <div className="w-full bg-slate-800 rounded-full h-2 mb-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-emerald-400 via-cyan-400 to-indigo-500 h-2 rounded-full transition-all duration-1000"
              style={{ width: `${metrics.posture_score}%` }}
            />
          </div>
          <span className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Acceptable Risk Threshold
          </span>
        </div>

        {/* Critical Overdue Findings */}
        <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between border-l-4 border-l-red-500">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase text-slate-400">Critical Vulnerabilities</span>
            <Bug className="w-4 h-4 text-red-400" />
          </div>
          <div className="flex items-baseline gap-3 my-2">
            <span className="text-4xl font-extrabold tracking-tight font-sans text-red-400">
              {metrics.critical_vulnerabilities}
            </span>
            <span className="text-xs font-mono text-red-400/80 bg-red-950/60 px-1.5 py-0.5 rounded border border-red-800">
              1 SLA Breached
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Total Open Findings: {metrics.open_vulnerabilities}
          </span>
        </div>

        {/* Active Incidents & Response */}
        <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between border-l-4 border-l-orange-500">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase text-slate-400">Active Incidents</span>
            <Flame className="w-4 h-4 text-orange-400" />
          </div>
          <div className="flex items-baseline gap-3 my-2">
            <span className="text-4xl font-extrabold tracking-tight font-sans text-orange-400">
              {metrics.open_incidents}
            </span>
            <span className="text-xs font-mono text-orange-400/80 bg-orange-950/60 px-1.5 py-0.5 rounded border border-orange-800">
              2 Containment
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Active Threat Alerts: {metrics.active_alerts}
          </span>
        </div>

        {/* Compliance Failures */}
        <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between border-l-4 border-l-purple-500">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-semibold uppercase text-slate-400">Failed Controls</span>
            <FileCheck2 className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-3 my-2">
            <span className="text-4xl font-extrabold tracking-tight font-sans text-purple-400">
              {metrics.failed_controls}
            </span>
            <span className="text-xs font-mono text-purple-400/80 bg-purple-950/60 px-1.5 py-0.5 rounded border border-purple-800">
              Action Required
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            ISO 27001 & NIST CSF Plans
          </span>
        </div>
      </div>

      {/* Middle Row: Department Exposure Treemap & Vulnerability Aging Funnel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Department Exposure Bar Chart */}
        <div className="glass-panel rounded-2xl p-5 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div className="flex flex-col">
              <span className="text-sm font-bold text-white">Attack Surface & Exposure by Department</span>
              <span className="text-[11px] text-slate-400 font-mono">Aggregated risk priority score per organizational unit</span>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics.department_exposure}>
                <XAxis dataKey="department" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', color: '#fff' }}
                />
                <Bar dataKey="exposure_score" fill="#06b6d4" radius={[6, 6, 0, 0]} name="Exposure Score" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Vulnerability Aging Funnel with SLA Breaches */}
        <div className="glass-panel rounded-2xl p-5 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div className="flex flex-col">
              <span className="text-sm font-bold text-white">Vulnerability Aging & SLA Clock Funnel</span>
              <span className="text-[11px] text-slate-400 font-mono">Findings distribution against resolution due dates</span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
              1 Breach on Finance Prod
            </span>
          </div>

          <div className="space-y-3.5 my-2">
            {metrics.aging_funnel.map((item, idx) => {
              const isBreach = item.range === '60+ Days';
              const percentage = Math.min(100, (item.count / 50) * 100);
              return (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-300 font-medium">{item.range}</span>
                    <div className="flex items-center gap-2">
                      <span className={isBreach ? 'text-red-400 font-bold' : 'text-slate-300 font-bold'}>
                        {item.count} findings
                      </span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded border ${
                        isBreach ? 'bg-red-950 text-red-400 border-red-800' : 'bg-slate-900 text-slate-400 border-slate-700'
                      }`}>
                        {item.status}
                      </span>
                    </div>
                  </div>
                  <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div
                      className={`h-2 rounded-full transition-all duration-700 ${
                        isBreach ? 'bg-red-500' : (idx === 2 ? 'bg-amber-500' : 'bg-cyan-500')
                      }`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <p className="text-[11px] text-slate-400 font-mono mt-2 pt-2 border-t border-slate-800/80">
            SLA Policy: Critical = 7d &bull; High = 14d &bull; Medium = 30d &bull; Low = 90d
          </p>
        </div>
      </div>

      {/* Bottom Row: 5x5 Risk Heatmap & Live Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 5x5 Likelihood x Impact Heatmap */}
        <div className="glass-panel rounded-2xl p-5 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <span className="text-sm font-bold text-white">5x5 Enterprise Risk Heatmap</span>
              <p className="text-[11px] text-slate-400 font-mono">Likelihood (1-5) &times; Impact (1-5) Matrix</p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 font-semibold">50+ Active Risks</span>
          </div>

          {/* 5x5 Grid */}
          <div className="flex flex-col gap-1.5 max-w-sm mx-auto">
            {[5, 4, 3, 2, 1].map(imp => (
              <div key={imp} className="flex items-center gap-1.5">
                <span className="text-[10px] font-mono text-slate-500 w-6 text-right">L{imp}</span>
                <div className="grid grid-cols-5 gap-1.5 flex-1">
                  {[1, 2, 3, 4, 5].map(like => {
                    const cell = heatmap.find(h => h.likelihood === like && h.impact === imp);
                    const count = cell ? cell.count : 0;
                    return (
                      <div
                        key={like}
                        className={`h-9 rounded-lg flex items-center justify-center text-xs font-mono cursor-pointer transition-transform hover:scale-105 ${getHeatmapColor(
                          like,
                          imp
                        )}`}
                        title={`Likelihood ${like}, Impact ${imp} (Score: ${like * imp}) - ${count} Risks`}
                      >
                        {count > 0 ? count : ''}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
            <div className="flex items-center gap-1.5 pt-1">
              <span className="w-6" />
              <div className="grid grid-cols-5 gap-1.5 flex-1 text-center text-[10px] font-mono text-slate-500">
                <span>I1</span><span>I2</span><span>I3</span><span>I4</span><span>I5</span>
              </div>
            </div>
          </div>
        </div>

        {/* Live Immutable Audit Log Feed */}
        <div className="glass-panel rounded-2xl p-5 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-bold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" /> Recent Security Operations Feed
            </span>
            <span className="text-[10px] font-mono text-slate-500">Append-Only Audit</span>
          </div>

          <div className="space-y-2.5 max-h-72 overflow-y-auto divide-y divide-slate-800/60 pr-1">
            {activity.slice(0, 5).map((log, idx) => (
              <div key={idx} className="pt-2 text-xs flex items-start justify-between gap-3">
                <div className="space-y-0.5">
                  <span className="font-mono text-cyan-400 font-semibold text-[11px]">{log.action}</span>
                  <p className="text-slate-400 text-[11px]">
                    Target: <span className="font-mono text-slate-300">{log.entity_type} #{log.entity_id}</span>
                  </p>
                  <p className="text-[10px] text-slate-500 font-mono">By: {log.user_email || 'SYSTEM'}</p>
                </div>
                <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                  {new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            ))}
          </div>

          <div className="pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>SOC Event Stream: Synchronized</span>
            <span className="text-emerald-400 font-bold">&bull; Live</span>
          </div>
        </div>
      </div>
    </div>
  );
};
