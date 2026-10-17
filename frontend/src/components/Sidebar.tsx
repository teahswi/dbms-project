import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Server,
  Bug,
  BellRing,
  Flame,
  FileCheck2,
  SlidersHorizontal,
  Users2,
  FileClock,
  FileText,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

interface Props {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  openAlertsCount?: number;
  openIncidentsCount?: number;
}

export const Sidebar: React.FC<Props> = ({
  collapsed,
  setCollapsed,
  openAlertsCount = 42,
  openIncidentsCount = 5
}) => {
  const navSections = [
    {
      group: 'MONITOR',
      items: [
        { name: 'Security Posture', path: '/', icon: LayoutDashboard },
        { name: 'Alerts & Events', path: '/alerts', icon: BellRing, badge: openAlertsCount, badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/40' }
      ]
    },
    {
      group: 'ASSESS',
      items: [
        { name: 'Asset Inventory', path: '/assets', icon: Server },
        { name: 'Vulnerabilities', path: '/vulnerabilities', icon: Bug, badge: 1, badgeColor: 'bg-orange-500/20 text-orange-400 border border-orange-500/40' }
      ]
    },
    {
      group: 'RESPOND',
      items: [
        { name: 'Incident Response', path: '/incidents', icon: Flame, badge: openIncidentsCount, badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/40' }
      ]
    },
    {
      group: 'GOVERN',
      items: [
        { name: 'Risk Register & 5x5', path: '/risks', icon: SlidersHorizontal },
        { name: 'Compliance & Audit', path: '/compliance', icon: FileCheck2 },
        { name: 'Executive Reports', path: '/reports', icon: FileText }
      ]
    },
    {
      group: 'ADMIN',
      items: [
        { name: 'Access Control & RBAC', path: '/users', icon: Users2 },
        { name: 'Application Audit Logs', path: '/audit-logs', icon: FileClock }
      ]
    }
  ];

  return (
    <aside
      className={`fixed top-0 left-0 z-40 h-screen transition-all duration-300 ease-in-out border-r border-slate-800 bg-slate-950/95 backdrop-blur-md flex flex-col ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Brand header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
            <Shield className="w-5 h-5 text-slate-950 stroke-[2.5]" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="text-base font-bold tracking-tight text-white flex items-center gap-1.5 font-sans">
                Cyber<span className="text-cyan-400">Shield</span>
              </span>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
                Nexora Tech SOC
              </span>
            </div>
          )}
        </div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-colors"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {navSections.map(section => (
          <div key={section.group}>
            {!collapsed && (
              <p className="px-3 mb-2 text-[10px] font-mono font-semibold tracking-wider text-slate-500 uppercase">
                {section.group}
              </p>
            )}
            <nav className="space-y-1">
              {section.items.map(item => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                      }`
                    }
                    title={collapsed ? item.name : undefined}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    {!collapsed && <span className="flex-1 truncate">{item.name}</span>}
                    {!collapsed && item.badge !== undefined && (
                      <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${item.badgeColor}`}>
                        {item.badge}
                      </span>
                    )}
                  </NavLink>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      {/* Footer System Status */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/80">
        <div className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping shrink-0" />
          {!collapsed && (
            <div className="flex flex-col truncate">
              <span className="text-slate-300 font-medium">DBMS Core: Active</span>
              <span className="text-[10px] text-slate-500">Dual MySQL / Mongo</span>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
