import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  Search,
  Bell,
  Sun,
  Moon,
  UserCheck,
  ChevronDown,
  LogOut,
  Calendar,
  ShieldAlert
} from 'lucide-react';

interface Props {
  onOpenCommandPalette: () => void;
  timeRange: string;
  setTimeRange: (range: string) => void;
}

export const Navbar: React.FC<Props> = ({ onOpenCommandPalette, timeRange, setTimeRange }) => {
  const { user, logout, theme, toggleTheme, loginAsDemo } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showDemoMenu, setShowDemoMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  const demoPersonas = [
    { email: 'analyst@nexora.test', role: 'Security Analyst', name: 'Aarav Sharma', badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' },
    { email: 'infra@nexora.test', role: 'IT Infrastructure Engineer', name: 'Priya Nair', badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    { email: 'auditor@nexora.test', role: 'Compliance Auditor', name: 'Rohan Deshmukh', badge: 'bg-purple-500/10 text-purple-400 border-purple-500/30' },
    { email: 'manager@nexora.test', role: 'Security Manager', name: 'Kavita Reddy', badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    { email: 'admin@nexora.test', role: 'Admin', name: 'Vikram Patel', badge: 'bg-red-500/10 text-red-400 border-red-500/30' }
  ];

  const recentNotifications = [
    { id: 1, title: 'CRITICAL: Log4Shell SLA Breached', time: '12m ago', desc: 'Finance Payment Gateway server #5 exceeded 7-day remediation deadline.', critical: true },
    { id: 2, title: 'Alert Auto-Escalated', time: '45m ago', desc: 'Critical malware detection escalated on Tier-1 core server.', critical: true },
    { id: 3, title: 'Audit Assessment Recorded', time: '2h ago', desc: 'Control A.8.8 marked FAIL in annual ISO 27001 audit.', critical: false }
  ];

  return (
    <header className="sticky top-0 z-30 h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between">
      {/* Search / Command Palette shortcut */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenCommandPalette}
          className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-all w-64 justify-between"
        >
          <span className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <span>Search assets, CVEs, alerts...</span>
          </span>
          <kbd className="px-1.5 py-0.5 text-[10px] font-mono bg-slate-800 text-slate-300 rounded border border-slate-700">
            Ctrl+K
          </kbd>
        </button>

        {/* Time range selector */}
        <div className="hidden lg:flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs">
          <Calendar className="w-3.5 h-3.5 text-slate-500 ml-1.5" />
          {['24h', '7d', '30d', '90d'].map(range => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                timeRange === range
                  ? 'bg-cyan-500/20 text-cyan-400 font-semibold border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Right Controls: Persona Switcher, Notifications, Theme, User */}
      <div className="flex items-center gap-3">
        {/* Quick Demo Persona Switcher */}
        <div className="relative">
          <button
            onClick={() => setShowDemoMenu(!showDemoMenu)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-indigo-950/50 hover:bg-indigo-900/50 border border-indigo-700/40 text-xs text-indigo-300 transition-colors"
            title="Switch Demo Persona"
          >
            <UserCheck className="w-3.5 h-3.5 text-indigo-400" />
            <span className="hidden sm:inline font-mono">Demo as:</span>
            <span className="font-semibold text-white">{user?.role || 'Switch Role'}</span>
            <ChevronDown className="w-3 h-3 text-indigo-400" />
          </button>

          {showDemoMenu && (
            <div className="absolute right-0 mt-2 w-72 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-2 z-50">
              <div className="px-3 py-1.5 border-b border-slate-800 mb-1">
                <p className="text-xs font-semibold text-white">Switch Role Persona</p>
                <p className="text-[11px] text-slate-400">Tailors dashboard, queues, and approvals</p>
              </div>
              <div className="space-y-1">
                {demoPersonas.map(p => (
                  <button
                    key={p.email}
                    onClick={() => {
                      loginAsDemo(p.email);
                      setShowDemoMenu(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs hover:bg-slate-800/80 flex flex-col transition-colors ${
                      user?.email === p.email ? 'bg-slate-800 border border-slate-700' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-white">{p.role}</span>
                      {user?.email === p.email && <span className="text-[10px] text-cyan-400 font-mono">ACTIVE</span>}
                    </div>
                    <span className="text-[11px] text-slate-400">{p.name}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Notifications Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-colors"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-2 z-50">
              <div className="px-3 py-2 border-b border-slate-800 flex items-center justify-between">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-red-400" /> Notifications
                </span>
                <span className="text-[10px] font-mono bg-red-950 text-red-400 px-1.5 py-0.5 rounded border border-red-800">
                  2 Critical
                </span>
              </div>
              <div className="divide-y divide-slate-800/60 max-h-72 overflow-y-auto">
                {recentNotifications.map(n => (
                  <div key={n.id} className="p-2.5 hover:bg-slate-800/40 transition-colors">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className={`font-semibold ${n.critical ? 'text-red-400' : 'text-slate-200'}`}>{n.title}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{n.time}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">{n.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-colors"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-600" />}
        </button>

        {/* User Menu */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-2 pl-2 pr-1 py-1 rounded-lg hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center text-xs font-bold text-white shadow">
              {user?.full_name?.charAt(0) || 'U'}
            </div>
            <div className="hidden md:flex flex-col text-left">
              <span className="text-xs font-semibold text-white leading-tight">{user?.full_name}</span>
              <span className="text-[10px] text-cyan-400 font-mono">{user?.role}</span>
            </div>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-56 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-2 z-50">
              <div className="px-3 py-2 border-b border-slate-800 mb-1">
                <p className="text-xs font-semibold text-white">{user?.full_name}</p>
                <p className="text-[11px] text-slate-400 font-mono truncate">{user?.email}</p>
                <p className="text-[10px] text-slate-500 mt-1">{user?.department}</p>
              </div>
              <button
                onClick={logout}
                className="w-full text-left px-3 py-2 rounded-lg text-xs text-red-400 hover:bg-red-950/40 hover:text-red-300 flex items-center gap-2 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
