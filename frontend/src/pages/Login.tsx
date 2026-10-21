import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, Mail, ArrowRight, UserCheck, AlertCircle } from 'lucide-react';

export const Login: React.FC = () => {
  const { login, loginAsDemo, isLoading } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@nexora.test');
  const [password, setPassword] = useState('Nexora@2026');
  const [error, setError] = useState<string | null>(null);

  const personas = [
    {
      role: 'Security Analyst',
      email: 'analyst@nexora.test',
      name: 'Aarav Sharma',
      desc: 'Triage alerts, investigate IOCs, run incidents',
      badge: 'border-cyan-500/40 text-cyan-400 bg-cyan-950/40'
    },
    {
      role: 'IT Infrastructure Engineer',
      email: 'infra@nexora.test',
      name: 'Priya Nair',
      desc: 'Own assets, fix vulnerabilities, submit evidence',
      badge: 'border-emerald-500/40 text-emerald-400 bg-emerald-950/40'
    },
    {
      role: 'Compliance Auditor',
      email: 'auditor@nexora.test',
      name: 'Rohan Deshmukh',
      desc: 'Run audit plans, assess controls, raise findings',
      badge: 'border-purple-500/40 text-purple-400 bg-purple-950/40'
    },
    {
      role: 'Security Manager',
      email: 'manager@nexora.test',
      name: 'Kavita Reddy',
      desc: 'Approve risk treatments, monitor SLAs, view posture',
      badge: 'border-amber-500/40 text-amber-400 bg-amber-950/40'
    },
    {
      role: 'Admin',
      email: 'admin@nexora.test',
      name: 'Vikram Patel',
      desc: 'Manage RBAC permissions, inspect immutable audit logs',
      badge: 'border-red-500/40 text-red-400 bg-red-950/40'
    }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await login(email, password);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err.message || 'Login failed. Please verify credentials.');
    }
  };

  const handleDemoClick = async (demoEmail: string) => {
    setError(null);
    try {
      await loginAsDemo(demoEmail);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err.message || 'Demo login failed.');
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center py-12 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Background Cyber Accents */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-cyan-600/15 via-indigo-600/10 to-transparent blur-3xl pointer-events-none" />
      <div className="absolute -bottom-20 -right-20 w-[600px] h-[300px] bg-indigo-500/10 blur-3xl pointer-events-none" />

      {/* Header */}
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center relative z-10">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500 to-indigo-600 shadow-xl shadow-cyan-500/20 mb-4 border border-cyan-400/30">
          <Shield className="w-9 h-9 text-slate-950 stroke-[2.5]" />
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-white font-sans">
          Cyber<span className="text-cyan-400">Shield</span>
        </h1>
        <p className="mt-1 text-sm font-mono text-slate-400">
          Nexora Technologies Enterprise Risk & Operations SOC
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-xl relative z-10 px-4">
        {/* Main Login Card */}
        <div className="glass-panel rounded-2xl p-8 border border-slate-800 shadow-2xl space-y-6">
          {error && (
            <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-500/50 flex items-center gap-3 text-red-300 text-xs font-mono">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 font-mono mb-1">
                CORPORATE EMAIL
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  placeholder="analyst@nexora.test"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 font-mono mb-1">
                PASSWORD
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  placeholder="••••••••••••"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs uppercase tracking-wider font-mono shadow-lg shadow-cyan-500/25 flex items-center justify-center gap-2 transition-all disabled:opacity-50"
            >
              {isLoading ? 'Authenticating...' : 'Sign In to Operations Portal'}
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Quick Demo Persona Switcher Section */}
          <div className="pt-4 border-t border-slate-800/80">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
                <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
                Instant Demo Persona Quick Switcher
              </span>
              <span className="text-[10px] text-slate-500 font-mono">1-Click Auto-Login</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {personas.map(p => (
                <button
                  key={p.email}
                  type="button"
                  onClick={() => handleDemoClick(p.email)}
                  disabled={isLoading}
                  className="text-left p-3 rounded-xl bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between group"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">
                      {p.role}
                    </span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${p.badge}`}>
                      TRY
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 truncate">{p.name}</p>
                  <p className="text-[10px] text-slate-500 mt-1 line-clamp-1">{p.desc}</p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Security & Academic Disclaimers */}
        <div className="mt-6 text-center text-xs text-slate-500 font-mono">
          Nexora Technologies &copy; 2026. DBMS Project Evaluation Environment.
          <br />
          Dual Repository Architecture: MySQL 3NF (InnoDB) + MongoDB ($jsonSchema).
        </div>
      </div>
    </div>
  );
};
