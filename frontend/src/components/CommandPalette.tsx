import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  Server,
  Bug,
  Flame,
  FileCheck2,
  SlidersHorizontal,
  X,
  ArrowRight
} from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export const CommandPalette: React.FC<Props> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(); // parent will toggle
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const quickNav = [
    { label: 'Security Posture Overview', path: '/', icon: SlidersHorizontal, group: 'Navigation' },
    { label: 'Asset Inventory & Specs', path: '/assets', icon: Server, group: 'Navigation' },
    { label: 'Vulnerability Queue & SLA', path: '/vulnerabilities', icon: Bug, group: 'Navigation' },
    { label: 'Active Security Incidents', path: '/incidents', icon: Flame, group: 'Navigation' },
    { label: 'ISO 27001 & NIST CSF Audit', path: '/compliance', icon: FileCheck2, group: 'Navigation' }
  ];

  const sampleTargets = [
    { label: 'nx-payment-gw-005.nexora.corp (Finance Prod)', path: '/assets', type: 'Asset (Critical)', icon: Server },
    { label: 'CVE-2021-44228 (Apache Log4Shell RCE)', path: '/vulnerabilities', type: 'Vulnerability (CVSS 10.0)', icon: Bug },
    { label: 'INC-2026-001 (Ransomware Canary Triggered)', path: '/incidents', type: 'Incident (Critical)', icon: Flame },
    { label: 'Control A.8.8 (Management of Technical Vulnerabilities)', path: '/compliance', type: 'Control (Failing)', icon: FileCheck2 }
  ];

  const filteredTargets = sampleTargets.filter(t =>
    t.label.toLowerCase().includes(query.toLowerCase()) || t.type.toLowerCase().includes(query.toLowerCase())
  );

  const handleSelect = (path: string) => {
    navigate(path);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-xl rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden flex flex-col">
        {/* Input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800">
          <Search className="w-5 h-5 text-cyan-400" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command, asset hostname, CVE ID, or incident..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="flex-1 bg-transparent border-none outline-none text-sm text-white placeholder-slate-500 font-sans"
          />
          <button onClick={onClose} className="p-1 rounded text-slate-500 hover:text-slate-300">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-3">
          {query.trim().length > 0 ? (
            <div>
              <p className="px-3 py-1 text-[10px] font-mono uppercase text-slate-500 font-semibold">Matched Entities</p>
              {filteredTargets.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">No matching assets or security findings found.</div>
              ) : (
                filteredTargets.map((item, idx) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={idx}
                      onClick={() => handleSelect(item.path)}
                      className="w-full flex items-center justify-between px-3 py-2.5 rounded-lg hover:bg-slate-800 text-xs text-left group transition-colors"
                    >
                      <div className="flex items-center gap-3 truncate">
                        <Icon className="w-4 h-4 text-cyan-400 shrink-0" />
                        <div className="truncate">
                          <p className="text-slate-200 font-medium group-hover:text-white truncate">{item.label}</p>
                          <p className="text-[10px] text-slate-400 font-mono">{item.type}</p>
                        </div>
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 transition-colors" />
                    </button>
                  );
                })
              )}
            </div>
          ) : (
            <div>
              <p className="px-3 py-1 text-[10px] font-mono uppercase text-slate-500 font-semibold">Quick Module Jump</p>
              {quickNav.map((item, idx) => {
                const Icon = item.icon;
                return (
                  <button
                    key={idx}
                    onClick={() => handleSelect(item.path)}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-lg hover:bg-slate-800 text-xs text-left group transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Icon className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition-colors" />
                      <span className="text-slate-300 group-hover:text-white font-medium">{item.label}</span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">Jump</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-slate-950/60 border-t border-slate-800 text-[10px] font-mono text-slate-500 flex items-center justify-between">
          <span>Navigate with arrows, Enter to select</span>
          <span>ESC to dismiss</span>
        </div>
      </div>
    </div>
  );
};
