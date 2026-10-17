import React from 'react';
import type { SeverityLevel } from '../types';

interface Props {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'sm', showDot = true }) => {
  const sev = (severity || 'INFO').toUpperCase();

  const config: Record<string, { bg: string; text: string; border: string; dot: string }> = {
    CRITICAL: {
      bg: 'bg-red-950/60',
      text: 'text-red-400',
      border: 'border-red-600/40',
      dot: 'bg-red-500 animate-pulse'
    },
    HIGH: {
      bg: 'bg-orange-950/60',
      text: 'text-orange-400',
      border: 'border-orange-600/40',
      dot: 'bg-orange-500'
    },
    MEDIUM: {
      bg: 'bg-amber-950/60',
      text: 'text-amber-400',
      border: 'border-amber-600/40',
      dot: 'bg-amber-500'
    },
    LOW: {
      bg: 'bg-sky-950/60',
      text: 'text-sky-400',
      border: 'border-sky-600/40',
      dot: 'bg-sky-500'
    },
    INFO: {
      bg: 'bg-slate-900',
      text: 'text-slate-400',
      border: 'border-slate-700',
      dot: 'bg-slate-400'
    }
  };

  const style = config[sev] || config.INFO;
  const sizeClasses = size === 'lg' ? 'px-3 py-1 text-xs' : (size === 'md' ? 'px-2.5 py-0.5 text-xs' : 'px-2 py-0.5 text-[11px]');

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-md border ${style.bg} ${style.text} ${style.border} ${sizeClasses}`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />}
      {sev}
    </span>
  );
};
