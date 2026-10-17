import React from 'react';

interface Props {
  status: string;
}

export const StatusBadge: React.FC<Props> = ({ status }) => {
  const s = (status || 'UNKNOWN').toUpperCase();

  const getStyle = () => {
    switch (s) {
      case 'OPEN':
      case 'NEW':
        return 'bg-blue-950/60 text-blue-400 border-blue-700/50';
      case 'IN_PROGRESS':
      case 'TRIAGE':
      case 'CONTAINMENT':
      case 'ERADICATION':
        return 'bg-amber-950/60 text-amber-400 border-amber-700/50';
      case 'PENDING_VERIFICATION':
      case 'SUBMITTED_FOR_REVIEW':
        return 'bg-purple-950/60 text-purple-400 border-purple-700/50';
      case 'REMEDIATED':
      case 'CLOSED':
      case 'CLOSED_TP':
      case 'PASS':
      case 'APPROVED':
        return 'bg-emerald-950/60 text-emerald-400 border-emerald-700/50';
      case 'FAIL':
      case 'ESCALATED':
        return 'bg-red-950/60 text-red-400 border-red-700/50';
      case 'RISK_ACCEPTED':
      case 'ACCEPTED':
        return 'bg-orange-950/60 text-orange-400 border-orange-700/50';
      case 'FALSE_POSITIVE':
      case 'CLOSED_FP':
      case 'SUPPRESSED':
      case 'NOT_APPLICABLE':
        return 'bg-slate-900 text-slate-400 border-slate-700';
      default:
        return 'bg-slate-900 text-slate-300 border-slate-800';
    }
  };

  const formatText = (text: string) => {
    return text.replace(/_/g, ' ');
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${getStyle()}`}>
      {formatText(s)}
    </span>
  );
};
