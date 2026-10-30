import React from 'react';

export const StatusPill = ({ status, severity, label, size = 'sm' }) => {
  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';

  const s = (status || severity || label || '').toUpperCase();

  if (s === 'CRITICAL' || s === 'MALICIOUS' || s === 'ATTACK' || s === 'DANGER') {
    colorClasses = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
  } else if (s === 'HIGH' || s === 'SUSPICIOUS' || s === 'NEW') {
    colorClasses = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
  } else if (s === 'MEDIUM' || s === 'INVESTIGATING') {
    colorClasses = 'bg-blue-500/10 text-blue-400 border-blue-500/30';
  } else if (s === 'LOW' || s === 'NORMAL' || s === 'RESOLVED' || s === 'CLOSED' || s === 'ONLINE' || s === 'ACTIVE') {
    colorClasses = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  } else if (s === 'FALSE_POSITIVE') {
    colorClasses = 'bg-purple-500/10 text-purple-400 border-purple-500/30';
  }

  const sizeClasses = size === 'xs' 
    ? 'text-[10px] px-1.5 py-0.5' 
    : size === 'md' 
    ? 'text-xs px-2.5 py-1' 
    : 'text-[11px] px-2 py-0.5';

  return (
    <span className={`inline-flex items-center gap-1.5 font-medium uppercase tracking-wider rounded-md border ${colorClasses} ${sizeClasses}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80"></span>
      {label || status || severity}
    </span>
  );
};
