import React from 'react';

const SEVERITY_STYLES = {
  Critical: 'bg-rose-500/20 text-rose-400 border-rose-500/40 shadow-rose-900/20',
  High: 'bg-orange-500/20 text-orange-400 border-orange-500/40 shadow-orange-900/20',
  Medium: 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-amber-900/20',
  Low: 'bg-blue-500/20 text-blue-400 border-blue-500/40 shadow-blue-900/20',
  Informational: 'bg-slate-500/20 text-slate-400 border-slate-500/40 shadow-slate-900/20',
  None: 'bg-slate-600/20 text-slate-400 border-slate-600/40 shadow-none',
  Passed: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shadow-emerald-900/20',
  Failed: 'bg-rose-500/20 text-rose-400 border-rose-500/40 shadow-rose-900/20',
  MALICIOUS: 'bg-rose-600/30 text-rose-400 border-rose-500/50 shadow-rose-900/30',
  SUSPICIOUS: 'bg-amber-600/30 text-amber-300 border-amber-500/50 shadow-amber-900/30',
  CLEAN: 'bg-emerald-600/30 text-emerald-400 border-emerald-500/50 shadow-emerald-900/30'
};

export default function SeverityBadge({ severity = 'Low', className = '', size = 'md' }) {
  const style = SEVERITY_STYLES[severity] || SEVERITY_STYLES.Informational;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center font-medium rounded-full border shadow-sm ${padding} ${style} ${className}`}>
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
      {severity}
    </span>
  );
}
