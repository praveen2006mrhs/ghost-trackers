import React from 'react';
import { 
  LayoutDashboard, 
  SearchCode, 
  ShieldCheck, 
  FileSearch, 
  Grid3X3, 
  Zap, 
  Binary,
  Layers,
  ExternalLink
} from 'lucide-react';

export default function Sidebar({ currentView, onSelectView }) {
  const menuItems = [
    {
      id: 'overview',
      label: 'Command Overview',
      subtitle: 'Global Threat Posture',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'vuln',
      label: 'Vulnerability Scanner',
      subtitle: 'Static SAST & CVSS 3.1',
      icon: SearchCode,
      badge: 'SAST'
    },
    {
      id: 'architecture',
      label: 'Architecture Review',
      subtitle: 'IAM, K8s & Docker Linter',
      icon: ShieldCheck,
      badge: 'CIS'
    },
    {
      id: 'forensics',
      label: 'Incident Forensics',
      subtitle: 'Log Parser & Timeline',
      icon: FileSearch,
      badge: 'IR'
    },
    {
      id: 'threat_model',
      label: 'Threat Modeling',
      subtitle: 'STRIDE & 5x5 Heatmap',
      icon: Grid3X3,
      badge: 'STRIDE'
    },
    {
      id: 'security_tests',
      label: 'Automated DAST',
      subtitle: 'CORS, Headers, SARIF',
      icon: Zap,
      badge: 'DAST'
    },
    {
      id: 'malware',
      label: 'Malware Triage',
      subtitle: 'PE/ELF & YARA Heuristics',
      icon: Binary,
      badge: 'STATIC'
    }
  ];

  return (
    <aside className="w-64 border-r border-soc-border bg-soc-panel/60 flex flex-col justify-between shrink-0">
      <div className="p-4 space-y-6">
        <div>
          <div className="text-[10px] font-semibold tracking-wider text-slate-400 uppercase px-3 mb-2">
            Operations Center
          </div>
          <nav className="space-y-1">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectView(item.id)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg flex items-center justify-between transition-all group ${
                    isActive
                      ? 'bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 shadow-md shadow-cyan-950/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-3 min-w-0">
                    <Icon className={`w-4 h-4 shrink-0 transition-colors ${
                      isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-300'
                    }`} />
                    <div className="truncate">
                      <div className="text-xs font-medium leading-tight truncate">
                        {item.label}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate">
                        {item.subtitle}
                      </div>
                    </div>
                  </div>
                  {item.badge && (
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded shrink-0 ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                        : 'bg-slate-800 text-slate-400'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Compliance frameworks mini summary */}
        <div className="p-3 rounded-lg bg-slate-900/60 border border-soc-border text-xs space-y-2">
          <div className="flex items-center justify-between text-[11px] font-medium text-slate-300">
            <span className="flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              Compliance Matrix
            </span>
            <span className="text-emerald-400 font-mono text-[10px]">100% PASS</span>
          </div>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            Mapped against CIS Benchmarks, NIST SP 800-53 Rev 5, and OWASP Top 10.
          </p>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-soc-border bg-slate-950/40">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span>Defensive Engine</span>
          <span className="font-mono text-cyan-400">ACTIVE</span>
        </div>
        <div className="text-[10px] text-slate-400 mt-1">
          Target Mode: Sandboxed Heuristics
        </div>
      </div>
    </aside>
  );
}
