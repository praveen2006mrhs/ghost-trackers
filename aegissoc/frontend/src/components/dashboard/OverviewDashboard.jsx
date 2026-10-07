import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle, 
  TrendingUp, 
  Server, 
  Terminal, 
  ArrowRight, 
  RefreshCw,
  Zap,
  Activity,
  Layers,
  FileText
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
  AreaChart, 
  Area 
} from 'recharts';
import SeverityBadge from '../common/SeverityBadge';
import { api } from '../../services/api';

const SEVERITY_COLORS = {
  Critical: '#f43f5e',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#3b82f6',
  Informational: '#64748b'
};

const PIE_DATA = [
  { name: 'Critical', value: 4, color: '#f43f5e' },
  { name: 'High', value: 8, color: '#f97316' },
  { name: 'Medium', value: 14, color: '#f59e0b' },
  { name: 'Low', value: 9, color: '#3b82f6' }
];

const TIMELINE_DATA = [
  { time: '14:00', requests: 120, threats: 2 },
  { time: '14:05', requests: 350, threats: 18 },
  { time: '14:10', requests: 840, threats: 94 },
  { time: '14:15', requests: 430, threats: 22 },
  { time: '14:20', requests: 210, threats: 5 },
  { time: '14:25', requests: 190, threats: 1 }
];

export default function OverviewDashboard({ onNavigate }) {
  const [stats, setStats] = useState({
    totalScans: 28,
    activeThreats: 12,
    complianceScore: 87.5,
    systemStatus: 'Optimal'
  });
  const [isLoading, setIsLoading] = useState(false);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-xl soc-panel border-cyan-500/20 bg-gradient-to-r from-cyan-950/30 via-slate-900/60 to-slate-900/30">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            SOC Command Operations Console
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time defensive telemetry, vulnerability posture, and active incident forensics.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('vuln')}
            className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-all flex items-center gap-1.5 shadow-lg shadow-cyan-500/20"
          >
            <Zap className="w-3.5 h-3.5" />
            Launch Scanner
          </button>
          <button
            onClick={() => onNavigate('forensics')}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs transition-all flex items-center gap-1.5"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            Investigate Logs
          </button>
        </div>
      </div>

      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl soc-card">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Total Vulnerabilities</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-100 font-mono">35</span>
            <span className="text-xs text-rose-400 font-mono">+4 critical</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Across 12 inspected services
          </div>
        </div>

        <div className="p-4 rounded-xl soc-card">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Architecture Compliance</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400 font-mono">87.5%</span>
            <span className="text-xs text-emerald-400/80 font-mono">CIS/NIST</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            21 passing checks, 3 warnings
          </div>
        </div>

        <div className="p-4 rounded-xl soc-card">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Brute-Force & Anomalies</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-400 font-mono">18</span>
            <span className="text-xs text-amber-300 font-mono">Mitigated</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Top vector: SSH password guessing
          </div>
        </div>

        <div className="p-4 rounded-xl soc-card">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">STRIDE Threat Vectors</span>
            <div className="p-2 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-violet-400 font-mono">7</span>
            <span className="text-xs text-slate-400 font-mono">Tracked</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            5 mitigated, 2 in progress
          </div>
        </div>
      </div>

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown Donut Chart */}
        <div className="p-5 rounded-xl soc-panel">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Vulnerability Distribution
            </h2>
            <span className="text-[10px] font-mono text-slate-400">CVSS v3.1</span>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={PIE_DATA}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {PIE_DATA.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0d1322" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0d1322', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2 pt-3 border-t border-slate-800">
            {PIE_DATA.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  {item.name}
                </span>
                <span className="font-mono text-slate-200 font-medium">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Activity Spike Timeline */}
        <div className="p-5 rounded-xl soc-panel lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Real-time Ingress & Threat Spikes
            </h2>
            <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
              Live Telemetry
            </span>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={TIMELINE_DATA}>
                <defs>
                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0d1322', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="requests" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorRequests)" name="HTTP Requests" />
                <Area type="monotone" dataKey="threats" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#colorThreats)" name="Threat Events" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 mt-2 pt-3 border-t border-slate-800">
            <span>Peak Spike: 14:10 UTC (Auth brute-force burst from 198.51.100.22)</span>
            <span className="text-cyan-400 font-mono">T1110 Credential Access</span>
          </div>
        </div>
      </div>

      {/* Module Navigation Cards */}
      <div>
        <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
          Cyber Defense Operations Grid
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div 
            onClick={() => onNavigate('vuln')}
            className="p-4 rounded-xl soc-card cursor-pointer group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                1. Static Code & Secrets Scanner
              </span>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Detect hardcoded API secrets, SQL injections, insecure deserialization, and compute CVSS 3.1.
            </p>
          </div>

          <div 
            onClick={() => onNavigate('architecture')}
            className="p-4 rounded-xl soc-card cursor-pointer group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                2. Security Architecture Linter
              </span>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Audit AWS IAM policies, Kubernetes manifests, and Dockerfiles against CIS & NIST SP 800-53.
            </p>
          </div>

          <div 
            onClick={() => onNavigate('forensics')}
            className="p-4 rounded-xl soc-card cursor-pointer group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                3. Incident Forensics Timeline
              </span>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Parse web logs, Linux auth logs, and Windows Event logs with brute-force correlation.
            </p>
          </div>

          <div 
            onClick={() => onNavigate('threat_model')}
            className="p-4 rounded-xl soc-card cursor-pointer group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                4. STRIDE Threat Modeling
              </span>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Interactive 5x5 Likelihood × Impact Risk Heatmap with mitigation tracking.
            </p>
          </div>

          <div 
            onClick={() => onNavigate('security_tests')}
            className="p-4 rounded-xl soc-card cursor-pointer group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                5. Automated DAST Harness
              </span>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Audit security headers, CORS policies, clickjacking, and export JUnit XML & SARIF reports.
            </p>
          </div>

          <div 
            onClick={() => onNavigate('malware')}
            className="p-4 rounded-xl soc-card cursor-pointer group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                6. Defensive Malware Triage
              </span>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Static file inspection, Shannon entropy analysis, PE/ELF headers, and mock YARA matching.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
