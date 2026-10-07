import React, { useState, useEffect } from 'react';
import { Shield, Radio, Terminal, AlertTriangle, Activity, Wifi } from 'lucide-react';

export default function Navbar({ activeModule, onSelectModule }) {
  const [time, setTime] = useState(new Date().toUTCString().slice(17, 25));

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toUTCString().slice(17, 25));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="h-16 border-b border-soc-border bg-soc-panel/90 backdrop-blur-md sticky top-0 z-50 flex items-center justify-between px-6">
      {/* Brand & Project Identity */}
      <div className="flex items-center space-x-4">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-950/40">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-lg tracking-wider text-slate-100 uppercase">
              Ghost Trackers
            </span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono">
              AEGIS-SOC v1.0
            </span>
          </div>
          <p className="text-xs text-soc-muted hidden md:block">
            Autonomous Defensive Cyber Operations Suite
          </p>
        </div>
      </div>

      {/* Operational Defcon & Status Indicators */}
      <div className="flex items-center space-x-6 text-xs">
        {/* Defcon Indicator */}
        <div className="hidden lg:flex items-center space-x-2 px-3 py-1.5 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
          <Radio className="w-3.5 h-3.5 animate-pulse" />
          <span className="font-semibold tracking-wide">DEFCON 4: GUARDED</span>
        </div>

        {/* Sandbox Guard */}
        <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-md bg-blue-500/10 border border-blue-500/30 text-blue-400">
          <Terminal className="w-3.5 h-3.5" />
          <span>SANDBOX ISOLATION ACTIVE</span>
        </div>

        {/* Live UTC Clock */}
        <div className="flex items-center space-x-2 font-mono text-slate-300 bg-slate-900/60 px-3 py-1.5 rounded-md border border-slate-800">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>{time} UTC</span>
        </div>

        {/* Live Network Health Status */}
        <div className="flex items-center space-x-2 text-emerald-400">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </span>
          <span className="font-mono hidden md:inline">SYSTEMS OPERATIONAL</span>
        </div>
      </div>
    </header>
  );
}
