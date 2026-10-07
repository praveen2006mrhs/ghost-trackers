import React, { useState, useEffect } from 'react';
import { 
  FileSearch, 
  Play, 
  AlertTriangle, 
  ShieldAlert, 
  Terminal, 
  Clock, 
  Globe, 
  User, 
  Filter,
  CheckCircle,
  Activity
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import { api } from '../../services/api';

export default function ForensicsView() {
  const [logType, setLogType] = useState('linux_auth'); // apache_nginx, linux_auth, windows_evtx_json
  const [logContent, setLogContent] = useState('');
  const [sampleLogs, setSampleLogs] = useState({});
  const [forensicsResult, setForensicsResult] = useState(null);
  const [isParsing, setIsParsing] = useState(false);
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false);

  useEffect(() => {
    async function loadSamples() {
      try {
        const samples = await api.getSampleLogs();
        setSampleLogs(samples);
        setLogContent(samples.linux_auth || '');
      } catch (err) {
        console.error("Failed to load sample logs:", err);
      }
    }
    loadSamples();
  }, []);

  const handleSelectType = (type) => {
    setLogType(type);
    if (sampleLogs[type]) {
      setLogContent(sampleLogs[type]);
    }
    setForensicsResult(null);
  };

  const handleParseLogs = async () => {
    setIsParsing(true);
    try {
      const res = await api.parseLogs(logType, logContent);
      setForensicsResult(res);
    } catch (err) {
      alert(`Forensics parse failed: ${err.message}`);
    } finally {
      setIsParsing(false);
    }
  };

  const filteredTimeline = forensicsResult?.timeline?.filter(
    (e) => !showAnomaliesOnly || e.is_anomaly
  ) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl soc-panel border-cyan-500/20">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-cyan-400" />
            Incident Response & Forensic Artifact Timeline
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Multiformat log ingestion (Apache/Nginx, Linux Auth, Windows EVTX) with brute-force anomaly correlation.
          </p>
        </div>

        {/* Log Source Selector */}
        <div className="flex rounded-lg bg-slate-900/80 p-1 border border-soc-border">
          <button
            onClick={() => handleSelectType('linux_auth')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
              logType === 'linux_auth' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Linux Auth.log
          </button>
          <button
            onClick={() => handleSelectType('apache_nginx')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
              logType === 'apache_nginx' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Apache/Nginx Access
          </button>
          <button
            onClick={() => handleSelectType('windows_evtx_json')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
              logType === 'windows_evtx_json' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Windows Event Log
          </button>
        </div>
      </div>

      {/* Input Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-xl soc-panel space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Raw Log Stream
              </span>
              <button
                onClick={() => setLogContent(sampleLogs[logType] || '')}
                className="text-[11px] text-cyan-400 hover:underline"
              >
                Reload Sample
              </button>
            </div>

            <textarea
              value={logContent}
              onChange={(e) => setLogContent(e.target.value)}
              rows={16}
              className="w-full font-mono text-xs bg-slate-950/80 border border-soc-border rounded-lg p-3 text-cyan-100/90 focus:outline-none focus:border-cyan-500/60 leading-relaxed resize-none"
              placeholder="Paste raw log data..."
            />

            <button
              onClick={handleParseLogs}
              disabled={isParsing}
              className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isParsing ? 'Correlating Artifacts...' : 'Parse & Construct Timeline'}
            </button>
          </div>
        </div>

        {/* Forensic Telemetry & Timeline */}
        <div className="lg:col-span-7 space-y-4">
          {forensicsResult ? (
            <div className="space-y-4">
              {/* Alert Banner for Brute Force */}
              {forensicsResult.brute_force_detected && (
                <div className="p-4 rounded-xl bg-rose-500/15 border border-rose-500/40 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400">
                      <ShieldAlert className="w-5 h-5 animate-bounce" />
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-rose-200">
                        CRITICAL ALERT: Credential Brute-Force Pattern Confirmed
                      </h4>
                      <p className="text-[11px] text-rose-300/80 mt-0.5">
                        Multiple rapid authentication failures detected exceeding defensive rate threshold.
                      </p>
                    </div>
                  </div>
                  <span className="font-mono text-xs font-bold px-2.5 py-1 rounded bg-rose-500/30 text-rose-200 border border-rose-400/40">
                    MITRE T1110
                  </span>
                </div>
              )}

              {/* Stats & Tactics Summary */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg soc-card">
                  <span className="text-[10px] text-slate-400">Total Events Parsed</span>
                  <div className="text-xl font-bold font-mono text-slate-100 mt-1">
                    {forensicsResult.total_events}
                  </div>
                </div>
                <div className="p-3 rounded-lg soc-card">
                  <span className="text-[10px] text-slate-400">Anomalies Detected</span>
                  <div className="text-xl font-bold font-mono text-rose-400 mt-1">
                    {forensicsResult.anomalies_detected}
                  </div>
                </div>
                <div className="p-3 rounded-lg soc-card">
                  <span className="text-[10px] text-slate-400">MITRE Tactics</span>
                  <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                    {forensicsResult.mitre_tactics.length}
                  </div>
                </div>
              </div>

              {/* Source IP Attribution Table */}
              {forensicsResult.top_source_ips?.length > 0 && (
                <div className="p-4 rounded-xl soc-panel space-y-2">
                  <span className="text-xs font-semibold text-slate-300">
                    Top Ingress IP Frequency & Threat Flagging
                  </span>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {forensicsResult.top_source_ips.map((ipObj, idx) => (
                      <div key={idx} className="p-2 rounded bg-slate-900 border border-soc-border flex items-center justify-between text-xs">
                        <span className="font-mono text-cyan-300">{ipObj.ip}</span>
                        <span className={`font-mono text-[11px] px-1.5 py-0.5 rounded ${
                          ipObj.risk === 'High' ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-400'
                        }`}>
                          {ipObj.count} hits
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Chronological Timeline */}
              <div className="p-4 rounded-xl soc-panel space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    Forensic Chronological Timeline
                  </h3>
                  <button
                    onClick={() => setShowAnomaliesOnly(!showAnomaliesOnly)}
                    className={`text-xs px-2.5 py-1 rounded-md border transition-all flex items-center gap-1 ${
                      showAnomaliesOnly 
                        ? 'bg-rose-500/20 border-rose-500/40 text-rose-300' 
                        : 'bg-slate-800 border-slate-700 text-slate-400'
                    }`}
                  >
                    <Filter className="w-3 h-3" />
                    Anomalies Only
                  </button>
                </div>

                <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
                  {filteredTimeline.map((item, idx) => (
                    <div 
                      key={idx}
                      className={`p-3 rounded-lg soc-card text-xs space-y-1 border-l-2 ${
                        item.is_anomaly ? 'border-l-rose-500 bg-rose-950/10' : 'border-l-slate-600'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[11px] text-cyan-400">
                          {item.timestamp}
                        </span>
                        <div className="flex items-center gap-2">
                          {item.mitre_attack && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet-900/30 text-violet-300 border border-violet-800/40">
                              {item.mitre_attack}
                            </span>
                          )}
                          <SeverityBadge severity={item.severity} size="sm" />
                        </div>
                      </div>

                      <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                        {item.source_ip && <span>IP: <strong className="text-slate-200">{item.source_ip}</strong></span>}
                        {item.user && <span>User: <strong className="text-slate-200">{item.user}</strong></span>}
                        <span>Type: {item.event_type}</span>
                      </div>

                      <p className="text-slate-200 font-mono text-[11px] bg-slate-950/40 p-1.5 rounded">
                        {item.details}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-12 text-center soc-panel rounded-xl text-slate-500 min-h-[380px]">
              <FileSearch className="w-10 h-10 mb-3 text-slate-600" />
              <h3 className="text-sm font-semibold text-slate-300">Ready to Ingest</h3>
              <p className="text-xs max-w-sm mt-1">
                Select a log format and click 'Parse & Construct Timeline' to generate forensic traces.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
