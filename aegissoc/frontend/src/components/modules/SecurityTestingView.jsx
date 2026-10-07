import React, { useState } from 'react';
import { 
  Zap, 
  Play, 
  Download, 
  CheckCircle, 
  AlertTriangle, 
  ShieldAlert, 
  Globe, 
  Code,
  FileText
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import { api } from '../../services/api';

export default function SecurityTestingView() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8000/api/v1/security-tests/mock-target');
  const [options, setOptions] = useState({
    check_cors: true,
    check_security_headers: true,
    check_clickjacking: true,
    check_ssl: true
  });
  const [isRunning, setIsRunning] = useState(false);
  const [dastResult, setDastResult] = useState(null);

  const handleRunDast = async () => {
    setIsRunning(true);
    try {
      const res = await api.runDast({
        target_url: targetUrl,
        ...options
      });
      setDastResult(res);
    } catch (err) {
      alert(`DAST audit failed: ${err.message}`);
    } finally {
      setIsRunning(false);
    }
  };

  const handleDownload = (format) => {
    if (!dastResult) return;
    const url = format === 'junit' 
      ? api.getDastJunitUrl(dastResult.id)
      : api.getDastSarifUrl(dastResult.id);
    window.open(url, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl soc-panel border-cyan-500/20">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Zap className="w-5 h-5 text-cyan-400" />
            Automated Defensive DAST & Header Testing Harness
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Dynamic analysis verifying CORS policies, anti-clickjacking, CSP, and exporting CI/CD JUnit XML & SARIF reports.
          </p>
        </div>

        {dastResult && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleDownload('junit')}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              JUnit XML
            </button>
            <button
              onClick={() => handleDownload('sarif')}
              className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono flex items-center gap-1.5 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              SARIF v2.1.0
            </button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Configuration & Trigger */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-5 rounded-xl soc-panel space-y-4">
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-cyan-400" />
                Target Web Application Endpoint
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="w-full text-xs font-mono bg-slate-950/80 border border-soc-border rounded-lg p-2.5 text-cyan-200 focus:outline-none focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500 block">
                Pre-configured with defensive mock test endpoint for automated test verification.
              </span>
            </div>

            <div className="space-y-2 pt-2 border-t border-soc-border">
              <span className="text-xs font-semibold text-slate-300 block">
                Active Test Suites
              </span>
              <div className="space-y-2 text-xs text-slate-300">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.check_security_headers}
                    onChange={(e) => setOptions({ ...options, check_security_headers: e.target.checked })}
                    className="rounded bg-slate-900 border-soc-border text-cyan-500"
                  />
                  <span>Security Headers (CSP, HSTS, X-Content-Type)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.check_cors}
                    onChange={(e) => setOptions({ ...options, check_cors: e.target.checked })}
                    className="rounded bg-slate-900 border-soc-border text-cyan-500"
                  />
                  <span>CORS Wildcard & Credential Policies</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.check_clickjacking}
                    onChange={(e) => setOptions({ ...options, check_clickjacking: e.target.checked })}
                    className="rounded bg-slate-900 border-soc-border text-cyan-500"
                  />
                  <span>Clickjacking Protection (X-Frame-Options)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.check_ssl}
                    onChange={(e) => setOptions({ ...options, check_ssl: e.target.checked })}
                    className="rounded bg-slate-900 border-soc-border text-cyan-500"
                  />
                  <span>Transport Security (HTTPS/TLS Validation)</span>
                </label>
              </div>
            </div>

            <button
              onClick={handleRunDast}
              disabled={isRunning}
              className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isRunning ? 'Auditing Headers & Directives...' : 'Trigger Baseline DAST Audit'}
            </button>
          </div>

          <div className="p-4 rounded-xl soc-card space-y-2 text-xs text-slate-400">
            <h4 className="text-slate-200 font-semibold flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              CI/CD Pipeline Integration
            </h4>
            <p className="text-[11px] leading-relaxed">
              Export findings directly to Jenkins, GitLab CI, or GitHub Advanced Security via standardized JUnit XML and OASIS SARIF v2.1.0 payloads.
            </p>
          </div>
        </div>

        {/* Right Column: DAST Audit Results */}
        <div className="lg:col-span-7 space-y-4">
          {dastResult ? (
            <div className="space-y-4">
              {/* Score Gauge */}
              <div className="p-4 rounded-xl soc-panel flex items-center justify-between">
                <div>
                  <span className="text-xs text-slate-400">Security Header Compliance Score</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-3xl font-extrabold font-mono text-cyan-400">
                      {dastResult.security_score}%
                    </span>
                    <span className="text-xs text-slate-400">
                      ({dastResult.passed_tests}/{dastResult.total_tests} Passed · {dastResult.scan_duration_ms}ms)
                    </span>
                  </div>
                </div>

                <div className="flex gap-2">
                  <div className="px-3 py-1 rounded bg-emerald-500/10 text-emerald-400 font-mono text-xs border border-emerald-500/20">
                    PASS: {dastResult.passed_tests}
                  </div>
                  <div className="px-3 py-1 rounded bg-rose-500/10 text-rose-400 font-mono text-xs border border-rose-500/20">
                    FAIL: {dastResult.failed_tests}
                  </div>
                </div>
              </div>

              {/* Findings */}
              <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                {dastResult.findings.map((f) => (
                  <div
                    key={f.test_id}
                    className={`p-4 rounded-xl soc-card space-y-2 border-l-4 ${
                      f.passed ? 'border-l-emerald-500 bg-emerald-950/10' : 'border-l-rose-500 bg-rose-950/10'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={f.passed ? 'Passed' : f.severity} size="sm" />
                          <h4 className="text-xs font-bold text-slate-100">
                            {f.name}
                          </h4>
                        </div>
                        <span className="text-[10px] text-cyan-400 font-mono">
                          {f.category} · {f.cwe}
                        </span>
                      </div>
                      <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${
                        f.passed ? 'text-emerald-400 bg-emerald-500/20' : 'text-rose-400 bg-rose-500/20'
                      }`}>
                        {f.passed ? 'COMPLIANT' : 'MISSING / INSECURE'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] p-2 rounded bg-slate-950/70 border border-slate-900 font-mono">
                      <div>
                        <span className="text-slate-500 block">Observed Value:</span>
                        <span className="text-rose-300 truncate block">{f.observed_value}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Expected Baseline:</span>
                        <span className="text-emerald-400 truncate block">{f.expected_value}</span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300">
                      <strong className="text-cyan-400">Remediation:</strong> {f.remediation}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-12 text-center soc-panel rounded-xl text-slate-500 min-h-[380px]">
              <Zap className="w-10 h-10 mb-3 text-slate-600" />
              <h3 className="text-sm font-semibold text-slate-300">DAST Testing Ready</h3>
              <p className="text-xs max-w-sm mt-1">
                Configure test options and click 'Trigger Baseline DAST Audit' to inspect HTTP headers and CORS configuration.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
