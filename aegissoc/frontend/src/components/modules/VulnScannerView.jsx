import React, { useState } from 'react';
import { 
  SearchCode, 
  Play, 
  Calculator, 
  Package, 
  AlertCircle, 
  FileCode, 
  Copy, 
  Check, 
  ExternalLink,
  ShieldAlert,
  Terminal
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import { api } from '../../services/api';

const SAMPLE_VULN_CODE = `# Vulnerable Microservice Handler
import pickle
import subprocess

AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
DATABASE_URL = "postgres://admin:supersecret_password_123456@db.corp.internal/main"

def authenticate_and_query(username, query_param):
    # CRITICAL: Dynamic SQL string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND role = 'admin'"
    cursor.execute(query)

    # CRITICAL: Insecure deserialization
    cached_session = pickle.loads(raw_cookie_payload)

    # HIGH: Shell command execution with shell=True
    subprocess.Popen(f"ping -c 1 {query_param}", shell=True)

    # CRITICAL: Dangerous eval statement
    eval(f"print('User logged in: {username}')")
    
    return True
`;

const SAMPLE_REQUIREMENTS = `requests==2.28.0
urllib3==1.26.5
flask==2.1.0
pyyaml==5.3.1
cryptography==40.0.0
lodash==4.17.15
safe-library==1.0.0
`;

export default function VulnScannerView() {
  const [activeTab, setActiveTab] = useState('code'); // 'code', 'cvss', 'deps'
  
  // Code Scanner State
  const [code, setCode] = useState(SAMPLE_VULN_CODE);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);

  // CVSS Calculator State
  const [cvssMetrics, setCvssMetrics] = useState({
    attack_vector: 'NETWORK',
    attack_complexity: 'LOW',
    privileges_required: 'NONE',
    user_interaction: 'NONE',
    scope: 'UNCHANGED',
    confidentiality: 'HIGH',
    integrity: 'HIGH',
    availability: 'HIGH'
  });
  const [cvssResult, setCvssResult] = useState(null);

  // Dependency Scanner State
  const [manifestContent, setManifestContent] = useState(SAMPLE_REQUIREMENTS);
  const [manifestType, setManifestType] = useState('requirements.txt');
  const [depResult, setDepResult] = useState(null);
  const [isDepScanning, setIsDepScanning] = useState(false);

  // Handlers
  const handleScanCode = async () => {
    setIsScanning(true);
    setError(null);
    try {
      const res = await api.scanCode(code, 'python', 'AuthService.py');
      setScanResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  const handleCalculateCvss = async () => {
    try {
      const res = await api.calculateCVSS(cvssMetrics);
      setCvssResult(res);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleScanDeps = async () => {
    setIsDepScanning(true);
    setError(null);
    try {
      const res = await api.scanDependencies(manifestType, manifestContent);
      setDepResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsDepScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl soc-panel border-cyan-500/20">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <SearchCode className="w-5 h-5 text-cyan-400" />
            Vulnerability Assessment & Static Detection Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Heuristic pattern engine targeting hardcoded secrets, injection, deserialization, and CVSS 3.1 vectors.
          </p>
        </div>
        
        {/* Navigation Tabs */}
        <div className="flex rounded-lg bg-slate-900/80 p-1 border border-soc-border">
          <button
            onClick={() => setActiveTab('code')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              activeTab === 'code' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            Source SAST
          </button>
          <button
            onClick={() => {
              setActiveTab('cvss');
              if (!cvssResult) handleCalculateCvss();
            }}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              activeTab === 'cvss' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Calculator className="w-3.5 h-3.5" />
            CVSS 3.1 Engine
          </button>
          <button
            onClick={() => setActiveTab('deps')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              activeTab === 'deps' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Package className="w-3.5 h-3.5" />
            Dependencies
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* TAB 1: CODE SAST SCANNER */}
      {activeTab === 'code' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Code Editor Panel */}
          <div className="lg:col-span-6 space-y-4">
            <div className="p-4 rounded-xl soc-panel space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Target Source Snippet (Python / Node / Polyglot)
                </span>
                <button
                  onClick={() => setCode(SAMPLE_VULN_CODE)}
                  className="text-[11px] text-cyan-400 hover:underline"
                >
                  Load Insecure Fixture
                </button>
              </div>

              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                rows={16}
                className="w-full font-mono text-xs bg-slate-950/80 border border-soc-border rounded-lg p-3 text-cyan-100/90 focus:outline-none focus:border-cyan-500/60 leading-relaxed resize-none"
                placeholder="Paste source code snippet here..."
              />

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-slate-500">
                  {code.split('\n').length} lines · UTF-8
                </span>
                <button
                  onClick={handleScanCode}
                  disabled={isScanning}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all flex items-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  {isScanning ? 'Analyzing Heuristics...' : 'Execute Static Scan'}
                </button>
              </div>
            </div>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-6 space-y-4">
            {scanResult ? (
              <div className="p-4 rounded-xl soc-panel space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-soc-border">
                  <div>
                    <h3 className="text-sm font-bold text-slate-100">
                      Scan Findings ({scanResult.total_findings})
                    </h3>
                    <p className="text-[11px] text-slate-400">
                      Target: {scanResult.target_name}
                    </p>
                  </div>
                  <div className="flex gap-1.5">
                    {Object.entries(scanResult.severity_breakdown).map(([sev, count]) => (
                      count > 0 && (
                        <SeverityBadge key={sev} severity={sev} size="sm" className="font-mono">
                          {sev}: {count}
                        </SeverityBadge>
                      )
                    ))}
                  </div>
                </div>

                <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                  {scanResult.findings.map((f) => (
                    <div key={f.id} className="p-3.5 rounded-lg soc-card space-y-2 border-l-4 border-l-rose-500">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={f.severity} size="sm" />
                            <span className="text-xs font-bold text-slate-100">
                              {f.rule_name}
                            </span>
                          </div>
                          <span className="text-[10px] text-cyan-400 font-mono">
                            Line {f.line_number} · {f.cwe_id} · CVSS {f.cvss_score}
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                          {f.category}
                        </span>
                      </div>

                      <div className="p-2 rounded bg-slate-950 font-mono text-[11px] text-rose-300 border border-rose-950/40 overflow-x-auto">
                        {f.matched_snippet}
                      </div>

                      <p className="text-xs text-slate-300">
                        {f.description}
                      </p>

                      <div className="p-2.5 rounded bg-cyan-950/20 border border-cyan-800/30 text-[11px] text-cyan-300/90">
                        <strong className="text-cyan-400">Remediation:</strong> {f.remediation}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center p-12 text-center soc-panel rounded-xl text-slate-500">
                <SearchCode className="w-10 h-10 mb-3 text-slate-600" />
                <h3 className="text-sm font-semibold text-slate-300">Ready to Scan</h3>
                <p className="text-xs max-w-sm mt-1">
                  Click 'Execute Static Scan' to run regex heuristics for hardcoded credentials, SQL injection, and deserialization.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: CVSS 3.1 BASE SCORE CALCULATOR */}
      {activeTab === 'cvss' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8 p-5 rounded-xl soc-panel space-y-4">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Calculator className="w-4 h-4 text-cyan-400" />
              CVSS v3.1 Metric Vector Configurator
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Attack Vector */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Attack Vector (AV)</label>
                <select
                  value={cvssMetrics.attack_vector}
                  onChange={(e) => {
                    const next = { ...cvssMetrics, attack_vector: e.target.value };
                    setCvssMetrics(next);
                  }}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="NETWORK">Network (AV:N - 0.85)</option>
                  <option value="ADJACENT">Adjacent (AV:A - 0.62)</option>
                  <option value="LOCAL">Local (AV:L - 0.55)</option>
                  <option value="PHYSICAL">Physical (AV:P - 0.20)</option>
                </select>
              </div>

              {/* Attack Complexity */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Attack Complexity (AC)</label>
                <select
                  value={cvssMetrics.attack_complexity}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, attack_complexity: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="LOW">Low (AC:L - 0.77)</option>
                  <option value="HIGH">High (AC:H - 0.44)</option>
                </select>
              </div>

              {/* Privileges Required */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Privileges Required (PR)</label>
                <select
                  value={cvssMetrics.privileges_required}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, privileges_required: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="NONE">None (PR:N - 0.85)</option>
                  <option value="LOW">Low (PR:L - 0.62)</option>
                  <option value="HIGH">High (PR:H - 0.27)</option>
                </select>
              </div>

              {/* User Interaction */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">User Interaction (UI)</label>
                <select
                  value={cvssMetrics.user_interaction}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, user_interaction: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="NONE">None (UI:N - 0.85)</option>
                  <option value="REQUIRED">Required (UI:R - 0.62)</option>
                </select>
              </div>

              {/* Scope */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Scope (S)</label>
                <select
                  value={cvssMetrics.scope}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, scope: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="UNCHANGED">Unchanged (S:U)</option>
                  <option value="CHANGED">Changed (S:C)</option>
                </select>
              </div>

              {/* Confidentiality */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Confidentiality Impact (C)</label>
                <select
                  value={cvssMetrics.confidentiality}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, confidentiality: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="HIGH">High (C:H - 0.56)</option>
                  <option value="LOW">Low (C:L - 0.22)</option>
                  <option value="NONE">None (C:N - 0.00)</option>
                </select>
              </div>

              {/* Integrity */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Integrity Impact (I)</label>
                <select
                  value={cvssMetrics.integrity}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, integrity: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="HIGH">High (I:H - 0.56)</option>
                  <option value="LOW">Low (I:L - 0.22)</option>
                  <option value="NONE">None (I:N - 0.00)</option>
                </select>
              </div>

              {/* Availability */}
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Availability Impact (A)</label>
                <select
                  value={cvssMetrics.availability}
                  onChange={(e) => setCvssMetrics({ ...cvssMetrics, availability: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200"
                >
                  <option value="HIGH">High (A:H - 0.56)</option>
                  <option value="LOW">Low (A:L - 0.22)</option>
                  <option value="NONE">None (A:N - 0.00)</option>
                </select>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleCalculateCvss}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
              >
                Recalculate Base Score
              </button>
            </div>
          </div>

          {/* CVSS Output Card */}
          <div className="lg:col-span-4 p-5 rounded-xl soc-panel flex flex-col justify-between space-y-4">
            <div>
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                CVSS 3.1 Base Score Output
              </h2>
              {cvssResult && (
                <div className="text-center py-6">
                  <div className="text-6xl font-extrabold font-mono text-cyan-400">
                    {cvssResult.base_score.toFixed(1)}
                  </div>
                  <div className="mt-2">
                    <SeverityBadge severity={cvssResult.severity_rating} size="md" />
                  </div>
                </div>
              )}
            </div>

            {cvssResult && (
              <div className="space-y-3 pt-3 border-t border-soc-border text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Impact Sub-score:</span>
                  <span className="font-mono text-slate-200">{cvssResult.impact_sub_score}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Exploitability Sub-score:</span>
                  <span className="font-mono text-slate-200">{cvssResult.exploitability_sub_score}</span>
                </div>
                <div>
                  <span className="text-slate-400 block mb-1">Vector String:</span>
                  <div className="p-2 rounded bg-slate-950 font-mono text-[10px] text-cyan-300 break-all border border-soc-border">
                    {cvssResult.vector_string}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: DEPENDENCY SCANNER */}
      {activeTab === 'deps' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 p-5 rounded-xl soc-panel space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Package className="w-4 h-4 text-cyan-400" />
                Package Manifest
              </span>
              <div className="flex items-center gap-2">
                <select
                  value={manifestType}
                  onChange={(e) => setManifestType(e.target.value)}
                  className="text-xs bg-slate-900 border border-soc-border rounded-lg p-1.5 text-slate-300"
                >
                  <option value="requirements.txt">requirements.txt (Python)</option>
                  <option value="package.json">package.json (Node.js)</option>
                </select>
              </div>
            </div>

            <textarea
              value={manifestContent}
              onChange={(e) => setManifestContent(e.target.value)}
              rows={12}
              className="w-full font-mono text-xs bg-slate-950/80 border border-soc-border rounded-lg p-3 text-cyan-100/90 focus:outline-none focus:border-cyan-500/60 leading-relaxed resize-none"
              placeholder="Paste manifest content..."
            />

            <button
              onClick={handleScanDeps}
              disabled={isDepScanning}
              className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all flex items-center justify-center gap-2"
            >
              <SearchCode className="w-4 h-4" />
              {isDepScanning ? 'Checking Vulnerability Database...' : 'Audit Manifest for CVEs'}
            </button>
          </div>

          <div className="lg:col-span-6 p-5 rounded-xl soc-panel space-y-4">
            <h3 className="text-sm font-bold text-slate-200">
              Vulnerable Dependencies {depResult ? `(${depResult.vulnerable_packages_count})` : ''}
            </h3>

            {depResult ? (
              <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1">
                {depResult.findings.map((d, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg soc-card space-y-2 border-l-4 border-l-orange-500">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-100">
                          {d.package}
                        </span>
                        <SeverityBadge severity={d.severity} size="sm" />
                      </div>
                      <span className="font-mono text-xs text-rose-400">
                        {d.cve_id}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-xs text-slate-400">
                      <span>Installed: <strong className="text-slate-200">{d.installed_version}</strong></span>
                      <span>Fixed in: <strong className="text-emerald-400">{d.fixed_version}</strong></span>
                      <span>CVSS: <strong className="text-orange-400">{d.cvss_score}</strong></span>
                    </div>

                    <p className="text-xs text-slate-300">
                      {d.advisory}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-center text-slate-500">
                <Package className="w-8 h-8 mb-2 text-slate-600" />
                <p className="text-xs">No scan performed yet. Click 'Audit Manifest for CVEs'.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
