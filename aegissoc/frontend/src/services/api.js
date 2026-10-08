const API_BASE = '/api/v1';

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  const response = await fetch(url, {
    ...options,
    headers
  });

  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || errorDetail;
    } catch (e) {
      // ignore
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export const api = {
  // System
  getHealth: () => request('/health'),
  
  // 1. Vulnerability Assessment
  scanCode: (code, language = 'python', targetName = 'Snippet') =>
    request('/vuln/scan-code', {
      method: 'POST',
      body: JSON.stringify({ code, language, target_name: targetName })
    }),
  scanDependencies: (manifestType, manifestContent) =>
    request('/vuln/scan-dependencies', {
      method: 'POST',
      body: JSON.stringify({ manifest_type: manifestType, manifest_content: manifestContent })
    }),
  calculateCVSS: (metrics) =>
    request('/vuln/cvss-calculate', {
      method: 'POST',
      body: JSON.stringify(metrics)
    }),
  getVulnRules: () => request('/vuln/rules'),
  getVulnHistory: () => request('/vuln/history'),

  // 2. Architecture Review
  reviewArchitecture: (configType, content, name) =>
    request('/architecture/review', {
      method: 'POST',
      body: JSON.stringify({ config_type: configType, content, name })
    }),
  getComplianceFrameworks: () => request('/architecture/compliance-frameworks'),
  getArchitectureHistory: () => request('/architecture/history'),

  // 3. Forensics & IR
  parseLogs: (logType, logContent) =>
    request('/forensics/parse-logs', {
      method: 'POST',
      body: JSON.stringify({ log_type: logType, log_content: logContent })
    }),
  getSampleLogs: () => request('/forensics/sample-logs'),
  getForensicsReports: () => request('/forensics/reports'),

  // 4. Threat Modeling
  getThreatModels: () => request('/threat-model/models'),
  getThreatModel: (id) => request(`/threat-model/models/${id}`),
  createThreatModel: (model) =>
    request('/threat-model/models', {
      method: 'POST',
      body: JSON.stringify(model)
    }),
  addThreat: (modelId, threat) =>
    request(`/threat-model/models/${modelId}/threats`, {
      method: 'POST',
      body: JSON.stringify(threat)
    }),
  mitigateThreat: (threatId, mitigation) =>
    request(`/threat-model/threats/${threatId}/mitigate`, {
      method: 'PUT',
      body: JSON.stringify(mitigation)
    }),
  getThreatHeatmap: (modelId) => request(`/threat-model/matrix/${modelId}`),
  getStrideTemplates: () => request('/threat-model/templates'),

  // 5. Automated DAST
  runDast: (options) =>
    request('/security-tests/run-dast', {
      method: 'POST',
      body: JSON.stringify(options)
    }),
  getDastHistory: () => request('/security-tests/history'),
  getDastJunitUrl: (id) => `${API_BASE}/security-tests/export/junit/${id}`,
  getDastSarifUrl: (id) => `${API_BASE}/security-tests/export/sarif/${id}`,

  // 6. Malware Triage
  analyzeArtifact: (filename, rawB64 = null, textContent = null) =>
    request('/malware/analyze-file', {
      method: 'POST',
      body: JSON.stringify({ filename, raw_content_b64: rawB64, text_content: textContent })
    }),
  calculateEntropy: (filename, textContent) =>
    request('/malware/calc-entropy', {
      method: 'POST',
      body: JSON.stringify({ filename, text_content: textContent })
    }),
  getSampleArtifacts: () => request('/malware/sample-artifacts'),
  getMalwareReports: () => request('/malware/reports')
};
