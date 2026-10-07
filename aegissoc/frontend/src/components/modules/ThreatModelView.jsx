import React, { useState, useEffect } from 'react';
import { 
  Grid3X3, 
  Plus, 
  ShieldCheck, 
  AlertTriangle, 
  Layers, 
  CheckCircle, 
  HelpCircle,
  Filter
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import { api } from '../../services/api';

const STRIDE_ICONS = {
  Spoofing: 'S',
  Tampering: 'T',
  Repudiation: 'R',
  'Information Disclosure': 'I',
  'Denial of Service': 'D',
  'Elevation of Privilege': 'E'
};

export default function ThreatModelView() {
  const [models, setModels] = useState([]);
  const [selectedModelId, setSelectedModelId] = useState(null);
  const [modelData, setModelData] = useState(null);
  const [heatmapData, setHeatmapData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  // New Threat Modal Form
  const [showAddModal, setShowAddModal] = useState(false);
  const [newThreat, setNewThreat] = useState({
    stride_category: 'Spoofing',
    title: '',
    description: '',
    likelihood: 3,
    impact: 3,
    mitigation_controls: ''
  });

  const loadModels = async () => {
    try {
      const list = await api.getThreatModels();
      setModels(list);
      if (list.length > 0 && !selectedModelId) {
        setSelectedModelId(list[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadModelDetails = async (id) => {
    if (!id) return;
    setIsLoading(true);
    try {
      const model = await api.getThreatModel(id);
      const matrix = await api.getThreatHeatmap(id);
      setModelData(model);
      setHeatmapData(matrix);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadModels();
  }, []);

  useEffect(() => {
    if (selectedModelId) {
      loadModelDetails(selectedModelId);
    }
  }, [selectedModelId]);

  const handleMitigateThreat = async (threatId, status) => {
    try {
      await api.mitigateThreat(threatId, {
        mitigation_status: status,
        mitigation_controls: status === 'Mitigated' ? 'Hardened defensive controls verified in production.' : undefined
      });
      loadModelDetails(selectedModelId);
    } catch (err) {
      alert(`Mitigation update failed: ${err.message}`);
    }
  };

  const handleCreateThreat = async (e) => {
    e.preventDefault();
    try {
      await api.addThreat(selectedModelId, newThreat);
      setShowAddModal(false);
      setNewThreat({
        stride_category: 'Spoofing',
        title: '',
        description: '',
        likelihood: 3,
        impact: 3,
        mitigation_controls: ''
      });
      loadModelDetails(selectedModelId);
    } catch (err) {
      alert(`Error adding threat: ${err.message}`);
    }
  };

  const filteredThreats = modelData?.threats?.filter((t) => {
    if (selectedCategory === 'ALL') return true;
    return t.stride_category === selectedCategory;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl soc-panel border-cyan-500/20">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Grid3X3 className="w-5 h-5 text-cyan-400" />
            STRIDE Threat Modeling & Qualitative Risk Matrix
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            System architectural risk assessment, 5x5 Likelihood × Impact Heatmap, and defensive mitigation lifecycle.
          </p>
        </div>

        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all flex items-center gap-1.5 shadow-lg shadow-cyan-500/20"
        >
          <Plus className="w-4 h-4" />
          Add Threat Vector
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Interactive 5x5 Heat Map */}
        <div className="lg:col-span-6 p-5 rounded-xl soc-panel space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200">
              5x5 Qualitative Risk Heatmap
            </h2>
            <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
              <span>Open: <strong className="text-rose-400">{heatmapData?.open_threats || 0}</strong></span>
              <span>Mitigated: <strong className="text-emerald-400">{heatmapData?.mitigated_threats || 0}</strong></span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex text-[10px] text-slate-400 font-semibold px-8 justify-between">
              <span>Impact 1 (Negligible)</span>
              <span>Impact 3 (Moderate)</span>
              <span>Impact 5 (Catastrophic)</span>
            </div>

            {/* 5x5 Matrix Grid */}
            <div className="grid grid-cols-5 gap-1.5 bg-slate-950 p-3 rounded-lg border border-soc-border">
              {[5, 4, 3, 2, 1].map((l) => (
                <React.Fragment key={`row-${l}`}>
                  {[1, 2, 3, 4, 5].map((i) => {
                    const cell = heatmapData?.matrix?.find(
                      (c) => c.likelihood === l && c.impact === i
                    );
                    const count = cell ? cell.threat_count : 0;
                    const score = l * i;

                    let bg = 'bg-slate-900/60 text-slate-600';
                    if (count > 0) {
                      if (score >= 15) bg = 'bg-rose-500/30 text-rose-200 border-rose-500/60';
                      else if (score >= 10) bg = 'bg-orange-500/30 text-orange-200 border-orange-500/60';
                      else if (score >= 5) bg = 'bg-amber-500/30 text-amber-200 border-amber-500/60';
                      else bg = 'bg-blue-500/30 text-blue-200 border-blue-500/60';
                    }

                    return (
                      <div
                        key={`cell-${l}-${i}`}
                        className={`h-14 rounded-md border flex flex-col items-center justify-center p-1 transition-all ${bg} ${
                          count > 0 ? 'shadow-sm font-bold' : 'border-slate-800/40 text-slate-600'
                        }`}
                        title={`Likelihood ${l} x Impact ${i} (Risk Score: ${score}) - ${count} threats`}
                      >
                        <span className="text-[10px] opacity-75 font-mono">
                          L{l}·I{i}
                        </span>
                        <span className="text-sm font-mono mt-0.5">
                          {count > 0 ? count : '·'}
                        </span>
                      </div>
                    );
                  })}
                </React.Fragment>
              ))}
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-400 px-2 pt-2">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded bg-rose-500/60"></span> Critical (15-25)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded bg-orange-500/60"></span> High (10-14)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded bg-amber-500/60"></span> Medium (5-9)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded bg-blue-500/60"></span> Low (1-4)
              </span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-soc-border text-xs text-slate-400 space-y-1">
            <strong className="text-slate-200 block">STRIDE Threat Spectrum:</strong>
            <p className="text-[11px]">
              Every threat vector maps directly to architectural boundaries. Addressing open vectors shifts risk scores downward into residual zones.
            </p>
          </div>
        </div>

        {/* Right Column: STRIDE Filter & Threats List */}
        <div className="lg:col-span-6 space-y-4">
          <div className="p-4 rounded-xl soc-panel space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-200">
                Threat Vectors ({filteredThreats.length})
              </h3>
              
              {/* Category Filter */}
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="text-xs bg-slate-900 border border-soc-border rounded-lg p-1.5 text-slate-300"
              >
                <option value="ALL">All STRIDE Categories</option>
                <option value="Spoofing">Spoofing</option>
                <option value="Tampering">Tampering</option>
                <option value="Repudiation">Repudiation</option>
                <option value="Information Disclosure">Information Disclosure</option>
                <option value="Denial of Service">Denial of Service</option>
                <option value="Elevation of Privilege">Elevation of Privilege</option>
              </select>
            </div>

            <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
              {filteredThreats.map((t) => (
                <div key={t.id} className="p-4 rounded-xl soc-card space-y-2 border-l-4 border-l-cyan-500">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-bold text-[10px] flex items-center justify-center font-mono">
                          {STRIDE_ICONS[t.stride_category] || 'T'}
                        </span>
                        <h4 className="text-xs font-bold text-slate-100">
                          {t.title}
                        </h4>
                      </div>
                      <span className="text-[10px] text-cyan-400 font-mono mt-0.5 block">
                        {t.stride_category} · Risk Score: {t.risk_score} (L:{t.likelihood} × I:{t.impact})
                      </span>
                    </div>
                    <SeverityBadge severity={t.risk_level} size="sm" />
                  </div>

                  <p className="text-xs text-slate-300">
                    {t.description}
                  </p>

                  {t.mitigation_controls && (
                    <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-emerald-300/90">
                      <strong className="text-emerald-400">Mitigation Control:</strong> {t.mitigation_controls}
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs">
                    <span className="text-slate-400">
                      Status: <strong className={t.mitigation_status === 'Mitigated' ? 'text-emerald-400' : 'text-amber-400'}>{t.mitigation_status}</strong>
                    </span>

                    <div className="flex gap-1.5">
                      {t.mitigation_status !== 'Mitigated' && (
                        <button
                          onClick={() => handleMitigateThreat(t.id, 'Mitigated')}
                          className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 text-[11px] font-semibold border border-emerald-500/30"
                        >
                          Mark Mitigated
                        </button>
                      )}
                      {t.mitigation_status === 'Open' && (
                        <button
                          onClick={() => handleMitigateThreat(t.id, 'In Progress')}
                          className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-[11px] font-semibold border border-amber-500/30"
                        >
                          In Progress
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Add Threat Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-panel border border-soc-border p-6 rounded-xl max-w-lg w-full space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Plus className="w-4 h-4 text-cyan-400" />
              Add STRIDE Threat Vector
            </h3>

            <form onSubmit={handleCreateThreat} className="space-y-3">
              <div>
                <label className="text-xs text-slate-400">STRIDE Category</label>
                <select
                  value={newThreat.stride_category}
                  onChange={(e) => setNewThreat({ ...newThreat, stride_category: e.target.value })}
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200 mt-1"
                >
                  <option value="Spoofing">Spoofing (Identity Impersonation)</option>
                  <option value="Tampering">Tampering (Data Alteration)</option>
                  <option value="Repudiation">Repudiation (Disavowing Actions)</option>
                  <option value="Information Disclosure">Information Disclosure (Data Leakage)</option>
                  <option value="Denial of Service">Denial of Service (Availability Loss)</option>
                  <option value="Elevation of Privilege">Elevation of Privilege (Authorization Bypass)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400">Threat Title</label>
                <input
                  type="text"
                  required
                  value={newThreat.title}
                  onChange={(e) => setNewThreat({ ...newThreat, title: e.target.value })}
                  placeholder="e.g. Unauthenticated API Key Enumeration"
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200 mt-1"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400">Description</label>
                <textarea
                  required
                  rows={3}
                  value={newThreat.description}
                  onChange={(e) => setNewThreat({ ...newThreat, description: e.target.value })}
                  placeholder="Describe attack vector and consequence..."
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200 mt-1"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-400">Likelihood (1-5)</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={newThreat.likelihood}
                    onChange={(e) => setNewThreat({ ...newThreat, likelihood: parseInt(e.target.value) || 1 })}
                    className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200 mt-1"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Impact (1-5)</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={newThreat.impact}
                    onChange={(e) => setNewThreat({ ...newThreat, impact: parseInt(e.target.value) || 1 })}
                    className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200 mt-1"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-400">Mitigation Control Description</label>
                <input
                  type="text"
                  value={newThreat.mitigation_controls}
                  onChange={(e) => setNewThreat({ ...newThreat, mitigation_controls: e.target.value })}
                  placeholder="e.g. Implement strict HMAC verification with nonce"
                  className="w-full text-xs bg-slate-900 border border-soc-border rounded-lg p-2 text-slate-200 mt-1"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  Save Threat
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
