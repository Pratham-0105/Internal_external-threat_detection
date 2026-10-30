import React, { useState, useEffect } from 'react';
import {
  Shield,
  ExternalLink,
  Search,
  CheckCircle2,
  AlertTriangle,
  Info,
  Terminal,
  Filter,
  BookOpen,
  ArrowRight
} from 'lucide-react';
import apiClient from '../services/apiClient';

export const MitreMatrix = () => {
  const [matrixData, setMatrixData] = useState([]);
  const [tacticsCovered, setTacticsCovered] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedTactic, setSelectedTactic] = useState('ALL');
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  useEffect(() => {
    fetchMatrix();
  }, []);

  const fetchMatrix = async () => {
    try {
      setLoading(true);
      const res = await apiClient.get('/api/mitre/matrix');
      if (res.data && res.data.techniques) {
        setMatrixData(res.data.techniques);
        setTacticsCovered(res.data.tactics_covered || []);
      }
    } catch (err) {
      console.error('Failed to load MITRE matrix:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredTechniques = matrixData.filter((item) => {
    const matchesSearch =
      item.technique_id.toLowerCase().includes(searchFilter.toLowerCase()) ||
      item.technique_name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      item.tactic.toLowerCase().includes(searchFilter.toLowerCase()) ||
      (item.description && item.description.toLowerCase().includes(searchFilter.toLowerCase()));

    const matchesTactic = selectedTactic === 'ALL' || item.tactic.toUpperCase() === selectedTactic.toUpperCase();

    return matchesSearch && matchesTactic;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-5">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono tracking-wider uppercase mb-1">
            <Shield className="w-4 h-4 text-cyan-400" />
            Adversary TTP Framework Alignment
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
            MITRE ATT&CK Enterprise Matrix
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
              v14 Enterprise
            </span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Automated alignment of multi-class LightGBM classifiers, DPI signatures, and UEBA anomalies to official MITRE tactics.
          </p>
        </div>

        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#141c2e] hover:bg-[#1a253c] text-xs font-medium text-gray-200 border border-white/10 transition-colors shadow-sm"
        >
          <BookOpen className="w-4 h-4 text-cyan-400" />
          Official MITRE ATT&CK Repository
          <ExternalLink className="w-3.5 h-3.5 text-gray-400" />
        </a>
      </div>

      {/* Control Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 bg-[#111726] p-3.5 rounded-xl border border-white/5 shadow-inner">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search by Technique ID (e.g. T1498), tactic, or attack name..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full bg-[#0d121f] text-sm text-white pl-9 pr-4 py-2 rounded-lg border border-white/10 focus:border-cyan-500 focus:outline-none placeholder-gray-500 font-mono"
          />
        </div>

        {/* Tactic Filter Dropdown */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={selectedTactic}
            onChange={(e) => setSelectedTactic(e.target.value)}
            className="bg-[#0d121f] text-xs text-white px-3 py-2 rounded-lg border border-white/10 focus:border-cyan-500 focus:outline-none font-medium"
          >
            <option value="ALL">All Tactics ({matrixData.length} Techniques)</option>
            {tacticsCovered.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Techniques Grid */}
      {loading ? (
        <div className="p-12 text-center text-gray-400 font-mono animate-pulse">
          Loading MITRE ATT&CK Matrix from CASOC Knowledge Base...
        </div>
      ) : filteredTechniques.length === 0 ? (
        <div className="p-12 text-center text-gray-500 bg-[#111726] rounded-xl border border-white/5">
          No MITRE techniques matched your search query "{searchFilter}".
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredTechniques.map((item) => (
            <div
              key={item.technique_id}
              onClick={() => setSelectedTechnique(item)}
              className="bg-[#111726] hover:bg-[#151c2f] p-4 rounded-xl border border-white/5 hover:border-cyan-500/40 transition-all duration-200 cursor-pointer flex flex-col justify-between group shadow-lg"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    {item.technique_id}
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-white/5 text-gray-400 border border-white/5">
                    {item.tactic} ({item.tactic_id})
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-white group-hover:text-cyan-300 transition-colors">
                  {item.technique_name}
                </h3>

                <p className="text-xs text-gray-400 mt-2 line-clamp-3 leading-relaxed">
                  {item.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-xs">
                <span className="text-[11px] text-gray-400 flex items-center gap-1.5 font-mono">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  NIST: {item.nist_phase}
                </span>

                <span className="text-cyan-400 flex items-center gap-1 text-[11px] font-medium group-hover:translate-x-0.5 transition-transform">
                  View Dossier <ArrowRight className="w-3 h-3" />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-[#0f1523] border border-white/10 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl relative">
            <button
              onClick={() => setSelectedTechnique(null)}
              className="absolute top-4 right-4 text-gray-400 hover:text-white p-1 rounded-lg hover:bg-white/5"
            >
              ✕
            </button>

            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {selectedTechnique.technique_id}
              </span>
              <span className="text-xs font-mono uppercase px-2.5 py-1 rounded bg-white/5 text-gray-300 border border-white/10">
                Tactic: {selectedTechnique.tactic} ({selectedTechnique.tactic_id})
              </span>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white">{selectedTechnique.technique_name}</h2>
              <p className="text-sm text-gray-300 mt-2 leading-relaxed">
                {selectedTechnique.description}
              </p>
            </div>

            <div className="space-y-3 bg-[#141b2c] p-4 rounded-xl border border-white/5">
              <div>
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider block mb-1">
                  Automated Mitigation Guidance
                </span>
                <p className="text-xs text-gray-300 leading-relaxed font-mono">
                  {selectedTechnique.mitigation_summary}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-white/5 text-xs">
                <div>
                  <span className="text-gray-400 block">NIST SP 800-61 Phase</span>
                  <span className="text-white font-medium">{selectedTechnique.nist_phase}</span>
                </div>
                <div>
                  <span className="text-gray-400 block">ML Detection Confidence</span>
                  <span className="text-emerald-400 font-medium">{selectedTechnique.detection_confidence}</span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <a
                href={selectedTechnique.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 font-mono underline"
              >
                Inspect Official Technique on MITRE ATT&CK
                <ExternalLink className="w-3.5 h-3.5" />
              </a>

              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-xs font-semibold text-white transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
