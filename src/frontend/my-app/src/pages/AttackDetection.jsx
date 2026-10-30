import React, { useState, useMemo } from 'react';
import { Radio, Filter, Search, ShieldAlert, Eye, Zap } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { AttackDetailModal } from '../components/modals/AttackDetailModal';
import { IncidentTriageModal } from '../components/modals/IncidentTriageModal';
import { AttackSimulatorModal } from '../components/modals/AttackSimulatorModal';

export const AttackDetection = () => {
  const { incidents, loading } = useSOC();
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [triageTarget, setTriageTarget] = useState(null);
  const [attackSimOpen, setAttackSimOpen] = useState(false);

  // Supported attack categories from backend ML model & DPI engine
  const categories = ['ALL', 'DDoS', 'PortScan', 'Web', 'DPI', 'Botnet', 'Normal'];

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      // Category filter
      if (categoryFilter !== 'ALL') {
        if (categoryFilter === 'Normal' && inc.is_attack) return false;
        if (categoryFilter !== 'Normal' && !inc.vector?.toLowerCase().includes(categoryFilter.toLowerCase())) return false;
      }

      // Status filter
      if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;

      // Search term
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        const matchesIp = inc.src_ip?.toLowerCase().includes(q) || inc.dst_ip?.toLowerCase().includes(q);
        const matchesVec = inc.vector?.toLowerCase().includes(q);
        if (!matchesIp && !matchesVec) return false;
      }

      return true;
    });
  }, [incidents, categoryFilter, statusFilter, searchTerm]);

  if (loading && incidents.length === 0) {
    return <LoadingState message="Loading detected attack events from backend..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header & Filter Bar */}
      <div className="soc-panel p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Radio className="w-4 h-4 text-cyan-400" />
              External Attack Detection Engine
            </h2>
            <div className="text-xs text-gray-400 mt-1 font-mono">
              Real-time classification based on LightGBM inference, Deep Packet Inspection (DPI), and Zero-Day Anomaly Scorer
            </div>
          </div>

          {/* Controls: Simulate & Search */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setAttackSimOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 hover:text-white border border-rose-500/40 font-mono text-xs font-bold flex items-center gap-1.5 transition-all shadow-md active:scale-95 whitespace-nowrap"
            >
              <Zap className="w-3.5 h-3.5 text-rose-400" />
              Simulate Attack
            </button>

            {/* Quick Search */}
            <div className="relative w-72">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by IP or attack vector..."
                className="w-full bg-[#131c2e] border border-white/5 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 font-mono focus:outline-none focus:border-cyan-500/50"
              />
            </div>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/5 text-xs font-mono">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-gray-400 text-[10px] uppercase font-bold mr-1 flex items-center gap-1">
              <Filter className="w-3 h-3" /> Vector:
            </span>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                  categoryFilter === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-gray-400 hover:text-gray-200 bg-white/[0.02]'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-gray-400 text-[10px] uppercase font-bold">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#131c2e] border border-white/10 rounded px-2.5 py-1 text-xs text-gray-200 font-mono focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">NEW</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </div>
        </div>
      </div>

      {/* Attacks Table */}
      <div className="soc-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            Classified Attack Records
          </h3>
          <span className="text-[11px] font-mono text-gray-400">
            Showing {filtered.length} of {incidents.length} events
          </span>
        </div>

        {filtered.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                  <th className="pb-2">Timestamp</th>
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Destination IP</th>
                  <th className="pb-2">Attack Vector</th>
                  <th className="pb-2">Confidence</th>
                  <th className="pb-2">Latency</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                  >
                    <td className="py-3 text-gray-400">{inc.time_display || inc.timestamp}</td>
                    <td className="py-3 text-gray-200 font-semibold">{inc.src_ip}</td>
                    <td className="py-3 text-gray-400">{inc.dst_ip}</td>
                    <td className="py-3 font-medium">
                      <div className="flex flex-col gap-0.5">
                        <span className={inc.is_attack ? 'text-rose-400 font-semibold' : 'text-emerald-400'}>
                          {inc.vector}
                        </span>
                        {inc.is_attack && (
                          <span className="text-[9px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/20 px-1 py-0.5 rounded w-fit">
                            MITRE {inc.vector?.includes('DDoS') ? 'T1498.001' : inc.vector?.includes('PortScan') ? 'T1046' : inc.vector?.includes('Web') || inc.vector?.includes('SQL') ? 'T1190' : inc.vector?.includes('Bot') ? 'T1071' : inc.vector?.includes('Brute') ? 'T1110' : 'T1203'}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 text-cyan-400">{inc.confidence}%</td>
                    <td className="py-3 text-gray-400">{inc.latency}ms</td>
                    <td className="py-3">
                      <StatusPill status={inc.status} />
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIncident(inc);
                        }}
                        className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Forensics
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No matching attacks found"
            description="No incidents matched your selected vector or status filter criteria."
          />
        )}
      </div>

      {/* Forensic Drawer / Modal */}
      {selectedIncident && (
        <AttackDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onTriageClick={(inc) => setTriageTarget(inc)}
        />
      )}

      {/* Triage Update Modal */}
      {triageTarget && (
        <IncidentTriageModal
          incident={triageTarget}
          onClose={() => setTriageTarget(null)}
        />
      )}

      {/* Red-Team Live Attack Simulator Modal */}
      <AttackSimulatorModal
        isOpen={attackSimOpen}
        onClose={() => setAttackSimOpen(false)}
      />
    </div>
  );
};
