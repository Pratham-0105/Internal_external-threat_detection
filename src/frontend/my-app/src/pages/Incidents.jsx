import React, { useState, useMemo } from 'react';
import { AlertOctagon, Search, Edit3, Eye, ShieldAlert } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { EmptyState } from '../components/common/EmptyState';
import { AttackDetailModal } from '../components/modals/AttackDetailModal';
import { IncidentTriageModal } from '../components/modals/IncidentTriageModal';

export const Incidents = () => {
  const { incidents } = useSOC();
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [triageTarget, setTriageTarget] = useState(null);

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchId = String(inc.id).includes(q);
        const matchIp = inc.src_ip?.toLowerCase().includes(q) || inc.dst_ip?.toLowerCase().includes(q);
        const matchVec = inc.vector?.toLowerCase().includes(q);
        if (!matchId && !matchIp && !matchVec) return false;
      }
      return true;
    });
  }, [incidents, statusFilter, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Header & Filter Toolbar */}
      <div className="soc-panel p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-cyan-400" />
              Incident Management & Triage Center
            </h2>
            <div className="text-xs text-gray-400 mt-1 font-mono">
              Persisted SQLite audit trail with live analyst triage status and forensic resolution logs
            </div>
          </div>

          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by ID, IP, or attack type..."
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyan-500/50"
            />
          </div>
        </div>

        {/* Status Filter Tabs per Section 21 */}
        <div className="flex items-center gap-2 border-t border-white/5 pt-3 font-mono text-xs">
          <span className="text-gray-400 text-[10px] uppercase font-bold mr-1">Status:</span>
          {['ALL', 'NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1 rounded text-[11px] font-medium transition-colors ${
                statusFilter === st
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-gray-400 hover:text-gray-200 bg-white/[0.02]'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table per Section 21 */}
      <div className="soc-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            Recorded Security Incidents ({filtered.length} Items)
          </h3>
        </div>

        {filtered.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                  <th className="pb-2">Incident ID</th>
                  <th className="pb-2">Timestamp</th>
                  <th className="pb-2">Type / Vector</th>
                  <th className="pb-2">Source</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Confidence</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Assigned To</th>
                  <th className="pb-2 text-right">Triage Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className="hover:bg-white/[0.02] cursor-pointer"
                  >
                    <td className="py-3 text-cyan-400 font-bold">#{inc.id}</td>
                    <td className="py-3 text-gray-400">{inc.time_display || inc.timestamp}</td>
                    <td className="py-3 font-semibold text-gray-200">{inc.vector}</td>
                    <td className="py-3 text-gray-300">{inc.src_ip}</td>
                    <td className="py-3">
                      <StatusPill severity={inc.is_attack ? 'CRITICAL' : 'LOW'} />
                    </td>
                    <td className="py-3 text-cyan-400">{inc.confidence}%</td>
                    <td className="py-3">
                      <StatusPill status={inc.status} />
                    </td>
                    <td className="py-3 text-gray-400">SOC Analyst</td>
                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setTriageTarget(inc)}
                          className="px-2 py-1 text-[11px] text-cyan-400 hover:text-cyan-300 bg-cyan-950/30 border border-cyan-800/40 rounded flex items-center gap-1"
                        >
                          <Edit3 className="w-3 h-3" />
                          Triage
                        </button>
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="px-2 py-1 text-[11px] text-gray-300 hover:text-white bg-white/5 border border-white/10 rounded flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" />
                          View
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No incidents match filter"
            description="All incidents under this criteria have been triaged or none exist."
          />
        )}
      </div>

      {selectedIncident && (
        <AttackDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onTriageClick={(inc) => setTriageTarget(inc)}
        />
      )}

      {triageTarget && (
        <IncidentTriageModal
          incident={triageTarget}
          onClose={() => setTriageTarget(null)}
        />
      )}
    </div>
  );
};
