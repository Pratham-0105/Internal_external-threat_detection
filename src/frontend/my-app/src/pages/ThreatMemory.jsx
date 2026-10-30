import React, { useState, useMemo } from 'react';
import { Database, Search, Cpu, Eye } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { EmptyState } from '../components/common/EmptyState';
import { AttackDetailModal } from '../components/modals/AttackDetailModal';

export const ThreatMemory = () => {
  const { incidents } = useSOC();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);

  // Search by IP, User, Incident, Attack type, Threat ID
  const filtered = useMemo(() => {
    if (!searchQuery) return incidents;
    const q = searchQuery.toLowerCase().trim();

    return incidents.filter((inc) => {
      const matchId = String(inc.id).includes(q);
      const matchIp = inc.src_ip?.toLowerCase().includes(q) || inc.dst_ip?.toLowerCase().includes(q);
      const matchVector = inc.vector?.toLowerCase().includes(q);
      const matchStatus = inc.status?.toLowerCase().includes(q);
      return matchId || matchIp || matchVector || matchStatus;
    });
  }, [incidents, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Header & Search */}
      <div className="soc-panel p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              Threat Memory & Historical Signature Index
            </h2>
            <div className="text-xs text-gray-400 mt-1 font-mono">
              Indexed threat memories retained in SQLite with real-time payload signature & IOC matching
            </div>
          </div>

          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by IP, Incident ID, vector..."
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyan-500/50"
            />
          </div>
        </div>
      </div>

      {/* Threat Memory Table */}
      <div className="soc-panel p-5">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-purple-400" />
            Retained Threat Memories ({filtered.length} Indexed)
          </span>
        </h3>

        {filtered.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                  <th className="pb-2">Threat ID</th>
                  <th className="pb-2">Timestamp</th>
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Destination IP</th>
                  <th className="pb-2">Attack Vector</th>
                  <th className="pb-2">Confidence</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className="hover:bg-white/[0.02] cursor-pointer"
                  >
                    <td className="py-3 text-cyan-400 font-bold">#THREAT-{inc.id}</td>
                    <td className="py-3 text-gray-400">{inc.time_display || inc.timestamp}</td>
                    <td className="py-3 text-gray-200">{inc.src_ip}</td>
                    <td className="py-3 text-gray-400">{inc.dst_ip}</td>
                    <td className="py-3 font-semibold text-rose-400">{inc.vector}</td>
                    <td className="py-3 text-cyan-400">{inc.confidence}%</td>
                    <td className="py-3">
                      <StatusPill status={inc.status} size="xs" />
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIncident(inc);
                        }}
                        className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No threat memories found"
            description="No stored incident signatures matched your search criteria."
          />
        )}
      </div>

      {selectedIncident && (
        <AttackDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
        />
      )}
    </div>
  );
};
