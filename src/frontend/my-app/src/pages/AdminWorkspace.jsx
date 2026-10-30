import React, { useState, useMemo } from 'react';
import { 
  ShieldCheck, 
  Search, 
  Eye, 
  Database, 
  Server, 
  Download, 
  RefreshCw,
  ExternalLink,
  Lock,
  Zap,
  Trash2
} from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { AttackDetailModal } from '../components/modals/AttackDetailModal';
import { IncidentTriageModal } from '../components/modals/IncidentTriageModal';
import { Link } from 'react-router-dom';

export const AdminWorkspace = () => {
  const { incidents, metrics, systemStatus, refreshAll, clearAllIncidents, wsConnected } = useSOC();
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL'); // 'ALL' | 'EXTERNAL' | 'INSIDER'
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [triageTarget, setTriageTarget] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isClearing, setIsClearing] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await refreshAll();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const handleClearDatabase = async () => {
    if (!confirmClear) {
      setConfirmClear(true);
      setTimeout(() => setConfirmClear(false), 4000);
      return;
    }
    setIsClearing(true);
    await clearAllIncidents();
    setConfirmClear(false);
    setIsClearing(false);
  };

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const isInsider = (inc.category && inc.category.toLowerCase().includes('insider')) ||
                        (inc.vector && inc.vector.toLowerCase().includes('insider')) ||
                        (inc.type && inc.type.toLowerCase().includes('insider')) ||
                        (inc.dst_ip && (inc.dst_ip.includes('USR-') || inc.dst_ip.includes('dev.engineer') || inc.dst_ip.includes('internal.analyst'))) ||
                        Boolean(inc.user_id);

      // Category filter
      if (categoryFilter === 'EXTERNAL' && isInsider) return false;
      if (categoryFilter === 'INSIDER' && !isInsider) return false;

      // Severity filter
      if (severityFilter !== 'ALL') {
        const sev = (inc.severity || (inc.is_attack ? 'CRITICAL' : 'LOW')).toUpperCase();
        if (sev !== severityFilter.toUpperCase()) return false;
      }

      // Search Query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchId = String(inc.id || '').toLowerCase().includes(q);
        const matchIp = (inc.src_ip || '').toLowerCase().includes(q) || (inc.dst_ip || '').toLowerCase().includes(q);
        const matchVec = (inc.vector || inc.type || inc.category || '').toLowerCase().includes(q);
        const matchUser = (inc.user_id || inc.username || '').toLowerCase().includes(q);
        if (!matchId && !matchIp && !matchVec && !matchUser) return false;
      }

      return true;
    });
  }, [incidents, categoryFilter, severityFilter, searchQuery]);

  const exportAuditLog = () => {
    const blob = new Blob([JSON.stringify(filteredIncidents, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `casoc-admin-audit-log-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Admin Workspace Header */}
      <div className="bg-[#0b101d] border border-cyan-500/20 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-40 bg-cyan-500/5 blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  WORKSPACE 1: SOC ADMINISTRATOR
                </span>
                <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                  <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                  {wsConnected ? 'LIVE SOCKET STREAM' : 'HTTP POLLING'}
                </span>
              </div>
              <h1 className="text-2xl font-black tracking-tight text-white mt-1">
                Admin Central Operations & Audit Vault
              </h1>
              <p className="text-xs text-gray-400">
                Master command center with full authority over all SQLite records, active firewall defenses, user investigations, and forensic evidence logs.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleClearDatabase}
              disabled={isClearing}
              className={`px-3 py-2 rounded-lg text-xs font-mono border flex items-center gap-1.5 transition-colors ${
                confirmClear
                  ? 'bg-rose-600 text-white border-rose-500 font-bold animate-pulse'
                  : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 hover:text-rose-200 border-rose-500/30'
              }`}
              title="Wipes all persisted incidents from SQLite database to start demo fresh"
            >
              <Trash2 className="w-3.5 h-3.5" />
              {confirmClear ? 'Click to Confirm Reset' : 'Clear / Reset DB'}
            </button>
            <button
              onClick={exportAuditLog}
              className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white text-xs font-mono border border-white/10 flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export Audit Trail
            </button>
            <button
              onClick={handleManualRefresh}
              disabled={isRefreshing}
              className="px-3.5 py-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 hover:text-cyan-200 text-xs font-bold border border-cyan-500/30 flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
              Sync DB Records
            </button>
          </div>
        </div>

        {/* Workspace Switcher Quick Navigation */}
        <div className="mt-5 pt-4 border-t border-white/10 flex flex-wrap items-center gap-3 text-xs">
          <span className="text-gray-400 font-mono text-[11px] uppercase">SWITCH WORKSPACE:</span>
          <span className="px-3 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
            1. Admin Workspace (Current)
          </span>
          <Link
            to="/user-workspace"
            className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 flex items-center gap-1 transition-colors"
          >
            <span>2. User / Employee Workspace</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
          <Link
            to="/attacker-workspace"
            className="px-3 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 hover:text-rose-200 border border-rose-500/20 flex items-center gap-1 transition-colors font-bold"
          >
            <span>3. Attacker Workspace (Red-Team Lab)</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
      </div>

      {/* Admin KPI Telemetry Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4">
          <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">Total Audit Records</div>
          <div className="text-2xl font-mono font-bold text-white mt-1">{incidents.length}</div>
          <div className="text-[10px] text-cyan-400 mt-0.5">Persisted in SQLite database</div>
        </div>

        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4">
          <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">Active Unresolved Threats</div>
          <div className="text-2xl font-mono font-bold text-rose-400 mt-1">{metrics?.activeThreats ?? 0}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Requiring analyst action</div>
        </div>

        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4">
          <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">Defense Neutralization Rate</div>
          <div className="text-2xl font-mono font-bold text-emerald-400 mt-1">{metrics?.threatsNeutralized ?? 100}%</div>
          <div className="text-[10px] text-emerald-400/80 mt-0.5">Automated firewall mitigations</div>
        </div>

        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4">
          <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">System Engines Online</div>
          <div className="text-sm font-bold text-cyan-400 mt-1 flex items-center gap-2">
            <Server className="w-4 h-4" />
            <span>NIDS :5000 & UEBA :5001</span>
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">{systemStatus.aiEngine.text}</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search across all records by IP address, Attack Vector, Incident ID, or Employee ID..."
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-mono uppercase text-gray-400">DOMAIN:</span>
            {['ALL', 'EXTERNAL', 'INSIDER'].map((cat) => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                  categoryFilter === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                    : 'bg-white/5 text-gray-400 hover:text-white border border-white/5'
                }`}
              >
                {cat}
              </button>
            ))}

            <span className="text-[10px] font-mono uppercase text-gray-400 ml-2">SEVERITY:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                  severityFilter === sev
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold'
                    : 'bg-white/5 text-gray-400 hover:text-white border border-white/5'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Complete Records Table */}
      <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              {categoryFilter === 'INSIDER'
                ? `Insider Threat Audit Records (${filteredIncidents.length} Records)`
                : categoryFilter === 'EXTERNAL'
                ? `External Threat Audit Records (${filteredIncidents.length} Records)`
                : `All Master Security Records (${filteredIncidents.length} Records)`}
            </h2>
          </div>
          <span className="text-xs font-mono text-gray-400">
            SHOWING REAL DATABASE AUDIT TRAIL
          </span>
        </div>

        {filteredIncidents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/10 pb-2">
                  <th className="pb-2.5">Record ID</th>
                  <th className="pb-2.5">Timestamp</th>
                  <th className="pb-2.5">Attack Vector</th>
                  <th className="pb-2.5">Source IP / Host</th>
                  <th className="pb-2.5">Target IP / User</th>
                  <th className="pb-2.5">Severity</th>
                  <th className="pb-2.5">AI Confidence</th>
                  <th className="pb-2.5">Active Defense Action</th>
                  <th className="pb-2.5 text-right">Forensic Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredIncidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                  >
                    <td className="py-3 text-cyan-400 font-bold">#{inc.id}</td>
                    <td className="py-3 text-gray-400">{inc.time_display || inc.timestamp}</td>
                    <td className="py-3 font-semibold text-white">
                      {inc.vector || inc.type || 'Security Event'}
                    </td>
                    <td className="py-3 text-cyan-300">
                      {inc.src_ip || 'N/A'}
                    </td>
                    <td className="py-3 text-gray-300">
                      {inc.dst_ip || inc.username || inc.user_id || 'N/A'}
                    </td>
                    <td className="py-3">
                      <StatusPill severity={inc.severity || (inc.is_attack ? 'CRITICAL' : 'LOW')} />
                    </td>
                    <td className="py-3 font-bold text-cyan-400">
                      {typeof inc.confidence === 'number' ? inc.confidence.toFixed(1) : (inc.confidence || '0.0')}%
                    </td>
                    <td className="py-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 w-fit">
                        <ShieldCheck className="w-3 h-3" />
                        {inc.action_taken || inc.mitigation_action || 'Traffic Logged'}
                      </span>
                    </td>
                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setTriageTarget(inc)}
                          className="px-2 py-1 text-[11px] text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 border border-cyan-800/40 rounded flex items-center gap-1"
                        >
                          <Zap className="w-3 h-3" />
                          Triage
                        </button>
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="px-2 py-1 text-[11px] text-gray-300 hover:text-white bg-white/5 border border-white/10 rounded flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" />
                          Inspect
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 mx-auto flex items-center justify-center text-cyan-400">
              <Database className="w-6 h-6" />
            </div>
            <div className="text-sm font-bold text-white">
              {categoryFilter !== 'ALL' 
                ? `No ${categoryFilter.toLowerCase()} threat records match current filters`
                : 'No security records found'}
            </div>
            <p className="text-xs text-gray-400 max-w-md mx-auto">
              {categoryFilter !== 'ALL' || searchQuery || severityFilter !== 'ALL'
                ? 'Try adjusting your search query, domain filter, or severity filter to view other security events.'
                : 'All incoming threats and anomalous activities detected by NIDS and UEBA are logged here in real time.'}
            </p>
            {(categoryFilter !== 'ALL' || searchQuery || severityFilter !== 'ALL') && (
              <button
                onClick={() => {
                  setCategoryFilter('ALL');
                  setSeverityFilter('ALL');
                  setSearchQuery('');
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-mono transition-colors border border-white/10"
              >
                <RefreshCw className="w-3 h-3" />
                Reset All Filters
              </button>
            )}
          </div>
        )}
      </div>

      {/* Incident Modal Inspector */}
      {selectedIncident && (
        <AttackDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onTriageClick={(inc) => setTriageTarget(inc)}
        />
      )}

      {/* Triage Modal */}
      {triageTarget && (
        <IncidentTriageModal
          incident={triageTarget}
          onClose={() => setTriageTarget(null)}
        />
      )}
    </div>
  );
};
