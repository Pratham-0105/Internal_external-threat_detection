import React, { useState, useMemo } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  Activity, 
  CheckCircle2, 
  ExternalLink, 
  Laptop,
  Terminal,
  Search,
  Zap,
  Radio
} from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { Link } from 'react-router-dom';

export const UserWorkspace = () => {
  const { incidents } = useSOC();

  // Extract unique targeted victims/endpoints from real incidents
  const discoveredTargets = useMemo(() => {
    const map = new Map();
    incidents.forEach((inc) => {
      // Find victim IP or username
      const targetKey = inc.dst_ip || inc.username || inc.user_id;
      if (targetKey && !map.has(targetKey)) {
        map.set(targetKey, {
          key: targetKey,
          label: inc.username ? `${inc.username} (${inc.dst_ip || 'Endpoint'})` : targetKey,
          isUser: Boolean(inc.username || inc.user_id),
          count: 0
        });
      }
      if (targetKey && map.has(targetKey)) {
        map.get(targetKey).count += 1;
      }
    });

    const list = Array.from(map.values());
    // Ensure default primary host is available if no incidents
    if (!list.some(t => t.key === '192.168.1.50')) {
      list.unshift({
        key: '192.168.1.50',
        label: '192.168.1.50 (Primary Host)',
        isUser: false,
        count: incidents.filter(i => i.dst_ip === '192.168.1.50').length
      });
    }
    return list;
  }, [incidents]);

  const [selectedTargetKey, setSelectedTargetKey] = useState('192.168.1.50');
  const [customSearch, setCustomSearch] = useState('');

  // Keep selection synchronized if new attacks appear
  const currentTargetKey = useMemo(() => {
    if (customSearch.trim()) return customSearch.trim();
    if (discoveredTargets.some(t => t.key === selectedTargetKey)) {
      return selectedTargetKey;
    }
    return discoveredTargets[0]?.key || '192.168.1.50';
  }, [selectedTargetKey, customSearch, discoveredTargets]);

  // Correlated real incidents for the selected endpoint/user
  const targetIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchDst = (inc.dst_ip || '').toLowerCase().includes(currentTargetKey.toLowerCase());
      const matchSrc = (inc.src_ip || '').toLowerCase() === currentTargetKey.toLowerCase();
      const matchUser = (inc.username || '').toLowerCase().includes(currentTargetKey.toLowerCase()) ||
                        (inc.user_id || '').toLowerCase().includes(currentTargetKey.toLowerCase());
      return matchDst || matchSrc || matchUser;
    });
  }, [incidents, currentTargetKey]);

  const isTargeted = targetIncidents.length > 0;

  // Real calculated risk score based on actual incidents
  const targetRiskScore = useMemo(() => {
    if (!isTargeted) return 0;
    const maxConf = targetIncidents.reduce((max, inc) => {
      const conf = typeof inc.confidence === 'number' ? inc.confidence : 85;
      return Math.max(max, conf);
    }, 60);
    return Math.min(100, Math.round(maxConf));
  }, [isTargeted, targetIncidents]);

  const latestMitigation = useMemo(() => {
    if (!isTargeted) return 'None (Normal Traffic)';
    return targetIncidents[0]?.action_taken || targetIncidents[0]?.mitigation_action || 'Traffic Quarantined';
  }, [isTargeted, targetIncidents]);

  return (
    <div className="space-y-6">
      {/* User Workspace Header */}
      <div className="bg-[#0b101d] border border-purple-500/20 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-40 bg-purple-500/5 blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 shadow-lg shadow-purple-500/10">
              <Laptop className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  WORKSPACE 2: USER & ENDPOINT ENVIRONMENT
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
                  isTargeted 
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse font-bold' 
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30 font-medium'
                }`}>
                  <span className={`w-2 h-2 rounded-full ${isTargeted ? 'bg-rose-400 animate-ping' : 'bg-emerald-400'}`} />
                  {isTargeted ? 'COMPROMISE DETECTED / CONTAINED' : 'NORMAL & SECURE'}
                </span>
              </div>
              <h1 className="text-2xl font-black tracking-tight text-white mt-1">
                Endpoint Telemetry & User Posture
              </h1>
              <p className="text-xs text-gray-400">
                Live host monitoring showing real threat detections, automated containment rules, and forensic activity logs.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              to="/attacker-workspace"
              className="px-3.5 py-2 rounded-lg bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 hover:text-white text-xs font-mono font-bold border border-rose-500/40 flex items-center gap-1.5 transition-colors shadow-lg shadow-rose-950/30"
            >
              <Zap className="w-3.5 h-3.5 text-rose-400" />
              Launch Attack Against Host
            </Link>
          </div>
        </div>

        {/* Dynamic Target Selector Bar */}
        <div className="mt-5 pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-gray-400 font-mono text-[11px] uppercase">MONITORED TARGETS:</span>
            {discoveredTargets.map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => { setSelectedTargetKey(t.key); setCustomSearch(''); }}
                className={`px-3 py-1 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                  currentTargetKey === t.key && !customSearch
                    ? 'bg-purple-600 text-white font-bold shadow-md shadow-purple-900/40 border border-purple-400'
                    : 'bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10'
                }`}
              >
                <span>{t.label}</span>
                {t.count > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full bg-rose-500/30 text-rose-300 text-[10px] font-bold">
                    {t.count} attack{t.count > 1 ? 's' : ''}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Quick Target Filter / Custom IP Input */}
          <div className="flex items-center gap-2">
            <div className="relative w-48">
              <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={customSearch}
                onChange={(e) => setCustomSearch(e.target.value)}
                placeholder="Inspect any IP or User..."
                className="w-full bg-[#131c2e] border border-white/10 rounded px-2.5 pl-8 py-1 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>
        </div>

        {/* Workspace Switcher */}
        <div className="mt-3 pt-3 border-t border-white/5 flex flex-wrap items-center gap-3 text-xs">
          <span className="text-gray-400 font-mono text-[11px] uppercase">SWITCH WORKSPACE:</span>
          <Link
            to="/admin-workspace"
            className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 flex items-center gap-1 transition-colors"
          >
            <span>1. Admin Workspace (Vault)</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
          <span className="px-3 py-1 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold">
            2. User Workspace (Current)
          </span>
          <Link
            to="/attacker-workspace"
            className="px-3 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 hover:text-rose-200 border border-rose-500/20 flex items-center gap-1 transition-colors font-bold"
          >
            <span>3. Attacker Workspace (Launch Attacks)</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
      </div>

      {/* Security Status Alert Banner if Targeted */}
      {isTargeted ? (
        <div className="bg-rose-500/10 border border-rose-500/40 rounded-xl p-4 flex items-center justify-between gap-4 shadow-lg animate-pulse">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-rose-500/20 flex items-center justify-center text-rose-400 shrink-0">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="text-xs font-bold text-rose-300 uppercase tracking-wider flex items-center gap-2">
                <span>SECURITY ALERT: ACTIVE THREAT MITIGATION ENFORCED ON TARGET</span>
                <span className="px-2 py-0.5 rounded bg-rose-500/30 text-rose-200 text-[10px] font-mono">
                  {targetIncidents.length} INCIDENT(S)
                </span>
              </div>
              <div className="text-[11px] text-gray-300 mt-0.5 font-mono">
                CASOC NIDS/UEBA has detected attack traffic against <span className="text-white font-bold">{currentTargetKey}</span>. Defense Action: <span className="text-emerald-400 font-bold">{latestMitigation}</span>.
              </div>
            </div>
          </div>

          <Link
            to="/admin-workspace"
            className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs hover:bg-rose-600 transition-colors shrink-0 flex items-center gap-1 font-mono shadow-md"
          >
            View in Admin Vault &rarr;
          </Link>
        </div>
      ) : (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-bold text-emerald-300 uppercase tracking-wider">
                NORMAL OPERATIONAL POSTURE &bull; ALL SYSTEMS COMPLIANT
              </div>
              <div className="text-[11px] text-gray-400 font-mono mt-0.5">
                Target endpoint <span className="text-emerald-300 font-bold">{currentTargetKey}</span> has 0 security alerts. Telemetry is healthy.
              </div>
            </div>
          </div>

          <Link
            to="/attacker-workspace"
            className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 text-xs font-mono border border-white/10 flex items-center gap-1 shrink-0"
          >
            Simulate Attack Against Host
          </Link>
        </div>
      )}

      {/* Profile & Workstation Telemetry Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1: Identity & Endpoint Specs */}
        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-3 pb-3 border-b border-white/10">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 font-bold font-mono">
              EP
            </div>
            <div>
              <h3 className="text-sm font-bold text-white font-mono">{currentTargetKey}</h3>
              <p className="text-xs text-gray-400 font-mono">Corporate Workstation Node</p>
            </div>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex items-center justify-between text-gray-400">
              <span>Target Entity / IP:</span>
              <span className="text-amber-400 font-bold">{currentTargetKey}</span>
            </div>
            <div className="flex items-center justify-between text-gray-400">
              <span>Hostname:</span>
              <span className="text-gray-200">WS-NODE-{currentTargetKey.replace(/[^a-zA-Z0-9]/g, '-').slice(-8)}</span>
            </div>
            <div className="flex items-center justify-between text-gray-400">
              <span>Network Subnet:</span>
              <span className="text-cyan-400">192.168.1.0/24 (LAN)</span>
            </div>
            <div className="flex items-center justify-between text-gray-400">
              <span>Recorded Attacks:</span>
              <span className={`font-bold ${isTargeted ? 'text-rose-400' : 'text-emerald-400'}`}>
                {targetIncidents.length} Event{targetIncidents.length !== 1 ? 's' : ''}
              </span>
            </div>
            <div className="flex items-center justify-between text-gray-400">
              <span>Current Posture:</span>
              <span className={isTargeted ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                {isTargeted ? 'ELEVATED RISK' : 'NORMAL SECURE'}
              </span>
            </div>
          </div>

          <div className="pt-3 border-t border-white/10">
            <div className="text-[11px] text-gray-400 uppercase tracking-wider mb-1 font-mono">Targeting Instructions:</div>
            <p className="text-xs text-gray-300 leading-relaxed">
              To test real detection against this host, open the <Link to="/attacker-workspace" className="text-rose-400 font-bold underline">Attacker Workspace</Link> and fire any attack against <code className="text-amber-300 font-mono">{currentTargetKey}</code>.
            </p>
          </div>
        </div>

        {/* Card 2: Workstation Security & Defense Telemetry */}
        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/10">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Endpoint Security Posture
            </h3>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
              isTargeted
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
            }`}>
              {isTargeted ? 'ELEVATED RISK' : 'NORMAL COMPLIANT'}
            </span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-gray-400 font-mono">Threat Anomaly Risk Index:</span>
                <span className={`font-mono font-bold ${
                  isTargeted ? 'text-rose-400' : 'text-emerald-400'
                }`}>
                  {targetRiskScore} / 100 {isTargeted ? '(HIGH RISK)' : '(NORMAL)'}
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    isTargeted ? 'bg-rose-500' : 'bg-emerald-500'
                  }`} 
                  style={{ width: `${Math.max(5, targetRiskScore)}%` }}
                />
              </div>
            </div>

            <div className="space-y-2 text-xs font-mono pt-2">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">CASOC Agent Daemon:</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> RUNNING v2.4
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Active Defense:</span>
                <span className={isTargeted ? 'text-rose-400 font-bold' : 'text-cyan-400'}>
                  {isTargeted ? 'FIREWALL BLOCKED' : 'MONITORING'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Network Egress Filter:</span>
                <span className="text-cyan-400">INSPECTED VIA NIDS</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Mitigation Rule:</span>
                <span className={`truncate max-w-[170px] ${isTargeted ? 'text-amber-400 font-bold' : 'text-gray-400'}`}>
                  {latestMitigation}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Card 3: Real Detected Activities & Activity Log */}
        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/10">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-purple-400" />
              Live Security Telemetry Feed
            </h3>
            <span className="text-[10px] font-mono text-gray-400">REAL LOG</span>
          </div>

          <div className="space-y-2.5">
            {isTargeted ? (
              targetIncidents.slice(0, 3).map((inc, idx) => (
                <div
                  key={inc.id || idx}
                  className="p-2.5 rounded-lg bg-rose-500/5 border border-rose-500/20 hover:border-rose-500/40 transition-colors"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-rose-300 truncate">
                      {inc.vector || inc.type || 'Exploit Intercepted'}
                    </span>
                    <span className="text-[10px] font-mono text-gray-400 shrink-0">
                      {inc.time_display || inc.timestamp?.split('T')[1]?.slice(0, 8) || 'Recent'}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-gray-400 mt-0.5 truncate">
                    Src: <span className="text-cyan-300">{inc.src_ip}</span> &bull; Action: <span className="text-emerald-400">{inc.action_taken || inc.mitigation_action || 'Blocked'}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-gray-500 text-xs font-mono">
                <Radio className="w-6 h-6 mx-auto mb-2 text-gray-600" />
                No malicious events recorded for this endpoint.
                <div className="text-[10px] text-gray-500 mt-1">
                  Baseline network activity within normal parameters.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Incident History Targeted at this User/Host */}
      <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Activity className="w-4 h-4 text-rose-400" />
            Correlated Security Incidents for {currentTargetKey} ({targetIncidents.length} Found)
          </h3>
          <span className="text-xs font-mono text-gray-400">LIVE DATABASE AUDIT TRAIL</span>
        </div>

        {targetIncidents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/10 pb-2">
                  <th className="pb-2">Incident ID</th>
                  <th className="pb-2">Timestamp</th>
                  <th className="pb-2">Vector / Threat Type</th>
                  <th className="pb-2">Attacker IP</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">AI Confidence</th>
                  <th className="pb-2">Automated Mitigation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {targetIncidents.map(inc => (
                  <tr key={inc.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-2.5 text-cyan-400 font-bold">#{inc.id}</td>
                    <td className="py-2.5 text-gray-400">{inc.time_display || inc.timestamp}</td>
                    <td className="py-2.5 text-white font-medium">{inc.vector || inc.type}</td>
                    <td className="py-2.5 text-rose-400">{inc.src_ip || 'N/A'}</td>
                    <td className="py-2.5 text-amber-300 font-bold">{inc.severity || 'CRITICAL'}</td>
                    <td className="py-2.5 text-cyan-400 font-bold">
                      {typeof inc.confidence === 'number' ? inc.confidence.toFixed(1) : (inc.confidence || '0.0')}%
                    </td>
                    <td className="py-2.5 text-emerald-400 font-medium">
                      {inc.action_taken || inc.mitigation_action || 'IP_BLOCKED_FIREWALL'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-10 text-center text-gray-400 text-xs">
            <Shield className="w-8 h-8 text-emerald-400/50 mx-auto mb-2" />
            No threat incidents currently recorded for <code className="text-amber-300 font-mono">{currentTargetKey}</code>.
            <div className="mt-2 text-[11px] text-gray-400">
              Use the <Link to="/attacker-workspace" className="text-rose-400 font-bold underline">Attacker Workspace</Link> to fire a test attack against this host.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
