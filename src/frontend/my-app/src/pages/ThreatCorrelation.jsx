import React from 'react';
import { GitMerge, ArrowDown, ShieldAlert, Users, Radio, Zap, CheckCircle2 } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { Link } from 'react-router-dom';

export const ThreatCorrelation = () => {
  const { incidents } = useSOC();
  const latestAttack = incidents.find((i) => i.is_attack) || incidents[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="soc-panel p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <GitMerge className="w-4 h-4 text-cyan-400" />
            CASOC Multi-Vector Threat Correlation Engine
          </h2>
          <div className="text-xs text-gray-400 mt-1 font-mono">
            Synthesizes external network telemetry with internal endpoint anomalies for automated root-cause isolation
          </div>
        </div>

        <Link
          to="/attacker-workspace"
          className="px-3.5 py-2 rounded-lg bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 hover:text-white text-xs font-mono font-bold border border-rose-500/40 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
        >
          <Zap className="w-3.5 h-3.5 text-rose-400" />
          Simulate Attack Sequence
        </Link>
      </div>

      {latestAttack ? (
        /* Multi-Vector Flow Visualization */
        <div className="soc-panel p-6">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-6">
            Correlated Attack Vector Flow (Active Incident #{latestAttack.id})
          </h3>

          {/* Level 1: Inputs */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-4 rounded-lg bg-black/40 border border-cyan-500/20">
              <div className="flex items-center gap-2 text-cyan-400 font-bold mb-2">
                <Radio className="w-4 h-4" />
                1. Network Flow Telemetry
              </div>
              <div className="text-gray-300">
                Vector: <span className="text-rose-400 font-bold">{latestAttack.vector || 'Network Attack'}</span>
              </div>
              <div className="text-gray-400 text-[11px] mt-1">
                Source: <span className="text-cyan-300">{latestAttack.src_ip || '198.51.100.88'}</span> &bull; Target: <span className="text-amber-300">{latestAttack.dst_ip || '192.168.1.50'}</span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-black/40 border border-purple-500/20">
              <div className="flex items-center gap-2 text-purple-400 font-bold mb-2">
                <Users className="w-4 h-4" />
                2. Endpoint / Entity Context
              </div>
              <div className="text-gray-300">
                Entity: <span className="text-purple-300 font-bold">{latestAttack.username || latestAttack.user_id || latestAttack.dst_ip}</span>
              </div>
              <div className="text-gray-400 text-[11px] mt-1">
                Host State: <span className="text-rose-400 font-semibold">{latestAttack.is_attack ? 'Under Attack' : 'Normal'}</span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-black/40 border border-amber-500/20">
              <div className="flex items-center gap-2 text-amber-400 font-bold mb-2">
                <ShieldAlert className="w-4 h-4" />
                3. Defense Decision
              </div>
              <div className="text-gray-300">
                Action: <span className="text-emerald-400 font-bold">{latestAttack.action_taken || latestAttack.mitigation_action || 'Firewall Enforced'}</span>
              </div>
              <div className="text-gray-400 text-[11px] mt-1">
                Confidence: <span className="text-cyan-400 font-bold">{typeof latestAttack.confidence === 'number' ? latestAttack.confidence.toFixed(1) : (latestAttack.confidence || '98.0')}%</span>
              </div>
            </div>
          </div>

          {/* Down Arrows */}
          <div className="flex justify-center my-4">
            <div className="w-8 h-8 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <ArrowDown className="w-4 h-4" />
            </div>
          </div>

          {/* Level 2: Correlation Engine */}
          <div className="p-5 rounded-lg bg-gradient-to-r from-cyan-950/40 via-purple-950/40 to-blue-950/40 border border-cyan-500/30 text-center font-mono">
            <div className="text-xs font-bold uppercase tracking-wider text-cyan-300">
              CASOC Autonomous Context Correlator
            </div>
            <p className="text-xs text-gray-400 max-w-xl mx-auto mt-1">
              Correlating inbound vector <span className="text-white font-bold">{latestAttack.vector}</span> from <span className="text-cyan-300">{latestAttack.src_ip}</span> against destination target <span className="text-amber-300">{latestAttack.dst_ip}</span>.
            </p>
            <div className="mt-3 flex items-center justify-center gap-4 text-xs">
              <span className="text-gray-400">ML Confidence: <strong className="text-white">{typeof latestAttack.confidence === 'number' ? latestAttack.confidence.toFixed(1) : latestAttack.confidence}%</strong></span>
              <span className="text-gray-400">Severity: <strong className="text-rose-400">{latestAttack.severity || (latestAttack.is_attack ? 'CRITICAL' : 'LOW')}</strong></span>
            </div>
          </div>

          {/* Level 3: Automated Containment */}
          <div className="mt-6 p-4 rounded-lg bg-black/40 border border-emerald-500/30 font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="text-emerald-400 font-bold uppercase text-[11px]">Enforced Response Action</div>
              <div className="text-white mt-0.5">{latestAttack.action_taken || latestAttack.mitigation_action || 'Firewall IP Blacklist Enforced'}</div>
            </div>
            <Link
              to="/admin-workspace"
              className="px-3 py-1.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-bold self-start sm:self-auto hover:bg-emerald-500/30 transition-colors"
            >
              Verify in Admin Vault &rarr;
            </Link>
          </div>
        </div>
      ) : (
        <div className="soc-panel p-16 text-center space-y-3 font-mono">
          <CheckCircle2 className="w-12 h-12 text-emerald-400/60 mx-auto" />
          <div className="text-sm font-bold text-white">Correlation Engine Active &bull; 0 Threats Detected</div>
          <p className="text-xs text-gray-400 max-w-md mx-auto">
            No active threat incidents currently stored in the database.
            Launch an attack sequence in the Attacker Workspace to populate real multi-vector correlation.
          </p>
          <Link
            to="/attacker-workspace"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition-all shadow-lg"
          >
            <Zap className="w-3.5 h-3.5" />
            Launch Attack in Attacker Workspace
          </Link>
        </div>
      )}
    </div>
  );
};
