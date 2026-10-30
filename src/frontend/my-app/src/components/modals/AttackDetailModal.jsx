import React from 'react';
import { X, ShieldAlert, Cpu, Server } from 'lucide-react';
import { StatusPill } from '../common/StatusPill';

export const AttackDetailModal = ({ incident, onClose, onTriageClick }) => {
  if (!incident) return null;

  const raw = incident.rawEvent || {};
  const xaiAttributions = raw.xai || [];
  const dpiFindings = raw.dpi?.findings || [];
  const zeroDayScore = raw.zero_day?.anomaly_score;
  const threatMemory = raw.threat_memory;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="soc-panel w-full max-w-3xl max-h-[90vh] overflow-y-auto border border-white/10 shadow-2xl bg-[#0f1523]">
        {/* Header */}
        <div className="p-5 border-b border-white/5 flex items-center justify-between sticky top-0 bg-[#0f1523] z-10">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${incident.is_attack ? 'bg-rose-500/15 text-rose-400' : 'bg-emerald-500/15 text-emerald-400'}`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white font-mono">
                  {incident.vector || 'Security Incident'}
                </h3>
                <span className="text-xs text-gray-400 font-mono">#{incident.id}</span>
              </div>
              <div className="text-xs text-gray-400 font-mono">
                Detected at {incident.timestamp || incident.time_display}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6">
          {/* Status & Severity Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <span className="text-[10px] uppercase font-bold text-gray-400 tracking-wider">Severity</span>
              <div className="mt-1">
                <StatusPill severity={raw.threat_severity || (incident.is_attack ? 'HIGH' : 'LOW')} />
              </div>
            </div>
            <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <span className="text-[10px] uppercase font-bold text-gray-400 tracking-wider">Status</span>
              <div className="mt-1">
                <StatusPill status={incident.status} />
              </div>
            </div>
            <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <span className="text-[10px] uppercase font-bold text-gray-400 tracking-wider">Confidence</span>
              <div className="mt-1 text-sm font-bold font-mono text-cyan-400">
                {incident.confidence}%
              </div>
            </div>
            <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <span className="text-[10px] uppercase font-bold text-gray-400 tracking-wider">Risk Score</span>
              <div className="mt-1 text-sm font-bold font-mono text-rose-400">
                {raw.risk_score || (incident.is_attack ? 85.0 : 10.0)}/100
              </div>
            </div>
          </div>

          {/* Network Connection Details */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2.5 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Network Flow Attributes
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
              <div className="p-3 rounded-lg bg-black/30 border border-white/5 flex justify-between items-center">
                <span className="text-gray-400">Source IP:</span>
                <span className="text-gray-200 font-semibold">{incident.src_ip || 'N/A'}</span>
              </div>
              <div className="p-3 rounded-lg bg-black/30 border border-white/5 flex justify-between items-center">
                <span className="text-gray-400">Destination IP:</span>
                <span className="text-gray-200 font-semibold">{incident.dst_ip || 'N/A'}</span>
              </div>
              <div className="p-3 rounded-lg bg-black/30 border border-white/5 flex justify-between items-center">
                <span className="text-gray-400">Protocol:</span>
                <span className="text-gray-200">{raw.protocol || 'TCP / HTTP'}</span>
              </div>
              <div className="p-3 rounded-lg bg-black/30 border border-white/5 flex justify-between items-center">
                <span className="text-gray-400">Latency:</span>
                <span className="text-cyan-400">{incident.latency || 0} ms</span>
              </div>
              <div className="p-3 rounded-lg bg-black/30 border border-white/5 flex justify-between items-center">
                <span className="text-gray-400">GeoIP Origin:</span>
                <span className="text-gray-200">
                  {raw.geoip?.flag} {raw.geoip?.country || 'Local/Internal'} {raw.geoip?.city ? `(${raw.geoip.city})` : ''}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-black/30 border border-white/5 flex justify-between items-center">
                <span className="text-gray-400">Mitigation Action:</span>
                <span className={incident.action_taken?.includes('Block') ? 'text-rose-400' : 'text-emerald-400'}>
                  {incident.action_taken || 'Traffic Allowed'}
                </span>
              </div>
            </div>
          </div>

          {/* AI Detection Reason & Explainability (Strictly Real Data per Rule 12) */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2.5 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              AI Detection Reason & Explainability
            </h4>

            {xaiAttributions.length > 0 || dpiFindings.length > 0 || zeroDayScore ? (
              <div className="space-y-2">
                {/* DPI Findings */}
                {dpiFindings.map((d, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/20 text-xs">
                    <div className="flex items-center justify-between text-rose-400 font-semibold mb-1">
                      <span>L7 Payload Signature: {d.signature}</span>
                      <StatusPill severity={d.severity} size="xs" />
                    </div>
                    <p className="text-gray-300 font-mono text-[11px] mb-1">Matched Pattern: {d.matched_pattern}</p>
                    <p className="text-gray-400 text-[11px] font-mono">{d.snippet}</p>
                  </div>
                ))}

                {/* Zero Day Detection */}
                {zeroDayScore > 0 && (
                  <div className="p-3 rounded-lg bg-purple-950/20 border border-purple-500/20 text-xs">
                    <div className="flex items-center justify-between text-purple-300 font-semibold">
                      <span>Isolation Forest Anomaly</span>
                      <span className="font-mono text-purple-400 font-bold">{zeroDayScore}%</span>
                    </div>
                    <p className="text-gray-400 text-[11px] mt-1">
                      Unsupervised anomaly evaluation flagged statistical deviation from normal traffic baseline.
                    </p>
                  </div>
                )}

                {/* XAI Attributions */}
                {xaiAttributions.map((attr, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-black/40 border border-white/5 text-xs flex items-start justify-between">
                    <div>
                      <div className="font-medium text-gray-200">{attr.feature}</div>
                      <div className="text-[11px] text-gray-400 mt-0.5">{attr.reason}</div>
                    </div>
                    <span className="font-mono font-semibold text-cyan-400 text-xs shrink-0 ml-4">
                      {attr.value}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5 text-xs text-gray-400 italic">
                Explainability data not available from backend for this event.
              </div>
            )}
          </div>

          {/* Threat Memory Details */}
          {threatMemory?.is_remembered && (
            <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/20 text-xs">
              <span className="font-bold text-blue-400">Threat Memory Match:</span>
              <p className="text-gray-300 text-[11px] mt-0.5 font-mono">
                Source IP was previously remembered in CASOC IOC threat index with matching malicious signature.
              </p>
            </div>
          )}

          {/* Analyst Notes if present */}
          {incident.notes && (
            <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5 text-xs">
              <span className="font-bold text-gray-300">Analyst Triage Notes:</span>
              <p className="text-gray-400 mt-1 text-[11px]">{incident.notes}</p>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-white/5 bg-[#0a0e17]/80 flex items-center justify-between sticky bottom-0">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-gray-400 hover:text-white bg-white/5 border border-white/10 rounded-lg"
          >
            Close
          </button>
          {onTriageClick && (
            <button
              onClick={() => {
                onClose();
                onTriageClick(incident);
              }}
              className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg shadow-md shadow-cyan-600/30 transition-colors"
            >
              Update Triage Status
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
