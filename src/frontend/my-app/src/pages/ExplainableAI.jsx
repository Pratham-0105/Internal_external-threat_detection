import React, { useState } from 'react';
import { HelpCircle, BarChart3, Info } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { EmptyState } from '../components/common/EmptyState';

export const ExplainableAI = () => {
  const { incidents } = useSOC();
  const [selectedIncidentId, setSelectedIncidentId] = useState(incidents[0]?.id || null);

  const selectedIncident = incidents.find((i) => i.id === Number(selectedIncidentId)) || incidents[0];
  const raw = selectedIncident?.rawEvent || {};
  const xaiAttributions = raw.xai || [];
  const dpiFindings = raw.dpi?.findings || [];

  return (
    <div className="space-y-6">
      {/* Header & Incident Selector */}
      <div className="soc-panel p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <HelpCircle className="w-4 h-4 text-purple-400" />
            Explainable AI (XAI) & Threat Attribution Engine
          </h2>
          <div className="text-xs text-gray-400 mt-1 font-mono">
            Human-interpretable feature contribution weights and Layer 7 Deep Packet Inspection (DPI) rationale
          </div>
        </div>

        {/* Select Incident to Explain */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-gray-400 uppercase font-bold text-[10px]">Select Incident:</span>
          <select
            value={selectedIncident?.id || ''}
            onChange={(e) => setSelectedIncidentId(Number(e.target.value))}
            className="bg-[#131c2e] border border-white/10 rounded px-3 py-1.5 text-xs text-white focus:outline-none"
          >
            {incidents.slice(0, 15).map((inc) => (
              <option key={inc.id} value={inc.id}>
                #{inc.id} &mdash; {inc.vector} ({inc.src_ip})
              </option>
            ))}
          </select>
        </div>
      </div>

      {selectedIncident ? (
        <div className="space-y-6">
          {/* Top Verdict Overview */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div className="soc-panel p-4">
              <span className="text-[10px] uppercase font-bold text-gray-400">Classified Vector</span>
              <div className="text-sm font-bold text-rose-400 mt-1">{selectedIncident.vector}</div>
            </div>
            <div className="soc-panel p-4">
              <span className="text-[10px] uppercase font-bold text-gray-400">Confidence Score</span>
              <div className="text-sm font-bold text-cyan-400 mt-1">{selectedIncident.confidence}%</div>
            </div>
            <div className="soc-panel p-4">
              <span className="text-[10px] uppercase font-bold text-gray-400">Threat Verdict</span>
              <div className="mt-1">
                <StatusPill
                  severity={selectedIncident.is_attack ? 'CRITICAL' : 'LOW'}
                  label={selectedIncident.is_attack ? 'MALICIOUS FLOW' : 'BENIGN SESSION'}
                />
              </div>
            </div>
            <div className="soc-panel p-4">
              <span className="text-[10px] uppercase font-bold text-gray-400">Processing Latency</span>
              <div className="text-sm font-bold text-purple-400 mt-1">{selectedIncident.latency} ms</div>
            </div>
          </div>

          {/* Actual Feature Attributions Returned by Backend xai_analyzer per Section 20 */}
          <div className="soc-panel p-5">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              ML Feature Contribution Factors & Decision Tree Rationale
            </h3>

            {xaiAttributions.length > 0 || dpiFindings.length > 0 ? (
              <div className="space-y-3 font-mono">
                {/* DPI Payload Matches */}
                {dpiFindings.map((dpi, idx) => (
                  <div key={idx} className="p-4 rounded-lg bg-rose-950/20 border border-rose-500/30 text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-rose-400">L7 Payload Finding: {dpi.signature}</span>
                      <StatusPill severity={dpi.severity} size="xs" />
                    </div>
                    <div className="text-gray-300 text-[11px] mb-1">Matched Pattern: {dpi.matched_pattern}</div>
                    <div className="text-gray-400 text-[10px] break-all bg-black/40 p-2 rounded">
                      {dpi.snippet}
                    </div>
                  </div>
                ))}

                {/* XAI Features */}
                {xaiAttributions.map((attr, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg bg-black/30 border border-white/5 text-xs flex items-start justify-between">
                    <div>
                      <div className="font-bold text-gray-200">{attr.feature}</div>
                      <div className="text-gray-400 text-[11px] mt-0.5 leading-relaxed">{attr.reason}</div>
                    </div>
                    <span className="text-xs font-bold font-mono text-cyan-400 shrink-0 ml-4">
                      {attr.value}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 rounded-lg bg-white/[0.02] border border-white/5 text-xs text-gray-400 font-mono">
                <div className="flex items-center gap-2 text-cyan-400 font-bold mb-1">
                  <Info className="w-4 h-4" /> Feature Attribution Baseline
                </div>
                Detailed feature weights are generated when flows are submitted through the live inference engine. Standard feature values: Flow Duration, Flow IAT Mean, and Forward Inter-Arrival times.
              </div>
            )}
          </div>
        </div>
      ) : (
        <EmptyState
          title="No incident selected"
          description="Select an evaluated incident to view AI explainability and feature weights."
        />
      )}
    </div>
  );
};
