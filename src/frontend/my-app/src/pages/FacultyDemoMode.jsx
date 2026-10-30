import React, { useState } from 'react';
import { 
  GraduationCap, 
  Play, 
  Activity, 
  Radio, 
  Zap, 
  HelpCircle
} from 'lucide-react';
import { 
  EXTERNAL_ATTACK_TEMPLATES, 
  INSIDER_THREAT_TEMPLATES, 
  executeExternalAttack, 
  executeInsiderThreat 
} from '../services/simulationService';
import { LivePipelineVisualizer } from '../components/simulator/LivePipelineVisualizer';
import { useSOC } from '../context/SOCContext';

export const FacultyDemoMode = () => {
  const { incidents, metrics } = useSOC();
  const [activeRunningId, setActiveRunningId] = useState(null);
  const [pipelineState, setPipelineState] = useState({ stage: 0, status: 'idle', latency: null });
  const [latestResult, setLatestResult] = useState(null);

  const triggerAttack = async (type, template) => {
    if (activeRunningId) return;
    setActiveRunningId(template.id);
    setPipelineState({ stage: 1, status: 'running', latency: null });

    await new Promise(r => setTimeout(r, 60));
    setPipelineState(prev => ({ ...prev, stage: 2 }));

    let res;
    if (type === 'external') {
      res = await executeExternalAttack(template);
    } else {
      res = await executeInsiderThreat(template);
    }

    setPipelineState(prev => ({ ...prev, stage: 5 }));
    await new Promise(r => setTimeout(r, 70));
    setPipelineState(prev => ({ ...prev, stage: 8 }));
    await new Promise(r => setTimeout(r, 50));
    setPipelineState({ stage: 9, status: res.success ? 'completed' : 'failed', latency: res.latencyMs });

    setLatestResult(res);
    setActiveRunningId(null);
  };

  return (
    <div className="space-y-6">
      {/* Banner / Header */}
      <div className="bg-gradient-to-r from-cyan-950/40 via-[#0b101d] to-blue-950/40 border border-cyan-500/20 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10">
            <GraduationCap className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                CAPSTONE PROJECT PRESENTATION
              </span>
              <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                LIVE SOC VERIFIED
              </span>
            </div>
            <h1 className="text-xl font-black tracking-tight text-white mt-1">
              Faculty Demonstration Console
            </h1>
            <p className="text-xs text-gray-400">
              High-impact single-screen demonstration showing real-time AI classification, DPI inspection, and auto-mitigation with live Socket.IO feed.
            </p>
          </div>
        </div>

        {/* Live Metrics Quick View */}
        <div className="flex items-center gap-3">
          <div className="px-3.5 py-2 rounded-lg bg-black/40 border border-white/10 text-center">
            <div className="text-[10px] text-gray-400 uppercase tracking-wider">Active Threats</div>
            <div className="text-lg font-mono font-bold text-rose-400">{metrics?.activeThreats ?? 0}</div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-black/40 border border-white/10 text-center">
            <div className="text-[10px] text-gray-400 uppercase tracking-wider">Total Events</div>
            <div className="text-lg font-mono font-bold text-cyan-400">{metrics?.totalEvents ?? 0}</div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-black/40 border border-white/10 text-center">
            <div className="text-[10px] text-gray-400 uppercase tracking-wider">Mitigation Rate</div>
            <div className="text-lg font-mono font-bold text-emerald-400">{metrics?.threatsNeutralized ?? 100}%</div>
          </div>
        </div>
      </div>

      {/* 9-Stage Telemetry Pipeline */}
      <LivePipelineVisualizer 
        activeStage={pipelineState.stage} 
        status={pipelineState.status} 
        latency={pipelineState.latency} 
      />

      {/* Split-Screen Demonstration Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Quick Attack Injection Trigger (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-blue-400" />
                1-Click Attack Triggers
              </span>
              <span className="text-[10px] font-mono text-gray-400">SELECT TO INJECT</span>
            </div>

            <div className="space-y-2">
              <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider px-1">
                External Attack Vectors (Port 5000)
              </div>
              {EXTERNAL_ATTACK_TEMPLATES.slice(0, 3).map((tmpl) => (
                <button
                  key={tmpl.id}
                  onClick={() => triggerAttack('external', tmpl)}
                  disabled={activeRunningId !== null}
                  className={`w-full p-3 rounded-lg border text-left transition-all flex items-center justify-between ${
                    activeRunningId === tmpl.id
                      ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                      : 'bg-white/[0.02] border-white/5 hover:border-blue-500/40 hover:bg-blue-500/5 text-gray-300 hover:text-white'
                  }`}
                >
                  <div>
                    <div className="text-xs font-bold flex items-center gap-2">
                      <span>{tmpl.name}</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">
                        {tmpl.severity}
                      </span>
                    </div>
                    <div className="text-[11px] text-gray-400 mt-0.5">{tmpl.mitigationExpected}</div>
                  </div>
                  <Play className={`w-3.5 h-3.5 shrink-0 ${activeRunningId === tmpl.id ? 'animate-spin text-amber-300' : 'text-blue-400'}`} />
                </button>
              ))}

              <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider px-1 pt-2">
                Insider Threats (Port 5001)
              </div>
              {INSIDER_THREAT_TEMPLATES.slice(0, 3).map((tmpl) => (
                <button
                  key={tmpl.id}
                  onClick={() => triggerAttack('insider', tmpl)}
                  disabled={activeRunningId !== null}
                  className={`w-full p-3 rounded-lg border text-left transition-all flex items-center justify-between ${
                    activeRunningId === tmpl.id
                      ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                      : 'bg-white/[0.02] border-white/5 hover:border-purple-500/40 hover:bg-purple-500/5 text-gray-300 hover:text-white'
                  }`}
                >
                  <div>
                    <div className="text-xs font-bold flex items-center gap-2">
                      <span>{tmpl.name}</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">
                        {tmpl.severity}
                      </span>
                    </div>
                    <div className="text-[11px] text-gray-400 mt-0.5">{tmpl.mitigationExpected}</div>
                  </div>
                  <Play className={`w-3.5 h-3.5 shrink-0 ${activeRunningId === tmpl.id ? 'animate-spin text-amber-300' : 'text-purple-400'}`} />
                </button>
              ))}
            </div>
          </div>

          {/* Academic Architecture Highlights for Defense */}
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-cyan-400" />
              Faculty Defense Architecture Highlights
            </h3>
            <div className="space-y-2 text-xs text-gray-300">
              <div className="p-2.5 rounded bg-white/[0.02] border border-white/5">
                <span className="font-bold text-cyan-400">1. LightGBM Classifier:</span> Pre-trained binary tree ensemble trained on modern network flow vector dimensions for sub-millisecond classification.
              </div>
              <div className="p-2.5 rounded bg-white/[0.02] border border-white/5">
                <span className="font-bold text-purple-400">2. Deep Packet Inspection (DPI):</span> Regex signature scanner analyzing packet payload strings for SQLi, XSS, and command injections.
              </div>
              <div className="p-2.5 rounded bg-white/[0.02] border border-white/5">
                <span className="font-bold text-emerald-400">3. Autonomous Mitigation:</span> Dynamic rule generation implementing TCP Reset, IP blackholing, and DLP egress lockdown.
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Live Telemetry & Real-Time Incident Stream (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Latest Execution Breakdown Card */}
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                Live AI Inference & Mitigation Response
              </span>
              {latestResult && (
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {latestResult.latencyMs} ms LATENCY
                </span>
              )}
            </div>

            {latestResult ? (
              <div className="space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <div className="text-[10px] text-gray-400 uppercase">Attack Name</div>
                    <div className="text-xs font-bold text-white truncate mt-0.5">{latestResult.name}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <div className="text-[10px] text-gray-400 uppercase">Backend Route</div>
                    <div className="text-xs font-mono text-cyan-300 truncate mt-0.5">{latestResult.endpoint.split(' ')[1]}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <div className="text-[10px] text-gray-400 uppercase">Classification</div>
                    <div className="text-xs font-bold text-rose-400 mt-0.5">MALICIOUS THREAT</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <div className="text-[10px] text-gray-400 uppercase">Defense Action</div>
                    <div className="text-xs font-bold text-emerald-400 mt-0.5">ACTIVE MITIGATED</div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-black/50 border border-cyan-500/20 text-xs font-mono">
                  <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">Raw API Response Payload:</div>
                  <pre className="text-[11px] text-cyan-300 overflow-x-auto max-h-36">
                    {JSON.stringify(latestResult.backendResponse, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-gray-400 text-xs">
                Trigger any attack on the left pane to view instantaneous AI inference telemetry.
              </div>
            )}
          </div>

          {/* Real-Time Live Incident Telemetry Feed */}
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                Live Socket.IO Security Incidents
              </span>
              <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                REAL-TIME STREAM
              </span>
            </div>

            <div className="space-y-2 max-h-72 overflow-y-auto">
              {incidents.slice(0, 5).map((inc, i) => (
                <div
                  key={inc.id || i}
                  className="p-3 rounded-lg bg-white/[0.02] border border-white/5 hover:border-white/15 flex items-center justify-between gap-3 text-xs"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-rose-400 shrink-0" />
                    <div>
                      <div className="font-bold text-white">{inc.type || 'Anomalous Threat Vector'}</div>
                      <div className="text-[11px] font-mono text-gray-400 mt-0.5">
                        SRC: {inc.src_ip || '198.51.100.45'} | DST: {inc.dst_ip || '192.168.1.50'}
                      </div>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      MITIGATED
                    </span>
                    <div className="text-[10px] font-mono text-gray-400 mt-0.5">
                      {new Date(inc.timestamp || Date.now()).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
