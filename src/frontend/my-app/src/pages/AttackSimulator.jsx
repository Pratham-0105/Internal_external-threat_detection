import React, { useState } from 'react';
import { 
  Play, 
  Terminal, 
  ShieldAlert, 
  Server, 
  Activity, 
  Zap, 
  UserCheck, 
  Cpu, 
  RotateCcw
} from 'lucide-react';
import { 
  EXTERNAL_ATTACK_TEMPLATES, 
  INSIDER_THREAT_TEMPLATES, 
  executeExternalAttack, 
  executeInsiderThreat 
} from '../services/simulationService';
import { LivePipelineVisualizer } from '../components/simulator/LivePipelineVisualizer';
import { SimulationConsole } from '../components/simulator/SimulationConsole';
import { useSOC } from '../context/SOCContext';

export const AttackSimulator = () => {
  const { wsConnected } = useSOC();
  const [activeTab, setActiveTab] = useState('external'); // 'external' | 'insider'
  const [runningAttackId, setRunningAttackId] = useState(null);
  const [pipelineState, setPipelineState] = useState({ stage: 0, status: 'idle', latency: null });
  const [simulationLogs, setSimulationLogs] = useState([]);

  // Metrics
  const totalSimulated = simulationLogs.length;
  const successfulSims = simulationLogs.filter(l => l.success).length;
  const avgLatency = totalSimulated > 0 
    ? Math.round(simulationLogs.reduce((acc, curr) => acc + (curr.latencyMs || 0), 0) / totalSimulated) 
    : 0;

  const runExternal = async (template) => {
    if (runningAttackId) return;
    setRunningAttackId(template.id);
    setPipelineState({ stage: 1, status: 'running', latency: null });

    // Step 1: Simulator generated payload
    await new Promise(r => setTimeout(r, 60));
    setPipelineState(prev => ({ ...prev, stage: 2 }));

    // Step 2: REST Ingress to Flask Port 5000 /predict
    const result = await executeExternalAttack(template);

    // Step 3-8: Fast progression through extraction, ML inference, DPI, defense
    setPipelineState(prev => ({ ...prev, stage: 4 }));
    await new Promise(r => setTimeout(r, 70));
    setPipelineState(prev => ({ ...prev, stage: 7 }));
    await new Promise(r => setTimeout(r, 60));
    setPipelineState(prev => ({ ...prev, stage: 9, status: result.success ? 'completed' : 'failed', latency: result.latencyMs }));

    setSimulationLogs(prev => [result, ...prev]);
    setRunningAttackId(null);
  };

  const runInsider = async (template) => {
    if (runningAttackId) return;
    setRunningAttackId(template.id);
    setPipelineState({ stage: 1, status: 'running', latency: null });

    await new Promise(r => setTimeout(r, 60));
    setPipelineState(prev => ({ ...prev, stage: 2 }));

    const result = await executeInsiderThreat(template);

    setPipelineState(prev => ({ ...prev, stage: 4 }));
    await new Promise(r => setTimeout(r, 70));
    setPipelineState(prev => ({ ...prev, stage: 7 }));
    await new Promise(r => setTimeout(r, 60));
    setPipelineState(prev => ({ ...prev, stage: 9, status: result.success ? 'completed' : 'failed', latency: result.latencyMs }));

    setSimulationLogs(prev => [result, ...prev]);
    setRunningAttackId(null);
  };

  const resetPipeline = () => {
    setPipelineState({ stage: 0, status: 'idle', latency: null });
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
              SINGLE ATTACK & DEFENSE PLATFORM
            </span>
            <span className="text-[10px] font-mono text-cyan-400 flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              {wsConnected ? 'REAL-TIME WEBSOCKET ACTIVE' : 'HTTP POLLING'}
            </span>
          </div>
          <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-red-400" />
            Attack Simulation Lab
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Launch controlled cyber attacks directly from this single interface. Watch real-time AI classification, DPI inspection, and auto-mitigation update the live SOC dashboard instantly.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={resetPipeline}
            className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white text-xs font-medium border border-white/10 flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Pipeline
          </button>
        </div>
      </div>

      {/* Top 4 Performance & Health KPI Badges */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">Total Attacks Injected</div>
            <div className="text-2xl font-mono font-bold text-white mt-1">{totalSimulated}</div>
            <div className="text-[10px] text-cyan-400 mt-0.5">{successfulSims} processed successfully</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Terminal className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">NIDS API Status</div>
            <div className="text-sm font-bold text-emerald-400 mt-1 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              PORT 5005 ONLINE
            </div>
            <div className="text-[10px] text-gray-400 mt-0.5">LightGBM & DPI Engine</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">Insider Threat Engine</div>
            <div className="text-sm font-bold text-purple-400 mt-1 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
              PORT 5001 ONLINE
            </div>
            <div className="text-[10px] text-gray-400 mt-0.5">Isolation Forest & Signatures</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <UserCheck className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-gray-400 uppercase tracking-wider font-semibold">Average Pipeline Latency</div>
            <div className="text-2xl font-mono font-bold text-cyan-400 mt-1">{avgLatency} ms</div>
            <div className="text-[10px] text-gray-400 mt-0.5">Round-trip ML classification</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* 9-Stage Pipeline Visualization */}
      <LivePipelineVisualizer 
        activeStage={pipelineState.stage} 
        status={pipelineState.status} 
        latency={pipelineState.latency} 
      />

      {/* Attack Vectors Tab Selector */}
      <div className="border-b border-white/10 flex items-center gap-3">
        <button
          onClick={() => setActiveTab('external')}
          className={`pb-3 text-sm font-bold tracking-wide flex items-center gap-2 border-b-2 transition-all ${
            activeTab === 'external'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          EXTERNAL ATTACK VECTORS (6 CARDS)
        </button>

        <button
          onClick={() => setActiveTab('insider')}
          className={`pb-3 text-sm font-bold tracking-wide flex items-center gap-2 border-b-2 transition-all ${
            activeTab === 'insider'
              ? 'border-purple-500 text-purple-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <UserCheck className="w-4 h-4" />
          INSIDER THREAT VECTORS (6 CARDS)
        </button>
      </div>

      {/* Attack Cards Grid */}
      {activeTab === 'external' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {EXTERNAL_ATTACK_TEMPLATES.map((tmpl) => {
            const isRunning = runningAttackId === tmpl.id;
            return (
              <div
                key={tmpl.id}
                className="bg-[#0b101d] border border-white/10 rounded-xl p-5 hover:border-blue-500/40 transition-all flex flex-col justify-between shadow-lg group relative overflow-hidden"
              >
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      {tmpl.category}
                    </span>
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        tmpl.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}
                    >
                      {tmpl.severity}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-white group-hover:text-blue-300 transition-colors">
                    {tmpl.name}
                  </h3>

                  <p className="text-xs text-gray-400 leading-relaxed">
                    {tmpl.description}
                  </p>

                  <div className="pt-2 border-t border-white/5 space-y-1 text-[11px] font-mono">
                    <div className="flex items-center justify-between text-gray-400">
                      <span>Expected Defense:</span>
                      <span className="text-cyan-400 text-right truncate max-w-[180px]">{tmpl.mitigationExpected}</span>
                    </div>
                    <div className="flex items-center justify-between text-gray-400">
                      <span>Target Endpoint:</span>
                      <span className="text-gray-300">POST :5005/predict</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-white/5">
                  <button
                    onClick={() => runExternal(tmpl)}
                    disabled={runningAttackId !== null}
                    className={`w-full py-2.5 px-4 rounded-lg font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md ${
                      isRunning
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 cursor-wait'
                        : runningAttackId !== null
                        ? 'bg-white/5 text-gray-400 cursor-not-allowed'
                        : 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-blue-500/20'
                    }`}
                  >
                    {isRunning ? (
                      <>
                        <Zap className="w-3.5 h-3.5 animate-spin text-amber-300" />
                        <span>Injecting & Processing...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        <span>Launch Attack Attack</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {activeTab === 'insider' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {INSIDER_THREAT_TEMPLATES.map((tmpl) => {
            const isRunning = runningAttackId === tmpl.id;
            return (
              <div
                key={tmpl.id}
                className="bg-[#0b101d] border border-white/10 rounded-xl p-5 hover:border-purple-500/40 transition-all flex flex-col justify-between shadow-lg group relative overflow-hidden"
              >
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      {tmpl.category}
                    </span>
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        tmpl.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : tmpl.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                      }`}
                    >
                      {tmpl.severity}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-white group-hover:text-purple-300 transition-colors">
                    {tmpl.name}
                  </h3>

                  <p className="text-xs text-gray-400 leading-relaxed">
                    {tmpl.description}
                  </p>

                  <div className="pt-2 border-t border-white/5 space-y-1 text-[11px] font-mono">
                    <div className="flex items-center justify-between text-gray-400">
                      <span>Expected Defense:</span>
                      <span className="text-purple-300 text-right truncate max-w-[180px]">{tmpl.mitigationExpected}</span>
                    </div>
                    <div className="flex items-center justify-between text-gray-400">
                      <span>Target Endpoint:</span>
                      <span className="text-gray-300">POST :5001/api/ingest</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-white/5">
                  <button
                    onClick={() => runInsider(tmpl)}
                    disabled={runningAttackId !== null}
                    className={`w-full py-2.5 px-4 rounded-lg font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md ${
                      isRunning
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 cursor-wait'
                        : runningAttackId !== null
                        ? 'bg-white/5 text-gray-400 cursor-not-allowed'
                        : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-purple-500/20'
                    }`}
                  >
                    {isRunning ? (
                      <>
                        <Zap className="w-3.5 h-3.5 animate-spin text-amber-300" />
                        <span>Injecting & Processing...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        <span>Launch Insider Threat</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Live Simulation Console */}
      <SimulationConsole 
        logs={simulationLogs} 
        onClear={() => setSimulationLogs([])} 
      />
    </div>
  );
};
