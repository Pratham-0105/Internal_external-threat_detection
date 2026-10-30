import React, { useState } from 'react';
import { 
  GitMerge, 
  Play, 
  CheckCircle, 
  Clock, 
  AlertCircle
} from 'lucide-react';
import { 
  MULTI_STAGE_SCENARIOS, 
  EXTERNAL_ATTACK_TEMPLATES, 
  INSIDER_THREAT_TEMPLATES,
  executeExternalAttack, 
  executeInsiderThreat 
} from '../services/simulationService';
import { SimulationConsole } from '../components/simulator/SimulationConsole';
import { LivePipelineVisualizer } from '../components/simulator/LivePipelineVisualizer';

export const ScenarioRunner = () => {
  const [selectedScenarioId, setSelectedScenarioId] = useState(MULTI_STAGE_SCENARIOS[0].id);
  const [runningScenario, setRunningScenario] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [stageStatuses, setStageStatuses] = useState({}); // step -> 'pending' | 'running' | 'success' | 'failed'
  const [scenarioLogs, setScenarioLogs] = useState([]);
  const [pipelineState, setPipelineState] = useState({ stage: 0, status: 'idle', latency: null });

  const activeScenario = MULTI_STAGE_SCENARIOS.find(s => s.id === selectedScenarioId) || MULTI_STAGE_SCENARIOS[0];

  const handleSelectScenario = (id) => {
    if (runningScenario) return;
    setSelectedScenarioId(id);
    setCurrentStepIndex(-1);
    setStageStatuses({});
    setPipelineState({ stage: 0, status: 'idle', latency: null });
  };

  const runEntireScenario = async () => {
    if (runningScenario) return;
    setRunningScenario(true);
    setStageStatuses({});
    setCurrentStepIndex(0);

    for (let i = 0; i < activeScenario.stages.length; i++) {
      const stage = activeScenario.stages[i];
      setCurrentStepIndex(i);
      setStageStatuses(prev => ({ ...prev, [stage.step]: 'running' }));
      setPipelineState({ stage: 2, status: 'running', latency: null });

      let result;
      if (stage.targetType === 'external') {
        const tmpl = EXTERNAL_ATTACK_TEMPLATES.find(t => t.id === stage.templateId) || EXTERNAL_ATTACK_TEMPLATES[0];
        result = await executeExternalAttack(tmpl);
      } else {
        const tmpl = INSIDER_THREAT_TEMPLATES.find(t => t.id === stage.templateId) || INSIDER_THREAT_TEMPLATES[0];
        result = await executeInsiderThreat(tmpl);
      }

      setScenarioLogs(prev => [result, ...prev]);
      setPipelineState({ stage: 9, status: result.success ? 'completed' : 'failed', latency: result.latencyMs });
      setStageStatuses(prev => ({ ...prev, [stage.step]: result.success ? 'success' : 'failed' }));

      // Realistic interval between cyber kill-chain stages
      if (i < activeScenario.stages.length - 1) {
        await new Promise(r => setTimeout(r, 1200));
      }
    }

    setRunningScenario(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            MULTI-STAGE CYBER ATTACK CHAINS
          </span>
        </div>
        <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
          <GitMerge className="w-6 h-6 text-cyan-400" />
          Scenario Runner & Cyber Kill-Chain
        </h1>
        <p className="text-xs text-gray-400 mt-0.5">
          Execute progressive, multi-stage cyber campaigns that mimic advanced persistent threat (APT) tactics, techniques, and procedures (TTPs).
        </p>
      </div>

      {/* Scenario Selection Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {MULTI_STAGE_SCENARIOS.map((sc) => {
          const isSelected = sc.id === selectedScenarioId;
          return (
            <div
              key={sc.id}
              onClick={() => handleSelectScenario(sc.id)}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-cyan-500/10 border-cyan-500/40 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-500/30'
                  : 'bg-[#0b101d] border-white/10 hover:border-white/20'
              } ${runningScenario ? 'opacity-60 pointer-events-none' : ''}`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 text-gray-300 border border-white/10">
                  {sc.stages.length} STAGES
                </span>
                {isSelected && (
                  <span className="text-[10px] font-bold text-cyan-400 flex items-center gap-1">
                    SELECTED
                  </span>
                )}
              </div>
              <h3 className="text-sm font-bold text-white mb-1.5">{sc.title}</h3>
              <p className="text-xs text-gray-400 line-clamp-2">{sc.description}</p>
            </div>
          );
        })}
      </div>

      {/* Active Scenario Pipeline Execution Box */}
      <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
          <div>
            <div className="text-xs text-cyan-400 font-mono font-bold uppercase tracking-wider">
              ACTIVE ATTACK SEQUENCE
            </div>
            <h2 className="text-lg font-bold text-white mt-0.5">{activeScenario.title}</h2>
            <p className="text-xs text-gray-400 mt-1 max-w-2xl">{activeScenario.description}</p>
          </div>

          <button
            onClick={runEntireScenario}
            disabled={runningScenario}
            className={`px-6 py-3 rounded-lg font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-lg ${
              runningScenario
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 cursor-wait'
                : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-cyan-500/20'
            }`}
          >
            {runningScenario ? (
              <>
                <Clock className="w-4 h-4 animate-spin" />
                <span>Executing Kill-Chain (Stage {currentStepIndex + 1}/{activeScenario.stages.length})...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Complete Scenario</span>
              </>
            )}
          </button>
        </div>

        {/* Stages Stepper */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {activeScenario.stages.map((stage, idx) => {
            const status = stageStatuses[stage.step] || 'pending';
            const isActive = currentStepIndex === idx && runningScenario;

            return (
              <div
                key={stage.step}
                className={`p-4 rounded-xl border transition-all ${
                  isActive
                    ? 'bg-amber-500/10 border-amber-500/40 ring-1 ring-amber-400/30 shadow-lg'
                    : status === 'success'
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : status === 'failed'
                    ? 'bg-rose-500/10 border-rose-500/30'
                    : 'bg-white/[0.02] border-white/5'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/40 text-gray-400">
                    STAGE 0{stage.step}
                  </span>
                  <span
                    className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
                      stage.targetType === 'external'
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                        : 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                    }`}
                  >
                    {stage.targetType}
                  </span>
                </div>

                <div className="text-xs font-bold text-white mb-1">{stage.name}</div>
                <div className="text-[11px] text-gray-400 leading-relaxed mb-3">{stage.explanation}</div>

                <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono">
                  <span className="text-gray-400">STATUS:</span>
                  {status === 'success' && (
                    <span className="text-emerald-400 font-bold flex items-center gap-1">
                      <CheckCircle className="w-3 h-3" /> MITIGATED
                    </span>
                  )}
                  {status === 'failed' && (
                    <span className="text-rose-400 font-bold flex items-center gap-1">
                      <AlertCircle className="w-3 h-3" /> ERROR
                    </span>
                  )}
                  {status === 'running' && (
                    <span className="text-amber-400 font-bold flex items-center gap-1 animate-pulse">
                      <Clock className="w-3 h-3" /> RUNNING
                    </span>
                  )}
                  {status === 'pending' && <span className="text-gray-400">QUEUED</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Pipeline Visualizer */}
      <LivePipelineVisualizer 
        activeStage={pipelineState.stage} 
        status={pipelineState.status} 
        latency={pipelineState.latency} 
      />

      {/* Scenario Execution Console */}
      <SimulationConsole 
        logs={scenarioLogs} 
        onClear={() => setScenarioLogs([])} 
      />
    </div>
  );
};
