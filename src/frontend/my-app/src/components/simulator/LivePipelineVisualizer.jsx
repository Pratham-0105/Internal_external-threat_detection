import React from 'react';
import { 
  Terminal, 
  Send, 
  Cpu, 
  Search, 
  ShieldAlert, 
  Zap, 
  Database, 
  Radio, 
  LayoutDashboard,
  CheckCircle,
  Clock,
  AlertCircle
} from 'lucide-react';

const PIPELINE_STAGES = [
  { id: 1, name: 'Simulator', icon: Terminal, desc: 'Payload Generator' },
  { id: 2, name: 'Ingestion', icon: Send, desc: 'REST Ingress API' },
  { id: 3, name: 'Extraction', icon: Cpu, desc: 'Feature Vector' },
  { id: 4, name: 'ML Classifier', icon: Cpu, desc: 'LightGBM / IsoForest' },
  { id: 5, name: 'DPI Engine', icon: Search, desc: 'Regex Signature' },
  { id: 6, name: 'Zero-Day', icon: ShieldAlert, desc: 'Anomaly Isolation' },
  { id: 7, name: 'Mitigation', icon: Zap, desc: 'Active Defense Rule' },
  { id: 8, name: 'Audit DB', icon: Database, desc: 'SQLite Persistence' },
  { id: 9, name: 'Dashboard', icon: Radio, desc: 'Socket.IO Broadcast' }
];

export const LivePipelineVisualizer = ({ activeStage = 0, status = 'idle', latency = null }) => {
  // status can be: 'idle', 'running', 'completed', 'failed'

  return (
    <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 shadow-2xl relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute top-0 left-1/4 w-96 h-20 bg-cyan-500/10 blur-3xl pointer-events-none" />

      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <LayoutDashboard className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              REAL-TIME DETECTION & MITIGATION PIPELINE
              {status === 'running' && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse">
                  PROCESSING
                </span>
              )}
              {status === 'completed' && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" /> PIPELINE VERIFIED
                </span>
              )}
              {status === 'failed' && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" /> PIPELINE ERROR
                </span>
              )}
            </h3>
            <p className="text-xs text-gray-400">
              Deterministic 9-stage telemetry journey from client payload injection to real-time dashboard sync
            </p>
          </div>
        </div>

        {latency !== null && (
          <div className="text-right">
            <div className="text-[11px] text-gray-400 uppercase tracking-wider">Round-Trip Latency</div>
            <div className="text-sm font-mono font-bold text-cyan-400 flex items-center gap-1 justify-end">
              <Clock className="w-3.5 h-3.5" />
              {latency} ms
            </div>
          </div>
        )}
      </div>

      {/* 9-Stage Flow Steps */}
      <div className="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-9 gap-2 pt-2">
        {PIPELINE_STAGES.map((stage) => {
          const Icon = stage.icon;
          const isPast = activeStage > stage.id || status === 'completed';
          const isCurrent = activeStage === stage.id && status === 'running';
          const isFailed = activeStage === stage.id && status === 'failed';

          return (
            <div
              key={stage.id}
              className={`relative rounded-lg p-2.5 border transition-all duration-300 flex flex-col items-center text-center ${
                isCurrent
                  ? 'bg-amber-500/10 border-amber-500/40 shadow-lg shadow-amber-500/10 ring-1 ring-amber-400/30'
                  : isPast
                  ? 'bg-emerald-500/10 border-emerald-500/30 shadow-sm'
                  : isFailed
                  ? 'bg-rose-500/10 border-rose-500/40'
                  : 'bg-white/[0.02] border-white/5 opacity-60'
              }`}
            >
              {/* Stage Number Badge */}
              <div className="absolute top-1.5 right-1.5 text-[9px] font-mono px-1 rounded bg-black/40 text-gray-400">
                0{stage.id}
              </div>

              {/* Stage Icon */}
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center mb-1.5 ${
                  isCurrent
                    ? 'bg-amber-500/20 text-amber-300 animate-bounce'
                    : isPast
                    ? 'bg-emerald-500/20 text-emerald-300'
                    : isFailed
                    ? 'bg-rose-500/20 text-rose-300'
                    : 'bg-white/5 text-gray-400'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
              </div>

              {/* Stage Name */}
              <div className="text-[11px] font-bold text-white truncate w-full mb-0.5">
                {stage.name}
              </div>

              {/* Stage Description */}
              <div className="text-[9px] font-mono text-gray-400 truncate w-full">
                {stage.desc}
              </div>

              {/* Status Indicator Pill */}
              <div className="mt-1.5">
                {isPast ? (
                  <span className="text-[9px] font-mono text-emerald-400 font-medium">DONE</span>
                ) : isCurrent ? (
                  <span className="text-[9px] font-mono text-amber-400 font-bold animate-pulse">ACTIVE</span>
                ) : isFailed ? (
                  <span className="text-[9px] font-mono text-rose-400 font-bold">ERR</span>
                ) : (
                  <span className="text-[9px] font-mono text-gray-400">WAIT</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
