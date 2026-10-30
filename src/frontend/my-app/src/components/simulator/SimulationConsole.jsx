import React, { useState } from 'react';
import { Terminal, Trash2, Copy, Check, ChevronDown, ChevronRight, Download } from 'lucide-react';

export const SimulationConsole = ({ logs = [], onClear = () => {} }) => {
  const [copiedId, setCopiedId] = useState(null);
  const [expandedLogId, setExpandedLogId] = useState(null);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const downloadLogs = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `casoc-simulation-log-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-[#0b101d] border border-white/10 rounded-xl overflow-hidden shadow-2xl flex flex-col h-96">
      {/* Console Header */}
      <div className="px-4 py-3 bg-[#0f1629] border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-bold text-white tracking-wider uppercase">
            SIMULATION EXECUTION CONSOLE
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            {logs.length} EVENTS RECORDED
          </span>
        </div>

        <div className="flex items-center gap-2">
          {logs.length > 0 && (
            <>
              <button
                onClick={downloadLogs}
                className="px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white text-xs font-mono flex items-center gap-1.5 transition-colors border border-white/10"
                title="Download JSON telemetry log"
              >
                <Download className="w-3 h-3" />
                Export
              </button>
              <button
                onClick={onClear}
                className="px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 hover:text-rose-200 text-xs font-mono flex items-center gap-1.5 transition-colors border border-rose-500/20"
                title="Clear console output"
              >
                <Trash2 className="w-3 h-3" />
                Clear
              </button>
            </>
          )}
        </div>
      </div>

      {/* Log Output Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs select-text">
        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-400 space-y-2">
            <Terminal className="w-8 h-8 opacity-30" />
            <p className="text-xs">No simulation runs recorded in current session.</p>
            <p className="text-[11px] text-gray-400">Launch any attack vector above to stream genuine backend telemetry logs.</p>
          </div>
        ) : (
          logs.map((log, idx) => {
            const isSuccess = log.success;
            const isExpanded = expandedLogId === idx;

            return (
              <div
                key={idx}
                className={`p-3 rounded-lg border transition-all ${
                  isSuccess
                    ? 'bg-emerald-500/[0.04] border-emerald-500/20'
                    : 'bg-rose-500/[0.04] border-rose-500/20'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-gray-400 text-[10px]">
                      {new Date(log.timestamp).toLocaleTimeString()}.{new Date(log.timestamp).getMilliseconds()}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        log.targetType === 'external'
                          ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                          : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                      }`}
                    >
                      {log.targetType.toUpperCase()}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        isSuccess
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {isSuccess ? 'PROCESSED' : 'ERROR'}
                    </span>
                    <span className="text-white font-semibold">{log.name}</span>
                    <span className="text-gray-400 text-[11px]">[{log.endpoint}]</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-cyan-400 font-bold text-[11px]">
                      {log.latencyMs} ms
                    </span>
                    <button
                      onClick={() => copyToClipboard(log.backendResponse || log.error, `raw-${idx}`)}
                      className="p-1 hover:bg-white/10 rounded text-gray-400 hover:text-white"
                      title="Copy response JSON"
                    >
                      {copiedId === `raw-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                    <button
                      onClick={() => setExpandedLogId(isExpanded ? null : idx)}
                      className="p-1 hover:bg-white/10 rounded text-gray-400 hover:text-white"
                    >
                      {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Quick Summary Line */}
                <div className="mt-1.5 text-[11px] text-gray-300">
                  {isSuccess ? (
                    <div className="flex items-center gap-3 flex-wrap">
                      {log.backendResponse?.predictions?.[0] && (
                        <>
                          <span className="text-gray-400">Classification:</span>
                          <span className={log.backendResponse.predictions[0].is_malicious ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                            {log.backendResponse.predictions[0].is_malicious ? 'MALICIOUS THREAT' : 'BENIGN TRAFFIC'}
                          </span>
                          <span className="text-gray-400">Confidence:</span>
                          <span className="text-cyan-300 font-bold">
                            {(log.backendResponse.predictions[0].confidence * 100).toFixed(1)}%
                          </span>
                          <span className="text-gray-400">Action:</span>
                          <span className="text-amber-300 font-bold">
                            {log.backendResponse.predictions[0].mitigation_action || 'BLOCK_PACKET'}
                          </span>
                        </>
                      )}
                      {log.backendResponse?.status && (
                        <>
                          <span className="text-gray-400">Status:</span>
                          <span className="text-emerald-400 font-bold">{log.backendResponse.status}</span>
                          <span className="text-gray-400">Risk Score:</span>
                          <span className="text-rose-400 font-bold">{log.backendResponse.risk_score || 'CRITICAL'}</span>
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="text-rose-400 font-medium">
                      Failed: {log.error}
                    </div>
                  )}
                </div>

                {/* Expanded Raw JSON View */}
                {isExpanded && (
                  <div className="mt-2 pt-2 border-t border-white/5 space-y-2">
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">Payload Dispatched:</div>
                      <pre className="p-2 rounded bg-black/50 text-[11px] text-gray-300 overflow-x-auto border border-white/5">
                        {JSON.stringify(log.payloadSent, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">Raw Backend Response:</div>
                      <pre className="p-2 rounded bg-black/50 text-[11px] text-cyan-300 overflow-x-auto border border-cyan-500/10">
                        {JSON.stringify(log.backendResponse || log.error, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
