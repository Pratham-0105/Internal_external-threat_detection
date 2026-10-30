import React, { useState } from 'react';
import { AICopilotModal } from '../components/modals/AICopilotModal';
import { Cpu, Zap, Shield, Sparkles, BookOpen, Terminal, CheckCircle2 } from 'lucide-react';
import { useSOC } from '../context/SOCContext';

export const AICopilot = () => {
  const { incidents } = useSOC();
  const latestAttack = incidents.find((i) => i.is_attack) || incidents[0] || null;
  const [modalOpen, setModalOpen] = useState(true);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-5">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono tracking-wider uppercase mb-1">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Autonomous Threat Intelligence & Response
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
            AI Security Operations Copilot
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
              SOAR Assistant
            </span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Natural language threat reasoning, TreeSHAP explainable AI decoding, and automated containment playbook execution.
          </p>
        </div>

        <button
          onClick={() => setModalOpen(true)}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/20 transition-all"
        >
          <Sparkles className="w-4 h-4" />
          Open Active Copilot Session
        </button>
      </div>

      {/* Feature Capabilities Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="bg-[#111726] p-5 rounded-2xl border border-white/5 space-y-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Mathematical TreeSHAP Reasoning</h3>
          <p className="text-xs text-gray-400 leading-relaxed">
            Translates raw gradient-boosted decision tree attributions into human-readable sentences detailing why forward packet IAT and idle variance triggered an alert.
          </p>
        </div>

        <div className="bg-[#111726] p-5 rounded-2xl border border-white/5 space-y-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <Terminal className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Multi-Platform Firewall Generator</h3>
          <p className="text-xs text-gray-400 leading-relaxed">
            Instantly generates syntactically correct rules for Linux <code>iptables</code>, Ubuntu <code>ufw</code>, Windows Defender, and Cisco enterprise router ACLs.
          </p>
        </div>

        <div className="bg-[#111726] p-5 rounded-2xl border border-white/5 space-y-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Zap className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">SOAR Playbook Automation</h3>
          <p className="text-xs text-gray-400 leading-relaxed">
            Executes 1-click active perimeter containment, isolates compromised internal VLAN ports, and stages IOC artifacts under NIST SP 800-61 incident response guidelines.
          </p>
        </div>
      </div>

      {/* Embedded Active Session */}
      <div className="bg-[#0f1524] rounded-2xl border border-white/5 p-6 text-center space-y-4">
        <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 mx-auto flex items-center justify-center text-cyan-400 shadow-xl shadow-cyan-500/10">
          <Sparkles className="w-8 h-8 animate-pulse" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-white">Interactive Copilot Console Ready</h2>
          <p className="text-xs text-gray-400 max-w-md mx-auto mt-1">
            The Copilot modal is currently active. You can minimize or open it anytime from the top bar to investigate any live threat event.
          </p>
        </div>
        <button
          onClick={() => setModalOpen(true)}
          className="px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-600 text-white font-semibold text-xs transition-colors shadow-md"
        >
          Launch Interactive Chat Console
        </button>
      </div>

      {modalOpen && (
        <AICopilotModal
          isOpen={modalOpen}
          onClose={() => setModalOpen(false)}
          initialIncident={latestAttack}
        />
      )}
    </div>
  );
};
