import React, { useState, useRef, useEffect } from 'react';
import {
  Cpu,
  Send,
  X,
  Shield,
  Terminal,
  Zap,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Sparkles,
  Copy,
  Check
} from 'lucide-react';
import apiClient from '../../services/apiClient';

export const AICopilotModal = ({ isOpen, onClose, initialIncident = null }) => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        "Hello Admin! 👋 I am your **CASOC Autonomous AI Security Copilot**, powered by local AI and connected directly to the live NIDS telemetry engine.\n\nYou can chat with me naturally about any part of this project or query live system data:\n\n• *'How many are blocked?'*\n• *'What is the reason for block?'*\n• *'What machine learning models are used in this project?'*\n• *'Tell me about the system architecture and ports'*\n• *'How does TreeSHAP explainable AI work?'*\n• *'How do I simulate attacks?'*\n\nHow can I help you today, Admin?",
      actionType: 'ADMIN_GREETING'
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [playbookExecuting, setPlaybookExecuting] = useState(false);
  const [playbookResult, setPlaybookResult] = useState(null);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [isOpen, messages]);

  if (!isOpen) return null;

  const handleSend = async (queryText) => {
    const text = queryText || inputQuery;
    if (!text.trim() || loading) return;

    const userMsg = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const res = await apiClient.post('/api/copilot/query', {
        query: text,
        incident: initialIncident
      });

      if (res.data && res.data.response) {
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: res.data.response.answer,
            actionType: res.data.response.action_type
          }
        ]);
      }
    } catch (err) {
      console.error('Copilot query error:', err);
      const detail = err.response?.data?.message || err.message || '';
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Failed to reach Copilot engine (${detail || 'Connection refused'}). Please verify the Flask ML API is running on port 5005.`,
          actionType: 'ERROR'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleExecutePlaybook = async () => {
    const targetIp = initialIncident?.src_ip || '';
    setPlaybookExecuting(true);
    try {
      const res = await apiClient.post('/api/copilot/execute-playbook', {
        playbook: 'ISOLATE_AND_PERIMETER_BLOCK',
        target_ip: targetIp
      });
      setPlaybookResult(res.data);
      const effectiveIp = res.data?.target_ip || targetIp || 'Threat Source';
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `✅ **SOAR Automated Playbook Successfully Executed!**\n\n• Target Host: \`${effectiveIp}\`\n• Action: Perimeter IP Blacklist & Host Quarantine applied.\n• Status: Active Containment Rule Enforced in Firewall Table.`,
          actionType: 'PLAYBOOK_EXECUTED'
        }
      ]);
    } catch (err) {
      console.error('Playbook execution failed:', err);
    } finally {
      setPlaybookExecuting(false);
    }
  };

  const handleCopyCode = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const quickPrompts = [
    { label: '👋 Hello Copilot', query: 'Hello Copilot! What can you help me with as Admin?' },
    { label: '🛡️ Check Blocked IPs', query: 'How many are blocked?' },
    { label: '🔍 Reason for Block', query: 'What is the reason for block?' },
    { label: '🧠 ML Models in Project', query: 'What machine learning models are used in this project?' },
    { label: '🔬 TreeSHAP Explainability', query: 'How does TreeSHAP explainable AI work in this project?' },
    { label: '🏗️ System Architecture', query: 'Tell me about the system architecture and ports of this project' },
    { label: '🎯 How to Simulate Attack', query: 'How do I simulate attacks in this project?' },
    { label: '📊 Live Threat Overview', query: 'What attacks happened recently and what is the threat status?' },
    { label: '🔥 Firewall Rules', query: 'Generate iptables and UFW firewall rules' }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <div className="bg-[#0c101b] border border-cyan-500/30 rounded-2xl max-w-3xl w-full h-[85vh] flex flex-col shadow-2xl overflow-hidden relative">
        {/* Modal Top Bar */}
        <div className="p-4 bg-[#111728] border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20 animate-pulse">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-white text-base">CASOC AI Security Copilot</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  GenAI Threat Analyst
                </span>
              </div>
              <p className="text-xs text-gray-400">
                Autonomous threat triage, XAI interpretation, and SOAR containment execution
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-2 rounded-lg hover:bg-white/5 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Incident Context Banner (if an incident is active) */}
        {initialIncident && (
          <div className="bg-cyan-950/30 border-b border-cyan-500/20 px-4 py-2 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-cyan-300 font-mono">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target Incident: <strong>{initialIncident.category || 'Malicious Flow'}</strong></span>
              <span className="text-gray-400">|</span>
              <span>Source: <code>{initialIncident.src_ip || 'Threat Host'}</code></span>
            </div>
            <button
              onClick={handleExecutePlaybook}
              disabled={playbookExecuting}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 text-[11px] font-bold transition-all disabled:opacity-50"
            >
              <Zap className="w-3 h-3 text-red-400" />
              {playbookExecuting ? 'Executing...' : 'Execute SOAR Containment'}
            </button>
          </div>
        )}

        {/* Chat Stream Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 font-sans text-sm">
          {messages.map((msg, i) => (
            <div
              key={i}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[85%] rounded-2xl p-4 shadow-md ${
                  msg.role === 'user'
                    ? 'bg-cyan-600 text-white rounded-br-none'
                    : 'bg-[#141b2d] border border-white/5 text-gray-200 rounded-bl-none'
                }`}
              >
                <div className="prose prose-invert prose-sm max-w-none space-y-2 whitespace-pre-wrap leading-relaxed">
                  {msg.content}
                </div>

                {msg.role === 'assistant' && msg.content.includes('```') && (
                  <div className="mt-3 flex justify-end">
                    <button
                      onClick={() => handleCopyCode(msg.content, i)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-[11px] text-gray-300 border border-white/10 transition-colors"
                    >
                      {copiedIndex === i ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" /> Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" /> Copy Snippet
                        </>
                      )}
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="bg-[#141b2d] border border-white/5 rounded-2xl p-4 rounded-bl-none text-gray-400 text-xs flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400 animate-spin" />
                Copilot evaluating decision trees and threat intelligence...
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Suggestion Chips */}
        <div className="px-4 py-2 bg-[#0e1424] border-t border-white/5 flex items-center gap-2 overflow-x-auto no-scrollbar">
          {quickPrompts.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(p.query)}
              disabled={loading}
              className="whitespace-nowrap px-3 py-1 rounded-full bg-[#161f36] hover:bg-[#1e2a4a] text-[11px] text-cyan-300 border border-cyan-500/20 transition-colors shadow-sm disabled:opacity-40"
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Input Field Bar */}
        <div className="p-3 bg-[#111728] border-t border-white/10 flex items-center gap-2">
          <input
            type="text"
            placeholder="Ask Copilot anything (e.g. 'How to mitigate this?', 'Explain SHAP', 'Generate iptables')..."
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            disabled={loading}
            className="flex-1 bg-[#090d17] text-white text-sm px-4 py-2.5 rounded-xl border border-white/10 focus:border-cyan-500 focus:outline-none placeholder-gray-500"
          />

          <button
            onClick={() => handleSend()}
            disabled={!inputQuery.trim() || loading}
            className="px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white rounded-xl font-semibold text-xs transition-all shadow-md shadow-cyan-500/20 disabled:opacity-40 flex items-center gap-1.5"
          >
            <Send className="w-4 h-4" />
            Send
          </button>
        </div>
      </div>
    </div>
  );
};
