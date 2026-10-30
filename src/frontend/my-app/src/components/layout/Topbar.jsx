import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Search,
  Bell,
  RefreshCw,
  User,
  Wifi,
  WifiOff,
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Settings,
  X,
  Radio,
  ExternalLink,
  Zap,
  Cpu
} from 'lucide-react';
import { useSOC } from '../../context/SOCContext';
import { useAuth } from '../../context/AuthContext';
import { socketService } from '../../services/socketService';
import { NIDS_BASE_URL } from '../../services/apiClient';
import { AttackSimulatorModal } from '../modals/AttackSimulatorModal';
import { AICopilotModal } from '../modals/AICopilotModal';

export const Topbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const {
    incidents,
    kpis,
    wsConnected,
    fetchIncidents,
    fetchDefenseStatus,
    fetchSystemStatus,
    setSelectedIncident,
    loading
  } = useSOC();
  const { user, switchRole } = useAuth();

  // Interactive UI Dropdown states
  const [searchQuery, setSearchQuery] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const [bellOpen, setBellOpen] = useState(false);
  const [wsModalOpen, setWsModalOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [refreshSuccess, setRefreshSuccess] = useState(false);
  const [attackModalOpen, setAttackModalOpen] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);

  // Refs for outside-click detection
  const searchRef = useRef(null);
  const bellRef = useRef(null);
  const wsRef = useRef(null);
  const profileRef = useRef(null);

  // Close menus when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (searchRef.current && !searchRef.current.contains(e.target)) {
        setSearchOpen(false);
      }
      if (bellRef.current && !bellRef.current.contains(e.target)) {
        setBellOpen(false);
      }
      if (wsRef.current && !wsRef.current.contains(e.target)) {
        setWsModalOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(e.target)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Compute Page Title from route
  const getPageTitle = (path) => {
    switch (path) {
      case '/':
        return 'Security Operations Center';
      case '/network-monitor':
        return 'Network Telemetry & Live Packet Monitor';
      case '/attack-detection':
        return 'External Attack Detection';
      case '/threat-intelligence':
        return 'Threat Intelligence & Blacklist Management';
      case '/user-behaviour':
        return 'User Behaviour Entity Analytics (UEBA)';
      case '/insider-threats':
        return 'Insider Threat Detection & Ingestion Engine';
      case '/user-investigation':
        return 'Forensic User Activity Investigation';
      case '/threat-correlation':
        return 'Threat Correlation & Attack Reconstruction';
      case '/threat-dna':
        return 'Threat DNA & Behavioral Fingerprints';
      case '/threat-memory':
        return 'Threat Memory & Historical Signature Index';
      case '/behaviour-evolution':
        return 'User Behaviour Evolution & Deviation Trends';
      case '/explainable-ai':
        return 'Explainable AI (XAI) & Feature Attributions';
      case '/incidents':
        return 'Incident Management & Triage Center';
      case '/automated-response':
        return 'Automated Response & Firewall Actions';
      case '/reports':
        return 'Security Reports & Forensic Exports';
      case '/settings':
        return 'SOC System Thresholds & Configuration';
      default:
        return 'Security Operations Center';
    }
  };

  // Handle comprehensive SOC refresh
  const handleRefresh = async () => {
    try {
      await Promise.all([
        fetchIncidents(),
        fetchDefenseStatus?.(),
        fetchSystemStatus?.()
      ]);
      setRefreshSuccess(true);
      setTimeout(() => setRefreshSuccess(false), 2000);
    } catch (e) {
      console.error('Refresh error:', e);
    }
  };

  // Filtered search results
  const q = searchQuery.toLowerCase().trim();
  const matchedIncidents = q
    ? incidents.filter(
        (i) =>
          (i.src_ip && i.src_ip.toLowerCase().includes(q)) ||
          (i.dst_ip && i.dst_ip.toLowerCase().includes(q)) ||
          (i.vector && i.vector.toLowerCase().includes(q))
      ).slice(0, 4)
    : [];

  const matchedUsers = q
    ? Array.from(
        new Set(
          incidents
            .map((i) => i.username || i.user_id)
            .filter(Boolean)
        )
      ).filter((u) => u.toLowerCase().includes(q))
    : [];

  const ALL_VIEWS = [
    { name: 'Dashboard Overview', path: '/' },
    { name: 'Network Telemetry & Sniffer', path: '/network-monitor' },
    { name: 'External Attack Detection', path: '/attack-detection' },
    { name: 'Threat Intelligence Blacklist', path: '/threat-intelligence' },
    { name: 'User Behaviour Analytics (UEBA)', path: '/user-behaviour' },
    { name: 'Insider Threat Ingest Engine', path: '/insider-threats' },
    { name: 'User Activity Investigation', path: '/user-investigation' },
    { name: 'Threat Correlation & Reconstruction', path: '/threat-correlation' },
    { name: 'Threat DNA Fingerprints', path: '/threat-dna' },
    { name: 'Threat Memory & Signatures', path: '/threat-memory' },
    { name: 'Behaviour Evolution Trends', path: '/behaviour-evolution' },
    { name: 'Explainable AI (XAI)', path: '/explainable-ai' },
    { name: 'Incident Triage Center', path: '/incidents' },
    { name: 'Automated Response & Firewall', path: '/automated-response' },
    { name: 'Security Reports & Exports', path: '/reports' },
    { name: 'SOC Settings & Thresholds', path: '/settings' }
  ];
  const matchedViews = q
    ? ALL_VIEWS.filter((v) => v.name.toLowerCase().includes(q)).slice(0, 4)
    : [];

  // Active threats for the Notification Flyout
  const activeAlerts = incidents
    .filter((i) => i.is_attack && (i.status === 'NEW' || i.status === 'INVESTIGATING'))
    .slice(0, 6);

  return (
    <header className="h-16 bg-[#0d121f]/90 backdrop-blur-md border-b border-white/5 px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Page Title & Subtitle */}
      <div>
        <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
          {getPageTitle(location.pathname)}
        </h1>
        <div className="text-[11px] text-gray-400 font-mono">
          Real-time monitoring &bull; AI-driven threat detection
        </div>
      </div>

      {/* Center / Right Tools */}
      <div className="flex items-center gap-4">
        {/* Global Search with Live Palette */}
        <div className="relative w-64" ref={searchRef}>
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onFocus={() => setSearchOpen(true)}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setSearchOpen(true);
            }}
            placeholder="Search IPs, threats, users..."
            className="w-full bg-[#131c2e] border border-white/5 rounded-lg pl-9 pr-7 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 transition-colors font-mono"
          />
          {searchQuery && (
            <button
              onClick={() => {
                setSearchQuery('');
                setSearchOpen(false);
              }}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Search Dropdown Palette */}
          {searchOpen && searchQuery.trim().length > 0 && (
            <div className="absolute left-0 right-0 top-full mt-2 bg-[#0f172a] border border-cyan-500/30 rounded-xl shadow-2xl p-3 z-50 space-y-3 font-mono text-xs max-h-96 overflow-y-auto">
              {matchedIncidents.length === 0 &&
                matchedUsers.length === 0 &&
                matchedViews.length === 0 && (
                  <div className="text-center py-4 text-gray-400 text-xs">
                    No matching IPs, users, or views found.
                  </div>
                )}

              {/* Incidents / Threats Results */}
              {matchedIncidents.length > 0 && (
                <div>
                  <div className="text-[10px] font-bold uppercase text-cyan-400 mb-1 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" />
                    Security Incidents ({matchedIncidents.length})
                  </div>
                  <div className="space-y-1">
                    {matchedIncidents.map((inc) => (
                      <div
                        key={inc.id}
                        onClick={() => {
                          setSelectedIncident(inc);
                          setSearchOpen(false);
                          navigate('/incidents');
                        }}
                        className="p-2 rounded bg-white/5 hover:bg-cyan-500/10 cursor-pointer flex items-center justify-between border border-transparent hover:border-cyan-500/30 transition-all"
                      >
                        <div>
                          <div className="font-bold text-white text-[11px]">{inc.vector}</div>
                          <div className="text-[10px] text-gray-400">
                            {inc.src_ip} &rarr; {inc.dst_ip}
                          </div>
                        </div>
                        <span
                          className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
                            inc.is_attack
                              ? 'bg-rose-500/20 text-rose-400'
                              : 'bg-emerald-500/20 text-emerald-400'
                          }`}
                        >
                          {inc.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Users Results */}
              {matchedUsers.length > 0 && (
                <div>
                  <div className="text-[10px] font-bold uppercase text-purple-400 mb-1 flex items-center gap-1">
                    <User className="w-3 h-3" />
                    Employee / User Profiles ({matchedUsers.length})
                  </div>
                  <div className="space-y-1">
                    {matchedUsers.map((u) => (
                      <div
                        key={u}
                        onClick={() => {
                          setSearchOpen(false);
                          navigate('/user-investigation');
                        }}
                        className="p-2 rounded bg-white/5 hover:bg-purple-500/10 cursor-pointer flex items-center justify-between border border-transparent hover:border-purple-500/30 transition-all"
                      >
                        <span className="font-bold text-gray-200">{u}</span>
                        <span className="text-[9px] text-purple-400 flex items-center gap-1">
                          Investigate <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Navigation Quick Jump */}
              {matchedViews.length > 0 && (
                <div>
                  <div className="text-[10px] font-bold uppercase text-indigo-400 mb-1 flex items-center gap-1">
                    <ExternalLink className="w-3 h-3" />
                    SOC System Views
                  </div>
                  <div className="space-y-1">
                    {matchedViews.map((v) => (
                      <div
                        key={v.path}
                        onClick={() => {
                          setSearchOpen(false);
                          navigate(v.path);
                        }}
                        className="p-1.5 rounded hover:bg-white/10 cursor-pointer flex items-center justify-between text-gray-300 hover:text-white"
                      >
                        <span>{v.name}</span>
                        <ChevronRight className="w-3 h-3 text-gray-500" />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Live Refresh Button */}
        <button
          onClick={handleRefresh}
          disabled={loading}
          title="Refresh All Backend Incidents & Health Status"
          className="relative p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 border border-white/5 transition-colors"
        >
          <RefreshCw
            className={`w-4 h-4 ${
              loading ? 'animate-spin text-cyan-400' : refreshSuccess ? 'text-emerald-400' : ''
            }`}
          />
          {refreshSuccess && (
            <span className="absolute -bottom-7 right-0 text-[10px] bg-emerald-500 text-black font-bold px-1.5 py-0.5 rounded shadow whitespace-nowrap">
              Synced!
            </span>
          )}
        </button>

        {/* Red-Team Live Attack Simulator Button */}
        <button
          onClick={() => setAttackModalOpen(true)}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-gradient-to-r from-rose-600/30 via-red-600/20 to-rose-600/30 hover:from-rose-600/50 hover:to-red-600/40 text-rose-300 hover:text-white border border-rose-500/40 hover:border-rose-400 text-xs font-bold font-mono transition-all shadow-md shadow-rose-950/40 group active:scale-95"
          title="Trigger Red-Team Live Attack In Front of Faculty"
        >
          <Zap className="w-3.5 h-3.5 text-rose-400 group-hover:animate-pulse" />
          <span className="hidden sm:inline">Simulate Attack</span>
        </button>

        {/* AI SOC Copilot Launcher Button */}
        <button
          onClick={() => setCopilotOpen(true)}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600/30 via-indigo-600/20 to-cyan-600/30 hover:from-cyan-600/50 hover:to-indigo-600/40 text-cyan-300 hover:text-white border border-cyan-500/40 hover:border-cyan-400 text-xs font-bold font-mono transition-all shadow-md shadow-cyan-950/40 group active:scale-95"
          title="Open AI SOC Copilot & SOAR Playbook Assistant"
        >
          <Cpu className="w-3.5 h-3.5 text-cyan-400 group-hover:animate-pulse" />
          <span className="hidden sm:inline">AI Copilot</span>
        </button>

        {/* WebSocket / Stream Health Indicator Popover */}
        <div className="relative" ref={wsRef}>
          <button
            onClick={() => setWsModalOpen(!wsModalOpen)}
            title="Click for WebSocket Stream Diagnostics"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-black/30 hover:bg-black/50 border border-white/5 hover:border-white/20 text-[11px] font-mono transition-all"
          >
            {wsConnected ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                <span className="text-emerald-400 font-medium">Socket.IO Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-amber-400 font-medium">Polling Mode</span>
              </>
            )}
          </button>

          {wsModalOpen && (
            <div className="absolute right-0 top-full mt-2 w-72 bg-[#0f172a] border border-cyan-500/30 rounded-xl shadow-2xl p-4 z-50 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <div className="font-bold text-white flex items-center gap-2">
                  <Radio className="w-4 h-4 text-cyan-400" />
                  Stream Diagnostics
                </div>
                <button
                  onClick={() => setWsModalOpen(false)}
                  className="text-gray-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-2 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-gray-400">Stream Status:</span>
                  <span className={`font-bold ${wsConnected ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {wsConnected ? 'Connected & Streaming' : 'Polling Standby'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Target Server:</span>
                  <span className="text-gray-200">{NIDS_BASE_URL}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Transport:</span>
                  <span className="text-gray-200">{wsConnected ? 'websocket / polling' : 'http'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Active Listeners:</span>
                  <span className="text-gray-200">new_threat_event</span>
                </div>
              </div>

              <button
                onClick={() => {
                  socketService.disconnect();
                  setTimeout(() => socketService.connect(), 300);
                  setWsModalOpen(false);
                }}
                className="w-full py-1.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/40 text-center font-bold text-[11px] transition-all"
              >
                Force Stream Reconnect
              </button>
            </div>
          )}
        </div>

        {/* Active Threats Counter Notification Bell with Dropdown */}
        <div className="relative" ref={bellRef}>
          <button
            onClick={() => setBellOpen(!bellOpen)}
            title="Active Threat Alerts"
            className="p-2 rounded-lg text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/5 transition-all relative"
          >
            <Bell className="w-4 h-4" />
            {kpis.activeThreats > 0 && (
              <span className="absolute -top-1 -right-1 min-w-4 h-4 px-1 rounded-full bg-rose-500 text-[10px] font-bold text-white flex items-center justify-center font-mono animate-pulse">
                {kpis.activeThreats}
              </span>
            )}
          </button>

          {bellOpen && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-[#0f172a] border border-rose-500/30 rounded-xl shadow-2xl p-4 z-50 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <div className="font-bold text-white flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  Active Threats ({kpis.activeThreats})
                </div>
                <button
                  onClick={() => setBellOpen(false)}
                  className="text-gray-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              {activeAlerts.length === 0 ? (
                <div className="text-center py-6 text-gray-400">
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
                  No active critical threats right now.
                </div>
              ) : (
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {activeAlerts.map((alt) => (
                    <div
                      key={alt.id}
                      onClick={() => {
                        setSelectedIncident(alt);
                        setBellOpen(false);
                        navigate('/incidents');
                      }}
                      className="p-2.5 rounded-lg bg-white/5 hover:bg-rose-500/10 border border-white/5 hover:border-rose-500/30 cursor-pointer transition-all"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-rose-400 text-[11px]">{alt.vector}</span>
                        <span className="text-[9px] text-gray-400">
                          {alt.time_display || new Date(alt.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-300">
                        {alt.src_ip} &rarr; {alt.dst_ip}
                      </div>
                      <div className="text-[9px] text-gray-400 mt-1 flex justify-between">
                        <span>Confidence: {Math.round(alt.confidence)}%</span>
                        <span className="text-cyan-400 underline">Triage Incident &rarr;</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <button
                onClick={() => {
                  setBellOpen(false);
                  navigate('/incidents');
                }}
                className="w-full py-1.5 rounded bg-white/5 hover:bg-white/10 text-gray-200 border border-white/10 text-center font-bold text-[11px] transition-all"
              >
                View All Incidents
              </button>
            </div>
          )}
        </div>

        {/* User Profile & Role Switcher Dropdown */}
        <div className="relative pl-2 border-l border-white/10" ref={profileRef}>
          <button
            onClick={() => setProfileOpen(!profileOpen)}
            className="flex items-center gap-3 text-left group focus:outline-none"
          >
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white text-xs font-bold shadow-md shadow-cyan-500/20 group-hover:scale-105 transition-transform">
              <User className="w-4 h-4" />
            </div>
            <div className="hidden md:block">
              <div className="text-xs font-semibold text-gray-200 group-hover:text-white transition-colors">
                {user.name}
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-mono text-cyan-400 font-semibold">
                  {user.role}
                </span>
                <span className="text-[9px] text-gray-400 font-mono">(menu)</span>
              </div>
            </div>
          </button>

          {profileOpen && (
            <div className="absolute right-0 top-full mt-2 w-64 bg-[#0f172a] border border-cyan-500/30 rounded-xl shadow-2xl p-4 z-50 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <div className="font-bold text-white flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" />
                  Operator Credentials
                </div>
                <button
                  onClick={() => setProfileOpen(false)}
                  className="text-gray-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-1.5 text-[11px]">
                <div className="text-white font-bold">{user.name}</div>
                <div className="text-gray-400">{user.email}</div>
                <div className="text-cyan-400 text-[10px]">CLEARANCE: TOP SECRET // LEVEL 4</div>
              </div>

              <div className="p-2.5 rounded bg-black/40 border border-white/5 space-y-1.5">
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Current Privilege:</span>
                  <span className="font-bold text-cyan-400">{user.role}</span>
                </div>
                <div className="text-[10px] text-gray-500">
                  {user.role === 'ADMIN'
                    ? 'Full write access: Active mitigation, IPTables blocking, rule authoring.'
                    : 'Read-only analyst access: Investigation, forensics, and alert review.'}
                </div>
                <button
                  onClick={() => {
                    switchRole();
                  }}
                  className="w-full mt-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/40 text-center font-bold text-[10px] transition-all"
                >
                  Switch to {user.role === 'ADMIN' ? 'ANALYST' : 'ADMIN'}
                </button>
              </div>

              <div className="pt-2 border-t border-white/10 space-y-1">
                <button
                  onClick={() => {
                    setProfileOpen(false);
                    navigate('/settings');
                  }}
                  className="w-full flex items-center justify-between p-1.5 rounded hover:bg-white/5 text-gray-300 hover:text-white transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <Settings className="w-3.5 h-3.5 text-gray-400" />
                    SOC Settings & Thresholds
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Red-Team Live Attack Simulator Modal */}
      <AttackSimulatorModal
        isOpen={attackModalOpen}
        onClose={() => setAttackModalOpen(false)}
      />

      {/* AI Security Copilot & SOAR Playbook Modal */}
      <AICopilotModal
        isOpen={copilotOpen}
        onClose={() => setCopilotOpen(false)}
        initialIncident={incidents.find((i) => i.is_attack) || null}
      />
    </header>
  );
};
