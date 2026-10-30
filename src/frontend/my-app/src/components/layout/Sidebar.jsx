import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Activity,
  Radio,
  Globe,
  Users,
  UserCheck,
  Search,
  GitMerge,
  Dna,
  Database,
  TrendingUp,
  HelpCircle,
  AlertOctagon,
  Zap,
  FileText,
  Settings,
  Server,
  Cpu,
  Lock,
  Laptop,
  Crosshair
} from 'lucide-react';
import { useSOC } from '../../context/SOCContext';

export const Sidebar = () => {
  const { systemStatus, wsConnected } = useSOC();

  const navSections = [
    {
      title: 'CORE WORKSPACES',
      items: [
        { label: '1. Admin Workspace', path: '/admin-workspace', icon: Lock },
        { label: '2. User Workspace', path: '/user-workspace', icon: Laptop },
        { label: '3. Attacker Workspace', path: '/attacker-workspace', icon: Crosshair }
      ]
    },
    {
      title: 'OVERVIEW',
      items: [
        { label: 'Dashboard', path: '/', icon: LayoutDashboard }
      ]
    },
    {
      title: 'EXTERNAL SECURITY',
      items: [
        { label: 'Network Monitor', path: '/network-monitor', icon: Activity },
        { label: 'Attack Detection', path: '/attack-detection', icon: Radio },
        { label: 'Threat Intelligence', path: '/threat-intelligence', icon: Globe },
        { label: 'Global Threat Radar', path: '/global-threat-radar', icon: Radio }
      ]
    },
    {
      title: 'INSIDER SECURITY',
      items: [
        { label: 'User Behaviour', path: '/user-behaviour', icon: Users },
        { label: 'Insider Threats', path: '/insider-threats', icon: UserCheck },
        { label: 'User Investigation', path: '/user-investigation', icon: Search }
      ]
    },
    {
      title: 'ATTACK SIMULATION LAB',
      items: [
        { label: 'Attack Simulator', path: '/attack-simulator', icon: AlertOctagon },
        { label: 'Scenario Runner', path: '/scenario-runner', icon: GitMerge },
        { label: 'Faculty Demo Mode', path: '/demo-mode', icon: Server }
      ]
    },
    {
      title: 'AI INTELLIGENCE',
      items: [
        { label: 'AI SOC Copilot', path: '/ai-copilot', icon: Cpu },
        { label: 'MITRE ATT&CK Matrix', path: '/mitre-matrix', icon: Shield },
        { label: 'Threat Correlation', path: '/threat-correlation', icon: GitMerge },
        { label: 'Threat DNA', path: '/threat-dna', icon: Dna },
        { label: 'Threat Memory', path: '/threat-memory', icon: Database },
        { label: 'Behaviour Evolution', path: '/behaviour-evolution', icon: TrendingUp },
        { label: 'Explainable AI', path: '/explainable-ai', icon: HelpCircle }
      ]
    },
    {
      title: 'OPERATIONS',
      items: [
        { label: 'Incidents', path: '/incidents', icon: AlertOctagon },
        { label: 'Automated Response', path: '/automated-response', icon: Zap },
        { label: 'Reports', path: '/reports', icon: FileText }
      ]
    },
    {
      title: 'SYSTEM',
      items: [
        { label: 'Settings', path: '/settings', icon: Settings }
      ]
    }
  ];

  return (
    <aside className="w-64 bg-[#0d121f] border-r border-white/5 flex flex-col h-screen fixed left-0 top-0 z-30 select-none">
      {/* Brand Cluster */}
      <div className="p-4 border-b border-white/5 flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold tracking-wider text-base text-white">CASOC</span>
            <span className="text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              v2.4
            </span>
          </div>
          <div className="text-[10px] text-gray-400 leading-tight">
            Cognitive Autonomous<br />Security Operations Center
          </div>
        </div>
      </div>

      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
        {navSections.map((sec) => (
          <div key={sec.title}>
            <div className="px-3 mb-1.5 text-[10px] font-bold tracking-wider text-gray-400 uppercase">
              {sec.title}
            </div>
            <div className="space-y-0.5">
              {sec.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
                        isActive
                          ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                      }`
                    }
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Bottom: SYSTEM STATUS - Directly from Backend Endpoints */}
      <div className="p-3.5 border-t border-white/5 bg-black/20">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-bold tracking-wider text-gray-400 uppercase flex items-center gap-1.5">
            <Server className="w-3 h-3 text-cyan-400" />
            SYSTEM STATUS
          </span>
          <span className="text-[10px] font-mono text-gray-400">
            {wsConnected ? (
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                LIVE
              </span>
            ) : (
              <span className="text-amber-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                POLL
              </span>
            )}
          </span>
        </div>

        <div className="space-y-1.5 text-[11px] font-mono">
          <div className="flex items-center justify-between px-2 py-1 rounded bg-white/[0.02]">
            <span className="text-gray-400 flex items-center gap-1.5">
              <Cpu className="w-3 h-3 text-purple-400" />
              AI Engine
            </span>
            <span className={systemStatus.aiEngine.online ? 'text-emerald-400 font-medium' : 'text-gray-400'}>
              {systemStatus.aiEngine.text}
            </span>
          </div>

          <div className="flex items-center justify-between px-2 py-1 rounded bg-white/[0.02]">
            <span className="text-gray-400 flex items-center gap-1.5">
              <Activity className="w-3 h-3 text-cyan-400" />
              Network Monitor
            </span>
            <span className={systemStatus.networkMonitor.online ? 'text-emerald-400 font-medium' : 'text-gray-400'}>
              {systemStatus.networkMonitor.text}
            </span>
          </div>

          <div className="flex items-center justify-between px-2 py-1 rounded bg-white/[0.02]">
            <span className="text-gray-400 flex items-center gap-1.5">
              <Radio className="w-3 h-3 text-blue-400" />
              ML Service
            </span>
            <span className={systemStatus.mlService.online ? 'text-emerald-400 font-medium' : 'text-gray-400'}>
              {systemStatus.mlService.text}
            </span>
          </div>

          <div className="flex items-center justify-between px-2 py-1 rounded bg-white/[0.02]">
            <span className="text-gray-400 flex items-center gap-1.5">
              <Database className="w-3 h-3 text-amber-400" />
              Database
            </span>
            <span className={systemStatus.database.online ? 'text-emerald-400 font-medium' : 'text-gray-400'}>
              {systemStatus.database.text}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
};
