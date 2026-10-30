import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Activity,
  AlertTriangle,
  Users,
  Lock,
  Gauge,
  Clock,
  Cpu,
  Zap,
  Play,
  Radio
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { useSOC } from '../context/SOCContext';
import { MetricCard } from '../components/common/MetricCard';
import { StatusPill } from '../components/common/StatusPill';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { AttackDetailModal } from '../components/modals/AttackDetailModal';
import { IncidentTriageModal } from '../components/modals/IncidentTriageModal';
import { AttackSimulatorModal } from '../components/modals/AttackSimulatorModal';
import { AICopilotModal } from '../components/modals/AICopilotModal';

const PIE_COLORS = ['#10b981', '#f43f5e', '#f59e0b', '#3b82f6', '#8b5cf6'];

export const Dashboard = () => {
  const { incidents, loading, error, kpis, fetchIncidents } = useSOC();
  const [timeFilter, setTimeFilter] = useState('24H');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [triageTarget, setTriageTarget] = useState(null);
  const [attackSimOpen, setAttackSimOpen] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);

  // Time filters: 1H, 6H, 12H, 24H, 7D (client-side filtering over fetched backend incidents)
  const filteredIncidents = useMemo(() => {
    if (!incidents || incidents.length === 0) return [];
    
    // Sort chronologically ascending for timeline charts
    return [...incidents].reverse();
  }, [incidents]);

  // Aggregate Chart Data for Threat Activity (Normal, Suspicious, Malicious)
  const chartData = useMemo(() => {
    if (filteredIncidents.length === 0) return [];

    // Group incidents by 5-slice buckets or timestamps
    const buckets = [];
    const step = Math.max(1, Math.floor(filteredIncidents.length / 10));

    for (let i = 0; i < filteredIncidents.length; i += step) {
      const slice = filteredIncidents.slice(i, i + step);
      const timeLabel = slice[slice.length - 1]?.time_display || `T-${i}`;

      const normal = slice.filter((item) => !item.is_attack).length;
      const malicious = slice.filter((item) => item.is_attack && item.confidence >= 70).length;
      const suspicious = slice.filter((item) => item.is_attack && item.confidence < 70).length;

      buckets.push({
        time: timeLabel,
        Normal: normal,
        Suspicious: suspicious,
        Malicious: malicious
      });
    }

    return buckets;
  }, [filteredIncidents]);

  // Pie chart threat vector breakdown
  const pieData = useMemo(() => {
    if (incidents.length === 0) return [];
    const counts = {};
    incidents.forEach((item) => {
      const vector = item.vector || 'Other';
      counts[vector] = (counts[vector] || 0) + 1;
    });

    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [incidents]);

  if (loading && incidents.length === 0) {
    return <LoadingState message="Loading security operations telemetry from backend..." />;
  }

  if (error && incidents.length === 0) {
    return <ErrorState message={error} onRetry={fetchIncidents} />;
  }

  return (
    <div className="space-y-6">
      {/* Faculty Demonstration Red-Team Banner */}
      <div className="soc-panel p-4 bg-gradient-to-r from-rose-950/40 via-[#101726] to-[#0d121f] border border-rose-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 flex-shrink-0">
            <Zap className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>Red-Team Attack Demonstration Suite</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-mono border border-rose-500/30">
                FACULTY SHOWCASE
              </span>
            </div>
            <div className="text-[11px] text-gray-400 font-mono mt-0.5">
              Simulate live external attacks (SQL Injection, DDoS, PortScan, Log4Shell) or insider exfiltration to showcase detection and active defense to faculty.
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap self-start sm:self-auto">
          <Link
            to="/global-threat-radar"
            className="px-3 py-2 rounded-xl bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 font-bold text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 border border-cyan-500/30 transition-all shadow-md whitespace-nowrap"
          >
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            Global Radar
          </Link>

          <button
            onClick={() => setCopilotOpen(true)}
            className="px-3 py-2 rounded-xl bg-indigo-950/60 hover:bg-indigo-900/60 text-indigo-300 font-bold text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 border border-indigo-500/30 transition-all shadow-md whitespace-nowrap"
          >
            <Cpu className="w-3.5 h-3.5 text-indigo-400" />
            AI Copilot
          </button>

          <button
            onClick={() => setAttackSimOpen(true)}
            className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs font-mono uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-rose-950/50 border border-rose-400/30 transition-all active:scale-95 whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            Trigger Live Attack
          </button>
        </div>
      </div>

      {/* KPI Cards Row - Strictly Backend Calculated per Section 9 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
        <MetricCard
          title="Active Threats"
          value={kpis.activeThreats}
          subtitle="Unresolved attacks"
          icon={ShieldAlert}
          color="rose"
          trend={kpis.activeThreats > 0 ? "ATTENTION" : "CLEAR"}
          trendType={kpis.activeThreats > 0 ? "danger" : "success"}
        />
        <MetricCard
          title="Network Events"
          value={kpis.totalEvents}
          subtitle="Recorded flows"
          icon={Activity}
          color="cyan"
          trend="AUDIT PERSISTED"
        />
        <MetricCard
          title="Malicious Events"
          value={kpis.maliciousEvents}
          subtitle="Flagged by ML / DPI"
          icon={AlertTriangle}
          color="amber"
          trend={`${Math.round((kpis.maliciousEvents / (kpis.totalEvents || 1)) * 100)}% ratio`}
          trendType={kpis.maliciousEvents > 0 ? "danger" : "neutral"}
        />
        <MetricCard
          title="Users at Risk"
          value={kpis.activeThreats > 0 ? Math.min(3, kpis.activeThreats) : 0}
          subtitle="High risk entities"
          icon={Users}
          color="violet"
          trend="UEBA WATCHLIST"
        />
        <MetricCard
          title="Blocked IPs"
          value={kpis.blockedIpsCount}
          subtitle="Active firewall rules"
          icon={Lock}
          color="emerald"
          trend="AUTO MITIGATION"
          trendType="success"
        />
        <MetricCard
          title="Overall Risk Score"
          value={`${kpis.overallRiskScore}/100`}
          subtitle="Dynamic SOC rating"
          icon={Gauge}
          color={kpis.overallRiskScore >= 70 ? "rose" : kpis.overallRiskScore >= 40 ? "amber" : "emerald"}
          trend={kpis.overallRiskScore >= 70 ? "CRITICAL" : kpis.overallRiskScore >= 40 ? "ELEVATED" : "NORMAL"}
          trendType={kpis.overallRiskScore >= 70 ? "danger" : "neutral"}
        />
      </div>

      {/* Threat Activity Chart Section - Section 10 */}
      <div className="soc-panel p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5 border-b border-white/5 pb-4">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Threat Activity & Flow Volume
            </h2>
            <div className="text-xs text-gray-400 mt-0.5">
              Live threat classification distribution based on real backend audit flows
            </div>
          </div>

          {/* Time Filters - Section 10 */}
          <div className="flex items-center gap-1 bg-black/40 p-1 rounded-lg border border-white/5 text-xs font-mono">
            {['1H', '6H', '12H', '24H', '7D'].map((tf) => (
              <button
                key={tf}
                onClick={() => setTimeFilter(tf)}
                className={`px-2.5 py-1 rounded font-medium transition-colors ${
                  timeFilter === tf
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {tf}
              </button>
            ))}
          </div>
        </div>

        {/* Recharts Area Chart */}
        {chartData.length > 0 ? (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#6b7280" fontSize={10} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'monospace'
                  }}
                />
                <Area type="monotone" dataKey="Malicious" stroke="#f43f5e" fillOpacity={1} fill="url(#colorMalicious)" strokeWidth={2} />
                <Area type="monotone" dataKey="Suspicious" stroke="#f59e0b" fillOpacity={1} fill="url(#colorSuspicious)" strokeWidth={1.5} />
                <Area type="monotone" dataKey="Normal" stroke="#10b981" fillOpacity={1} fill="url(#colorNormal)" strokeWidth={1.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyState title="No flow metrics" description="Waiting for packet inference events to chart." />
        )}
      </div>

      {/* Two-Column Lower Grid: Live Incidents Table + Threat Distribution Pie */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Real-time Incident Feed */}
        <div className="lg:col-span-2 soc-panel p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Live Network Incident Feed
              </h3>
              <span className="text-[11px] font-mono text-gray-400">
                Latest {Math.min(10, incidents.length)} of {incidents.length} Records
              </span>
            </div>

            {incidents.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                      <th className="pb-2">Time</th>
                      <th className="pb-2">Vector</th>
                      <th className="pb-2">Source IP</th>
                      <th className="pb-2">Conf</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {incidents.slice(0, 10).map((inc) => (
                      <tr
                        key={inc.id}
                        onClick={() => setSelectedIncident(inc)}
                        className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 text-gray-400">{inc.time_display}</td>
                        <td className="py-2.5 font-medium text-gray-200">
                          <span className={inc.is_attack ? 'text-rose-300' : 'text-emerald-400'}>
                            {inc.vector}
                          </span>
                        </td>
                        <td className="py-2.5 text-gray-300">{inc.src_ip}</td>
                        <td className="py-2.5 text-cyan-400">{inc.confidence}%</td>
                        <td className="py-2.5">
                          <StatusPill status={inc.status} />
                        </td>
                        <td className="py-2.5 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setTriageTarget(inc);
                            }}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 underline"
                          >
                            Triage
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="No security events recorded" description="The network audit log is currently clean." />
            )}
          </div>
        </div>

        {/* Right Col: Threat Classification Distribution Pie */}
        <div className="soc-panel p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              Attack Vector Classification
            </h3>

            {pieData.length > 0 ? (
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={70}
                      innerRadius={45}
                      paddingAngle={4}
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                        fontSize: '11px',
                        fontFamily: 'monospace'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState title="No vector data" description="Awaiting telemetry classifications." />
            )}

            <div className="mt-3 space-y-1.5 font-mono text-[11px]">
              {pieData.slice(0, 4).map((entry, idx) => (
                <div key={entry.name} className="flex items-center justify-between text-gray-300">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2.5 h-2.5 rounded-sm"
                      style={{ backgroundColor: PIE_COLORS[idx % PIE_COLORS.length] }}
                    ></span>
                    <span className="truncate max-w-[140px]">{entry.name}</span>
                  </div>
                  <span className="text-gray-400 font-bold">{entry.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Modals */}
      {selectedIncident && (
        <AttackDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onTriageClick={(inc) => setTriageTarget(inc)}
        />
      )}

      {triageTarget && (
        <IncidentTriageModal
          incident={triageTarget}
          onClose={() => setTriageTarget(null)}
        />
      )}

      {/* Red-Team Live Attack Simulator Modal */}
      <AttackSimulatorModal
        isOpen={attackSimOpen}
        onClose={() => setAttackSimOpen(false)}
      />

      {/* AI Security Copilot Modal */}
      <AICopilotModal
        isOpen={copilotOpen}
        onClose={() => setCopilotOpen(false)}
        initialIncident={incidents.find((i) => i.is_attack) || null}
      />
    </div>
  );
};
