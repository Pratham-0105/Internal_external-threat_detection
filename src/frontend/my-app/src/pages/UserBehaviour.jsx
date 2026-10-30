import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Users, 
  ShieldAlert, 
  Zap, 
  Search, 
  RefreshCw, 
  Filter,
  CheckCircle2,
  Radio,
  Play,
  Square,
  Flame,
  AlertTriangle
} from 'lucide-react';
import { insiderService } from '../services/insiderService';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { Link, useNavigate } from 'react-router-dom';

const SIMULATION_ACTIONS = [
  {
    label: 'After-Hours Logon',
    type: 'LOGON',
    activity: 'Logon',
    details: '{"workstation":"WS-FIN-09","logon_time":"03:22:15","status":"Success","anomaly":"Logon outside baseline shift hours"}'
  },
  {
    label: 'Mass File Exfiltration',
    type: 'FILE',
    activity: 'Bulk_Download',
    details: '{"file_path":"/confidential/q3_merger_financials.enc","bytes":48920194,"anomaly":"Mass sensitive archive download"}'
  },
  {
    label: 'Rogue USB Insertion',
    type: 'DEVICE',
    activity: 'Connect',
    details: '{"vendor_id":"SanDisk_Ultra_USB3","serial":"SN-9948201","device_type":"Removable_Storage","anomaly":"Unregistered mass storage drive"}'
  },
  {
    label: 'Normal Business Activity',
    type: 'HTTP',
    activity: 'Browse_Intranet',
    details: '{"url":"https://intranet.corp.local/hr/policies","status":"200","anomaly":"None - Standard compliant activity"}'
  }
];

export const UserBehaviour = () => {
  const navigate = useNavigate();
  const { triggerThreatNotification } = useSOC();

  // Active View Tab: 'stream' (Real-time Appended Events) | 'profiles' (1,001 Trained Baselines)
  const [activeTab, setActiveTab] = useState('stream');

  // Live Stream & Polling State
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [isAutoGenerating, setIsAutoGenerating] = useState(false);
  const autoGenIntervalRef = useRef(null);

  // Data State
  const [recentEvents, setRecentEvents] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [lastSyncTime, setLastSyncTime] = useState(new Date());

  // Aggregate Stats
  const [stats, setStats] = useState({
    totalUsers: 0,
    totalEvents: 0,
    anomalousEvents: 0,
    totalAlerts: 0,
    criticalUsers: 0,
    highUsers: 0,
    mediumUsers: 0,
    lowUsers: 0
  });

  // Fetch real-time events and stats
  const fetchLiveTelemetry = useCallback(async () => {
    try {
      const [evRes, statsRes] = await Promise.allSettled([
        insiderService.getEvents({ limit: 50 }),
        insiderService.getStats()
      ]);

      if (evRes.status === 'fulfilled' && evRes.value?.status === 'success') {
        setRecentEvents(evRes.value.events || []);
      }

      if (statsRes.status === 'fulfilled' && statsRes.value?.status === 'success') {
        setStats({
          totalUsers: statsRes.value.total_users || 0,
          totalEvents: statsRes.value.total_events || 0,
          anomalousEvents: statsRes.value.anomalous_events || 0,
          totalAlerts: statsRes.value.total_alerts || 0,
          criticalUsers: statsRes.value.critical_users || 0,
          highUsers: statsRes.value.high_users || 0,
          mediumUsers: statsRes.value.medium_users || 0,
          lowUsers: statsRes.value.low_users || 0
        });
      }

      setLastSyncTime(new Date());
      setError(null);
    } catch (err) {
      console.error('Failed to fetch live telemetry:', err);
    }
  }, []);

  // Fetch monitored entity profiles
  const fetchUsers = useCallback(async () => {
    try {
      const data = await insiderService.getUsers({
        search: searchTerm,
        risk_level: riskFilter,
        limit: 50
      });

      if (data && data.status === 'success') {
        setUsers(data.users || []);
      }
    } catch (err) {
      console.error('Failed to fetch user profiles:', err);
    }
  }, [searchTerm, riskFilter]);

  // Initial Load
  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await Promise.all([fetchLiveTelemetry(), fetchUsers()]);
      setLoading(false);
    };
    init();
  }, [fetchLiveTelemetry, fetchUsers]);

  // Real-time Polling Interval (every 2.5 seconds when streaming is ON)
  useEffect(() => {
    if (!isLiveStreaming) return;
    const interval = setInterval(() => {
      fetchLiveTelemetry();
      if (activeTab === 'profiles') {
        fetchUsers();
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [isLiveStreaming, fetchLiveTelemetry, fetchUsers, activeTab]);

  // Quick Ingest Action
  const handleInjectAction = useCallback(async (actionPreset) => {
    try {
      // Pick a random user from current loaded users or fallback
      const targetUser = users.length > 0 
        ? users[Math.floor(Math.random() * Math.min(users.length, 10))] 
        : { user_id: 'MOH0273', full_name: 'Macaulay Otto Hopkins', department: 'Corporate Staff' };

      const payload = {
        user: targetUser.user_id,
        user_id: targetUser.user_id,
        username: targetUser.full_name,
        department: targetUser.department,
        event_type: actionPreset.type,
        activity: actionPreset.activity,
        timestamp: new Date().toISOString(),
        details: actionPreset.details
      };

      const res = await insiderService.ingestEvent(payload);

      if (res.alert_generated) {
        triggerThreatNotification({
          title: `🚨 BEHAVIOURAL ANOMALY DETECTED: ${targetUser.user_id}`,
          vector: actionPreset.label,
          target: `${targetUser.user_id} (${targetUser.full_name})`,
          action: 'UEBA Isolation Forest Quarantine',
          confidence: Math.round((res.risk_score || 0.9) * 100)
        });
      }

      // Immediately refresh live feed
      await fetchLiveTelemetry();
      if (activeTab === 'profiles') {
        await fetchUsers();
      }
    } catch (err) {
      console.error('Failed to inject activity:', err);
    }
  }, [users, fetchLiveTelemetry, fetchUsers, activeTab, triggerThreatNotification]);

  // Continuous Auto-Stream Toggle
  useEffect(() => {
    if (isAutoGenerating) {
      autoGenIntervalRef.current = setInterval(() => {
        const randomPreset = SIMULATION_ACTIONS[Math.floor(Math.random() * SIMULATION_ACTIONS.length)];
        handleInjectAction(randomPreset);
      }, 4000);
    } else {
      if (autoGenIntervalRef.current) {
        clearInterval(autoGenIntervalRef.current);
      }
    }

    return () => {
      if (autoGenIntervalRef.current) clearInterval(autoGenIntervalRef.current);
    };
  }, [isAutoGenerating, handleInjectAction]);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="soc-panel p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
              CERT R4.2 UEBA ENGINE :5001
            </span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1.5 ${
              isLiveStreaming 
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' 
                : 'bg-white/5 text-gray-400 border-white/10'
            }`}>
              <span className={`w-2 h-2 rounded-full ${isLiveStreaming ? 'bg-emerald-400 animate-ping' : 'bg-gray-500'}`} />
              {isLiveStreaming ? 'REAL-TIME TELEMETRY STREAM ACTIVE' : 'STREAM PAUSED'}
            </span>
          </div>
          <h1 className="text-xl font-black tracking-tight text-white mt-1 flex items-center gap-2">
            <Users className="w-5 h-5 text-purple-400" />
            User & Entity Behaviour Analytics (UEBA)
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time behavioral telemetry dynamically evaluated by Isolation Forest ML and appended live to SQLite.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all ${
              isLiveStreaming 
                ? 'bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 border border-emerald-500/40' 
                : 'bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>{isLiveStreaming ? 'Polling Live (2.5s)' : 'Resume Live'}</span>
          </button>

          <button
            onClick={() => setIsAutoGenerating(!isAutoGenerating)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all ${
              isAutoGenerating 
                ? 'bg-rose-600 text-white shadow-md shadow-rose-900/50 animate-pulse' 
                : 'bg-purple-600/30 hover:bg-purple-600/50 text-purple-300 border border-purple-500/40'
            }`}
            title="Automatically streams realistic employee actions every 4 seconds"
          >
            {isAutoGenerating ? <Square className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isAutoGenerating ? 'Stop Auto-Stream' : '▶ Continuous Auto-Stream'}</span>
          </button>

          <button
            onClick={() => { fetchLiveTelemetry(); fetchUsers(); }}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 transition-colors"
            title="Refresh immediately"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <Link
            to="/attacker-workspace"
            className="px-3 py-1.5 rounded-lg bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 hover:text-white border border-rose-500/40 font-mono text-xs font-bold flex items-center gap-1.5 transition-all"
          >
            <Zap className="w-3.5 h-3.5 text-rose-400" />
            Attacker Workspace &rarr;
          </Link>
        </div>
      </div>

      {error && <ErrorState message={error} onRetry={fetchLiveTelemetry} />}

      {/* Real-Time KPI Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
        <div className="bg-[#0b101d] border border-cyan-500/20 rounded-xl p-4 relative overflow-hidden">
          <span className="text-[10px] font-bold text-gray-400 uppercase flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-cyan-400" /> Live Appended Events
          </span>
          <div className="text-2xl font-bold text-cyan-400 mt-1 flex items-baseline gap-2">
            <span>{stats.totalEvents}</span>
            <span className="text-[11px] text-cyan-300/70 font-normal">in SQLite</span>
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">Streamed in real-time</div>
        </div>

        <div className="bg-[#0b101d] border border-rose-500/20 rounded-xl p-4 relative overflow-hidden">
          <span className="text-[10px] font-bold text-gray-400 uppercase flex items-center gap-1.5">
            <Flame className="w-3.5 h-3.5 text-rose-400" /> Anomalies Detected
          </span>
          <div className="text-2xl font-bold text-rose-400 mt-1 flex items-baseline gap-2">
            <span>{stats.anomalousEvents}</span>
            <span className="text-[11px] text-rose-300/70 font-normal">({stats.totalAlerts} alerts)</span>
          </div>
          <div className="text-[10px] text-rose-400/80 mt-0.5">Flagged by Isolation Forest</div>
        </div>

        <div className="bg-[#0b101d] border border-amber-500/20 rounded-xl p-4 relative overflow-hidden">
          <span className="text-[10px] font-bold text-gray-400 uppercase flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Elevated Risk Profiles
          </span>
          <div className="text-2xl font-bold text-amber-400 mt-1 flex items-baseline gap-2">
            <span>{stats.criticalUsers + stats.highUsers}</span>
            <span className="text-[11px] text-amber-300/70 font-normal">Critical/High</span>
          </div>
          <div className="text-[10px] text-amber-400/80 mt-0.5">Under continuous containment</div>
        </div>

        <div className="bg-[#0b101d] border border-purple-500/20 rounded-xl p-4 relative overflow-hidden">
          <span className="text-[10px] font-bold text-gray-400 uppercase flex items-center gap-1.5">
            <Users className="w-3.5 h-3.5 text-purple-400" /> Monitored Entities
          </span>
          <div className="text-2xl font-bold text-purple-400 mt-1 flex items-baseline gap-2">
            <span>{stats.totalUsers || 1001}</span>
            <span className="text-[11px] text-purple-300/70 font-normal">Trained</span>
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">CERT r4.2 Baseline Models</div>
        </div>
      </div>

      {/* Real-time Injection Action Bar */}
      <div className="soc-panel p-4 bg-gradient-to-r from-purple-950/20 via-[#0b101d] to-cyan-950/20 border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400 shrink-0" />
          <div>
            <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">
              Inject Real-Time User Activity:
            </span>
            <p className="text-[11px] text-gray-400">
              Dispatches live telemetry evaluated through the Isolation Forest ML model and immediately appends to the database.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {SIMULATION_ACTIONS.map((act) => (
            <button
              key={act.label}
              onClick={() => handleInjectAction(act)}
              className="px-2.5 py-1.5 rounded bg-white/5 hover:bg-white/15 text-xs font-mono text-gray-200 hover:text-white border border-white/10 transition-all flex items-center gap-1.5 shadow-sm"
            >
              <Zap className="w-3 h-3 text-cyan-400" />
              <span>{act.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tab Navigation & Search Bar */}
      <div className="bg-[#0b101d] border border-white/10 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          {/* Tabs */}
          <div className="flex items-center gap-2 bg-black/40 p-1 rounded-lg border border-white/10">
            <button
              onClick={() => setActiveTab('stream')}
              className={`px-3 py-1.5 rounded text-xs font-bold font-mono transition-all flex items-center gap-1.5 ${
                activeTab === 'stream'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>REAL-TIME INGESTED STREAM ({recentEvents.length} Appended)</span>
            </button>
            <button
              onClick={() => setActiveTab('profiles')}
              className={`px-3 py-1.5 rounded text-xs font-bold font-mono transition-all flex items-center gap-1.5 ${
                activeTab === 'profiles'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-900/40'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Users className="w-3.5 h-3.5" />
              <span>TRAINED BEHAVIOURAL PROFILES ({stats.totalUsers || 1001})</span>
            </button>
          </div>

          <div className="text-[11px] font-mono text-gray-400 flex items-center gap-2">
            <span>Last Sync: {lastSyncTime.toLocaleTimeString()}</span>
          </div>
        </div>

        {/* Filter Row for Profiles Tab */}
        {activeTab === 'profiles' && (
          <div className="pt-2 border-t border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by User ID (e.g. MOH0273, NGF0157) or employee name..."
                className="w-full bg-[#131c2e] border border-white/10 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[10px] font-mono uppercase text-gray-400 mr-1 flex items-center gap-1">
                <Filter className="w-3 h-3" /> RISK:
              </span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setRiskFilter(lvl)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                    riskFilter === lvl
                      ? 'bg-purple-600 text-white font-bold shadow-sm'
                      : 'bg-white/5 text-gray-400 hover:text-white border border-white/5'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Main Content Area */}
      {loading ? (
        <LoadingState message="Connecting to live User Behaviour Analytics engine..." />
      ) : activeTab === 'stream' ? (
        /* TAB 1: Real-Time Appended Stream Table */
        <div className="soc-panel p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/10">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Live Appended Real-Time Activity Feed ({recentEvents.length} Recent Events)
              </h3>
            </div>
            <span className="text-[11px] font-mono text-cyan-400">
              POLLING &bull; PORT 5001 ISOLATION FOREST
            </span>
          </div>

          {recentEvents.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="text-[10px] uppercase text-gray-400 border-b border-white/10 pb-2.5">
                    <th className="pb-2.5">Timestamp</th>
                    <th className="pb-2.5">Target Employee</th>
                    <th className="pb-2.5">Event Type</th>
                    <th className="pb-2.5">Activity</th>
                    <th className="pb-2.5">Anomaly Status</th>
                    <th className="pb-2.5">ML Score</th>
                    <th className="pb-2.5">Observed Details / Payload</th>
                    <th className="pb-2.5 text-right">Investigation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {recentEvents.map((ev, idx) => (
                    <tr 
                      key={ev.event_id || idx}
                      className={`hover:bg-white/[0.03] transition-colors cursor-pointer ${
                        ev.is_anomalous ? 'bg-rose-950/15' : ''
                      }`}
                      onClick={() => navigate(`/user-investigation?user=${ev.user_id}`)}
                    >
                      <td className="py-3 text-gray-400 text-[11px] whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${ev.is_anomalous ? 'bg-rose-400 animate-ping' : 'bg-cyan-400'}`} />
                          {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Live'}
                        </div>
                      </td>
                      <td className="py-3">
                        <div className="font-bold text-white">{ev.full_name || ev.user_id}</div>
                        <div className="text-[10px] text-cyan-400">{ev.user_id} &bull; {ev.department}</div>
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/5 border border-white/10 text-gray-300">
                          {ev.event_type || 'ACTIVITY'}
                        </span>
                      </td>
                      <td className="py-3 text-white font-medium">
                        {ev.activity || 'Observed Event'}
                      </td>
                      <td className="py-3">
                        {ev.is_anomalous ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1 w-fit">
                            <Flame className="w-3 h-3 text-rose-400" />
                            ANOMALOUS
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 w-fit">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            COMPLIANT
                          </span>
                        )}
                      </td>
                      <td className="py-3">
                        {ev.anomaly_score != null ? (
                          <span className={`font-bold ${ev.is_anomalous ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {ev.anomaly_score.toFixed(3)}
                          </span>
                        ) : (
                          <span className="text-gray-500">0.000</span>
                        )}
                      </td>
                      <td className="py-3 text-gray-400 text-[11px] max-w-xs truncate">
                        {typeof ev.details === 'string' ? ev.details : JSON.stringify(ev.details)}
                      </td>
                      <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <Link
                          to={`/user-investigation?user=${ev.user_id}`}
                          className="px-2.5 py-1 text-[11px] text-cyan-300 hover:text-white bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-700/40 rounded inline-flex items-center gap-1 transition-colors"
                        >
                          Forensics &rarr;
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center text-gray-400 text-xs font-mono space-y-3">
              <Radio className="w-10 h-10 text-cyan-400/60 mx-auto animate-pulse" />
              <div className="text-white font-bold text-sm">Waiting for Live User Telemetry...</div>
              <p className="max-w-md mx-auto text-gray-400">
                0 live events currently in queue. Click "Inject Real-Time User Activity" above or perform an attack in the Attacker Workspace to watch events dynamically append in real time.
              </p>
              <button
                onClick={() => handleInjectAction(SIMULATION_ACTIONS[0])}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-all shadow-md"
              >
                <Zap className="w-3.5 h-3.5" />
                Inject First Anomaly Event
              </button>
            </div>
          )}
        </div>
      ) : (
        /* TAB 2: 1,001 Trained Entity Profiles Table */
        <div className="soc-panel p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/10">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Trained Behavioral Entity Profiles ({users.length} Displayed)
              </h3>
            </div>
            <span className="text-[11px] font-mono text-gray-400">
              SORTED BY RECENT ACTIVITY & RISK &bull; PORT 5001
            </span>
          </div>

          {users.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="text-[10px] uppercase text-gray-400 border-b border-white/10 pb-2.5">
                    <th className="pb-2.5">User ID</th>
                    <th className="pb-2.5">Employee Name</th>
                    <th className="pb-2.5">Department</th>
                    <th className="pb-2.5">Role</th>
                    <th className="pb-2.5">Risk Level</th>
                    <th className="pb-2.5">Total Alerts</th>
                    <th className="pb-2.5">Baseline Shift</th>
                    <th className="pb-2.5">Files/Day</th>
                    <th className="pb-2.5">USB Freq</th>
                    <th className="pb-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {users.map((u) => (
                    <tr 
                      key={u.user_id} 
                      className="hover:bg-white/[0.03] transition-colors cursor-pointer"
                      onClick={() => navigate(`/user-investigation?user=${u.user_id}`)}
                    >
                      <td className="py-3 text-cyan-400 font-bold font-mono">{u.user_id}</td>
                      <td className="py-3 text-white font-semibold">{u.full_name}</td>
                      <td className="py-3 text-gray-300">{u.department}</td>
                      <td className="py-3 text-gray-400">{u.role}</td>
                      <td className="py-3">
                        <StatusPill severity={u.current_risk_level} />
                      </td>
                      <td className="py-3">
                        {u.total_alerts > 0 ? (
                          <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">
                            {u.total_alerts} alert{u.total_alerts > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="text-gray-500">0</span>
                        )}
                      </td>
                      <td className="py-3 text-gray-300">
                        {u.avg_logon_time?.slice(0, 5)} - {u.avg_logoff_time?.slice(0, 5)}
                      </td>
                      <td className="py-3 text-purple-300">{u.avg_file_accesses_per_day}</td>
                      <td className="py-3 text-amber-300">{u.usb_usage_frequency}</td>
                      <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <Link
                          to={`/user-investigation?user=${u.user_id}`}
                          className="px-2.5 py-1 text-[11px] text-purple-300 hover:text-white bg-purple-950/40 hover:bg-purple-900/50 border border-purple-700/40 rounded inline-flex items-center gap-1 transition-colors"
                        >
                          Investigate &rarr;
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center text-gray-400 text-xs font-mono space-y-3">
              <CheckCircle2 className="w-10 h-10 text-emerald-400/60 mx-auto" />
              <div className="text-white font-bold text-sm">No Monitored Users Match Criteria</div>
              <p className="max-w-md mx-auto text-gray-400">
                No profiles found matching search '{searchTerm}' with risk level '{riskFilter}'.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
export default UserBehaviour;
