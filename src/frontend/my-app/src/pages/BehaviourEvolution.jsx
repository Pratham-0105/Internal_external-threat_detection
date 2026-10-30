import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  TrendingUp, 
  Info, 
  User, 
  Clock, 
  FileText, 
  HardDrive, 
  ExternalLink,
  RefreshCw
} from 'lucide-react';
import { insiderService } from '../services/insiderService';
import { StatusPill } from '../components/common/StatusPill';
import { LoadingState } from '../components/common/LoadingState';
import { Link } from 'react-router-dom';

export const BehaviourEvolution = () => {
  const [usersList, setUsersList] = useState([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [profile, setProfile] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchUsers = useCallback(async () => {
    try {
      setLoading(true);
      const res = await insiderService.getUsers({ limit: 50 });
      if (res && res.status === 'success' && res.users) {
        setUsersList(res.users);
        if (!selectedUserId && res.users.length > 0) {
          setSelectedUserId(res.users[0].user_id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch users for evolution:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedUserId]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  useEffect(() => {
    if (!selectedUserId) return;
    const loadDetails = async () => {
      try {
        const [profRes, evRes] = await Promise.allSettled([
          insiderService.getUserProfile(selectedUserId),
          insiderService.getUserEvents(selectedUserId)
        ]);
        if (profRes.status === 'fulfilled' && profRes.value?.user) {
          setProfile(profRes.value.user);
        }
        if (evRes.status === 'fulfilled' && evRes.value?.events) {
          setEvents(evRes.value.events);
        }
      } catch (e) {
        console.error('Failed to load user evolution profile:', e);
      }
    };
    loadDetails();
  }, [selectedUserId]);

  const anomalousEventsCount = useMemo(() => {
    return events.filter(e => e.is_anomalous).length;
  }, [events]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="soc-panel p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
              CERT R4.2 BEHAVIORAL BASELINE ENGINE
            </span>
          </div>
          <h2 className="text-xl font-black text-white tracking-tight mt-1 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            User Behaviour Evolution & Deviation Trends
          </h2>
          <div className="text-xs text-gray-400 mt-1 font-mono">
            Continuous baseline modeling comparing typical shift activities against real-time variance
          </div>
        </div>

        {usersList.length > 0 && (
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-gray-400 uppercase font-bold text-[10px]">Select Employee:</span>
            <select
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              className="bg-[#131c2e] border border-white/10 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
            >
              {usersList.map((u) => (
                <option key={u.user_id} value={u.user_id}>
                  {u.user_id} - {u.full_name} ({u.current_risk_level})
                </option>
              ))}
            </select>
            <button
              onClick={fetchUsers}
              className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {/* Integration Note */}
      <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-500/20 flex items-start gap-3 text-xs">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-gray-300 leading-relaxed font-mono">
          <strong>UEBA Evolution Engine:</strong> Profiles are derived from historical enterprise baselines (trained on 1,001 CERT r4.2 corporate users). Anomaly thresholds recalculate continuously as activities are ingested into SQLite via the ML Isolation Forest model.
        </div>
      </div>

      {loading && !profile ? (
        <LoadingState message="Computing behavioral variance metrics..." />
      ) : profile ? (
        <>
          {/* User Quick Identity Card */}
          <div className="soc-panel p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <User className="w-6 h-6" />
              </div>
              <div>
                <div className="text-lg font-bold text-white flex items-center gap-2">
                  {profile.full_name}
                  <StatusPill severity={profile.current_risk_level} />
                </div>
                <div className="text-xs font-mono text-gray-400 mt-0.5">
                  ID: <span className="text-cyan-400">{profile.user_id}</span> &bull; {profile.department} &bull; {profile.role}
                </div>
              </div>
            </div>

            <Link
              to={`/user-investigation?user=${profile.user_id}`}
              className="px-4 py-2 rounded-lg bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-300 hover:text-white border border-cyan-500/40 text-xs font-mono font-bold flex items-center gap-1.5 transition-all self-start md:self-auto"
            >
              <span>Investigate Forensic Timeline</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Deviation Evolution Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 font-mono text-xs">
            {/* Shift Timing Evolution */}
            <div className="soc-panel p-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <Clock className="w-4 h-4 text-cyan-400" /> Shift Hours Variance
                </span>
                <span className="text-[10px] text-gray-400 font-mono">STANDARD vs CURRENT</span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Trained Baseline:</span>
                  <span className="text-white font-bold">{profile.avg_logon_time?.slice(0, 5)} - {profile.avg_logoff_time?.slice(0, 5)}</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Typical Workdays:</span>
                  <span className="text-cyan-300 font-bold">{profile.typical_work_days || 'Mon-Fri'}</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Observed Variance:</span>
                  <span className={profile.total_alerts > 0 ? "text-amber-400 font-bold" : "text-emerald-400 font-bold"}>
                    {profile.total_alerts > 0 ? "Elevated After-Hours Telemetry" : "0.0% Standard Shift Compliance"}
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                <div className="w-full bg-white/5 h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${profile.total_alerts > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`} 
                    style={{ width: profile.total_alerts > 0 ? '82%' : '100%' }} 
                  />
                </div>
              </div>
            </div>

            {/* File Access Velocity */}
            <div className="soc-panel p-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <FileText className="w-4 h-4 text-purple-400" /> File Velocity Baseline
                </span>
                <span className="text-[10px] text-gray-400 font-mono">FILES / DAY</span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Baseline Volume:</span>
                  <span className="text-purple-300 font-bold">{profile.avg_file_accesses_per_day} files/day</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">HTTP Web Requests:</span>
                  <span className="text-white font-bold">{profile.avg_http_requests_per_day} req/day</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Anomalous Bursts:</span>
                  <span className={anomalousEventsCount > 0 ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                    {anomalousEventsCount} Detected Anomaly Events
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                <div className="w-full bg-white/5 h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${anomalousEventsCount > 0 ? 'bg-rose-500' : 'bg-purple-500'}`} 
                    style={{ width: `${Math.min(100, Math.max(20, profile.avg_file_accesses_per_day * 4))}%` }} 
                  />
                </div>
              </div>
            </div>

            {/* Peripheral & Exfiltration Posture */}
            <div className="soc-panel p-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <HardDrive className="w-4 h-4 text-amber-400" /> USB & Peripheral Risk
                </span>
                <span className="text-[10px] text-gray-400 font-mono">HARDWARE TELEMETRY</span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">USB Mount Frequency:</span>
                  <span className="text-amber-300 font-bold">{profile.usb_usage_frequency} connects/day</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Total Flagged Alerts:</span>
                  <span className={profile.total_alerts > 0 ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                    {profile.total_alerts} ({profile.high_risk_alerts} Critical)
                  </span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-gray-400">Email Dispatch Baseline:</span>
                  <span className="text-white font-bold">{profile.avg_email_count_per_day} emails/day</span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                <div className="w-full bg-white/5 h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${profile.usb_usage_frequency > 1.0 ? 'bg-rose-500' : 'bg-amber-500'}`} 
                    style={{ width: `${Math.min(100, Math.max(15, profile.usb_usage_frequency * 20))}%` }} 
                  />
                </div>
              </div>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};
export default BehaviourEvolution;
