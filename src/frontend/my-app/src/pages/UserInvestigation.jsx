import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { 
  Search, 
  Clock, 
  Zap, 
  ShieldAlert, 
  User, 
  Building, 
  Briefcase, 
  HardDrive, 
  FileText, 
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Flame
} from 'lucide-react';
import { insiderService } from '../services/insiderService';
import { useSOC } from '../context/SOCContext';
import { StatusPill } from '../components/common/StatusPill';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';

const ANOMALY_PRESETS = [
  {
    label: 'After-Hours Intrusion',
    type: 'LOGON',
    activity: 'Logon',
    details: '{"workstation":"WS-FIN-09","logon_time":"02:44:12","auth_method":"NTLM","status":"Success","anomaly":"Outside standard shift hours"}'
  },
  {
    label: 'Sensitive File Mass Exfiltration',
    type: 'FILE',
    activity: 'Bulk_Download',
    details: '{"file_path":"/confidential/q3_merger_financials.enc","bytes":48920194,"action":"Read_Extract","anomaly":"Sensitive keyword detected"}'
  },
  {
    label: 'Unauthorized Rogue USB Drive',
    type: 'DEVICE',
    activity: 'Connect',
    details: '{"vendor_id":"SanDisk_Ultra_USB3","serial":"SN-9948201","device_type":"Removable_Storage","anomaly":"Unapproved external mass storage"}'
  },
  {
    label: 'Malicious Outbound Exfiltration Email',
    type: 'EMAIL',
    activity: 'Send',
    details: '{"to":"exfil_dropbox@external-c2.darknet","subject":"INTERNAL SALARY ARCHIVES","attachments":["payroll_2026.zip"],"anomaly":"External shadow domain"}'
  }
];

export const UserInvestigation = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryUser = searchParams.get('user') || '';

  const { incidents, triggerThreatNotification, fetchIncidents } = useSOC();

  // State
  const [usersList, setUsersList] = useState([]);
  const [selectedUserId, setSelectedUserId] = useState(queryUser || '');
  const [userProfile, setUserProfile] = useState(null);
  const [userEvents, setUserEvents] = useState([]);
  const [userAlerts, setUserAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Ingestion / Simulation state
  const [isInjecting, setIsInjecting] = useState(false);
  const [injectionSuccess, setInjectionSuccess] = useState(null);

  // Fetch initial list of users
  useEffect(() => {
    let isMounted = true;
    const fetchUsers = async () => {
      try {
        const res = await insiderService.getUsers({ limit: 100 });
        if (isMounted && res && res.status === 'success' && res.users) {
          setUsersList(res.users);
          if (!queryUser && !selectedUserId && res.users.length > 0) {
            // Default to first user with active alerts, or first in list
            const priorityUser = res.users.find(u => u.total_alerts > 0) || res.users[0];
            setSelectedUserId(priorityUser.user_id);
          }
        }
      } catch (err) {
        console.error('Failed to load users list:', err);
      }
    };
    fetchUsers();
    return () => { isMounted = false; };
  }, [queryUser, selectedUserId]);

  // Synchronize selection with URL parameter
  useEffect(() => {
    if (queryUser && queryUser !== selectedUserId) {
      setSelectedUserId(queryUser);
    }
  }, [queryUser, selectedUserId]);

  // Fetch detailed data for selected user
  const fetchUserData = useCallback(async (uid) => {
    if (!uid) return;
    try {
      setLoading(true);
      setError(null);

      const [profRes, evRes, alRes] = await Promise.allSettled([
        insiderService.getUserProfile(uid),
        insiderService.getUserEvents(uid),
        insiderService.getUserAlerts(uid)
      ]);

      if (profRes.status === 'fulfilled' && profRes.value && profRes.value.status === 'success') {
        setUserProfile(profRes.value.user);
      } else {
        // Fallback: If not found in SQLite, generate stub profile so user is still investigatable
        setUserProfile({
          user_id: uid,
          full_name: uid,
          department: 'Corporate Endpoint',
          role: 'Staff Employee',
          current_risk_level: 'MEDIUM',
          total_alerts: 0,
          high_risk_alerts: 0,
          avg_logon_time: '08:30:00',
          avg_logoff_time: '17:30:00',
          typical_work_days: 'Mon-Fri',
          avg_file_accesses_per_day: 12.0,
          avg_http_requests_per_day: 180.0,
          avg_email_count_per_day: 25.0,
          usb_usage_frequency: 0.1
        });
      }

      if (evRes.status === 'fulfilled' && evRes.value && evRes.value.status === 'success') {
        setUserEvents(evRes.value.events || []);
      } else {
        setUserEvents([]);
      }

      if (alRes.status === 'fulfilled' && alRes.value && alRes.value.status === 'success') {
        setUserAlerts(alRes.value.alerts || []);
      } else {
        setUserAlerts([]);
      }
    } catch (err) {
      console.error('Failed to fetch user telemetry:', err);
      setError('Failed to retrieve user telemetry from UEBA engine.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedUserId) {
      fetchUserData(selectedUserId);
    }
  }, [selectedUserId, fetchUserData]);

  // Handler to switch selected user
  const handleSelectUser = (uid) => {
    setSelectedUserId(uid);
    setSearchParams({ user: uid });
    setInjectionSuccess(null);
  };

  // Correlated NIDS incidents from Master Audit (Port 5000)
  const correlatedIncidents = useMemo(() => {
    if (!selectedUserId) return [];
    return incidents.filter((inc) => {
      const matchUser = (inc.username || '').toLowerCase() === selectedUserId.toLowerCase() ||
                        (inc.user_id || '').toLowerCase() === selectedUserId.toLowerCase();
      const matchDst = (inc.dst_ip || '').toLowerCase() === selectedUserId.toLowerCase();
      return matchUser || matchDst;
    });
  }, [incidents, selectedUserId]);

  // Combined Chronological Timeline
  const combinedTimeline = useMemo(() => {
    const list = [];

    // Add Insider Events
    userEvents.forEach((ev) => {
      list.push({
        id: ev.event_id || `ev-${ev.id}`,
        timestamp: ev.timestamp,
        source: 'UEBA_EVENT',
        vector: `${ev.event_type || 'SYSTEM'} ${ev.activity || 'Activity'}`,
        is_anomalous: ev.is_anomalous,
        risk_score: ev.risk_score,
        anomaly_score: ev.anomaly_score,
        details: ev.details,
        action: ev.is_anomalous ? 'Anomalous Event Flagged' : 'Normal Baseline'
      });
    });

    // Add Insider Alerts
    userAlerts.forEach((al) => {
      list.push({
        id: al.alert_id || `al-${al.id}`,
        timestamp: al.timestamp,
        source: 'UEBA_ALERT',
        vector: `ALERT: ${al.alert_type || 'THREAT'}`,
        is_anomalous: true,
        risk_level: al.risk_level,
        risk_score: al.risk_score,
        anomaly_score: al.anomaly_score,
        details: al.description,
        action: `Security Alert Triggered [${al.risk_level}]`
      });
    });

    // Add Correlated NIDS Incidents
    correlatedIncidents.forEach((inc) => {
      list.push({
        id: `nids-${inc.id}`,
        timestamp: inc.timestamp,
        source: 'NIDS_NETWORK',
        vector: inc.vector || inc.type || 'Network Intrusion',
        is_anomalous: Boolean(inc.is_attack),
        risk_score: inc.confidence,
        details: `Src: ${inc.src_ip} -> Dst: ${inc.dst_ip} (Port ${inc.dst_port || 80})`,
        action: inc.action_taken || inc.mitigation_action || 'Quarantined'
      });
    });

    // Sort descending by timestamp
    return list.sort((a, b) => {
      const tA = new Date(a.timestamp).getTime() || 0;
      const tB = new Date(b.timestamp).getTime() || 0;
      return tB - tA;
    });
  }, [userEvents, userAlerts, correlatedIncidents]);

  // Simulate Anomaly Injection directly from this page
  const handleSimulateAnomaly = async (preset) => {
    if (!selectedUserId || isInjecting) return;
    setIsInjecting(true);
    setInjectionSuccess(null);

    try {
      const payload = {
        user: selectedUserId,
        user_id: selectedUserId,
        username: userProfile?.full_name || selectedUserId,
        department: userProfile?.department || 'Corporate Staff',
        event_type: preset.type,
        activity: preset.activity,
        timestamp: new Date().toISOString(),
        details: preset.details
      };

      const res = await insiderService.ingestEvent(payload);

      setInjectionSuccess(`Successfully simulated '${preset.label}'. Detection Score: ${res.risk_score || 'High'}`);
      
      triggerThreatNotification({
        title: `🚨 INSIDER THREAT DETECTED: ${selectedUserId}`,
        vector: preset.label,
        target: `${selectedUserId} (${userProfile?.full_name || 'Staff'})`,
        action: 'UEBA Isolation Forest Quarantine',
        confidence: 96.5
      });

      // Refresh data
      await fetchUserData(selectedUserId);
      await fetchIncidents();
    } catch (err) {
      console.error('Failed to simulate anomaly:', err);
      setError('Anomaly simulation failed. Check if Insider Threat API (:5001) is running.');
    } finally {
      setIsInjecting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Entity Selector */}
      <div className="soc-panel p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
              CERT R4.2 FORENSIC LAB
            </span>
            <span className="text-[10px] font-mono text-cyan-400 flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              PORT 5001 UEBA AUDIT
            </span>
          </div>
          <h1 className="text-xl font-black tracking-tight text-white mt-1 flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" />
            Forensic User & Entity Activity Investigation
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Chronological audit trail, baseline shifts, and ML anomaly telemetry for monitored corporate entities.
          </p>
        </div>

        {/* Entity Switcher Dropdown */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-gray-400 uppercase font-bold text-[10px]">Select Target:</span>
            <select
              value={selectedUserId}
              onChange={(e) => handleSelectUser(e.target.value)}
              className="bg-[#131c2e] border border-white/15 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono shadow-inner"
            >
              {usersList.length > 0 ? (
                usersList.map((u) => (
                  <option key={u.user_id} value={u.user_id}>
                    {u.user_id} - {u.full_name} ({u.current_risk_level})
                  </option>
                ))
              ) : (
                <option value={selectedUserId}>{selectedUserId || 'No users loaded'}</option>
              )}
            </select>
          </div>

          <button
            onClick={() => fetchUserData(selectedUserId)}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 transition-colors"
            title="Refresh user forensic data"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && <ErrorState message={error} onRetry={() => fetchUserData(selectedUserId)} />}

      {injectionSuccess && (
        <div className="p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-500/40 flex items-center justify-between text-xs font-mono text-emerald-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{injectionSuccess}</span>
          </div>
          <button onClick={() => setInjectionSuccess(null)} className="text-emerald-400 hover:text-white text-xs">
            &times;
          </button>
        </div>
      )}

      {loading && !userProfile ? (
        <LoadingState message={`Analyzing forensic telemetry for entity ${selectedUserId}...`} />
      ) : userProfile ? (
        <>
          {/* Target Identity & Risk Posture Panel */}
          <div className="soc-panel p-5 grid grid-cols-1 md:grid-cols-12 gap-5">
            {/* Identity Column */}
            <div className="md:col-span-4 border-b md:border-b-0 md:border-r border-white/10 pb-4 md:pb-0 md:pr-5 space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <span className="text-[10px] uppercase font-bold text-gray-400 font-mono">Entity Subject</span>
                  <div className="text-xl font-extrabold text-white mt-0.5 flex items-center gap-2">
                    <User className="w-5 h-5 text-cyan-400" />
                    {userProfile.full_name}
                  </div>
                  <div className="text-xs font-mono text-cyan-400 mt-0.5">{userProfile.user_id}</div>
                </div>
                <StatusPill severity={userProfile.current_risk_level} />
              </div>

              <div className="text-xs font-mono text-gray-300 space-y-1.5 pt-2">
                <div className="flex items-center gap-2">
                  <Building className="w-3.5 h-3.5 text-gray-500" />
                  <span className="text-gray-400">Department:</span>
                  <span className="text-white font-medium">{userProfile.department}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Briefcase className="w-3.5 h-3.5 text-gray-500" />
                  <span className="text-gray-400">Role:</span>
                  <span className="text-white font-medium">{userProfile.role}</span>
                </div>
                <div className="flex items-center gap-2">
                  <User className="w-3.5 h-3.5 text-gray-500" />
                  <span className="text-gray-400">Supervisor:</span>
                  <span className="text-white font-medium">{userProfile.supervisor || 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Baseline Metrics Matrix */}
            <div className="md:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
              <div className="bg-[#131c2e] p-3 rounded-lg border border-white/5">
                <span className="text-[10px] text-gray-400 uppercase flex items-center gap-1">
                  <Clock className="w-3 h-3 text-cyan-400" /> Shift Hours
                </span>
                <div className="text-sm font-bold text-white mt-1">
                  {userProfile.avg_logon_time?.slice(0, 5)} - {userProfile.avg_logoff_time?.slice(0, 5)}
                </div>
                <div className="text-[10px] text-gray-400 mt-0.5">{userProfile.typical_work_days || 'Mon-Fri'}</div>
              </div>

              <div className="bg-[#131c2e] p-3 rounded-lg border border-white/5">
                <span className="text-[10px] text-gray-400 uppercase flex items-center gap-1">
                  <FileText className="w-3 h-3 text-purple-400" /> Files / Day
                </span>
                <div className="text-sm font-bold text-purple-300 mt-1">
                  {userProfile.avg_file_accesses_per_day}
                </div>
                <div className="text-[10px] text-gray-400 mt-0.5">Typical Baseline</div>
              </div>

              <div className="bg-[#131c2e] p-3 rounded-lg border border-white/5">
                <span className="text-[10px] text-gray-400 uppercase flex items-center gap-1">
                  <HardDrive className="w-3 h-3 text-amber-400" /> USB Frequency
                </span>
                <div className="text-sm font-bold text-amber-300 mt-1">
                  {userProfile.usb_usage_frequency}
                </div>
                <div className="text-[10px] text-gray-400 mt-0.5">Mounts / Shift</div>
              </div>

              <div className="bg-[#131c2e] p-3 rounded-lg border border-white/5">
                <span className="text-[10px] text-gray-400 uppercase flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3 text-rose-400" /> Alerts Count
                </span>
                <div className="text-sm font-bold text-rose-400 mt-1">
                  {userProfile.total_alerts}
                </div>
                <div className="text-[10px] text-gray-400 mt-0.5">
                  {userProfile.high_risk_alerts} High-Risk
                </div>
              </div>
            </div>
          </div>

          {/* Quick Anomaly Injection Bar */}
          <div className="soc-panel p-4 bg-gradient-to-r from-purple-950/20 via-[#0b101d] to-rose-950/20 border border-purple-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400 shrink-0" />
              <div>
                <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  Inject Simulated Behaviour for {userProfile.user_id}:
                </span>
                <p className="text-[11px] text-gray-400">
                  Execute live anomalous insider activities evaluated by Isolation Forest ML model.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {ANOMALY_PRESETS.map((p) => (
                <button
                  key={p.label}
                  onClick={() => handleSimulateAnomaly(p)}
                  disabled={isInjecting}
                  className="px-2.5 py-1.5 rounded bg-white/5 hover:bg-purple-600/30 hover:border-purple-500/50 text-xs font-mono text-gray-300 hover:text-white border border-white/10 transition-all flex items-center gap-1.5"
                >
                  <Flame className="w-3 h-3 text-rose-400" />
                  <span>{p.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Active Alerts for this User */}
          {userAlerts.length > 0 && (
            <div className="soc-panel p-5 space-y-3">
              <h3 className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                Active Anomaly Alerts for {userProfile.user_id} ({userAlerts.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                {userAlerts.map((al) => (
                  <div 
                    key={al.alert_id || al.id} 
                    className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/30 space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-rose-300 font-bold">#{al.alert_id} &bull; {al.alert_type}</span>
                      <StatusPill severity={al.risk_level} />
                    </div>
                    <div className="text-gray-300 text-[11px]">{al.description}</div>
                    <div className="text-gray-400 text-[10px] flex items-center justify-between pt-1 border-t border-rose-500/20">
                      <span>Anomaly Score: {al.anomaly_score}</span>
                      <span>Risk Score: {al.risk_score}</span>
                      <span>{new Date(al.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Chronological Audit Timeline */}
          <div className="soc-panel p-5">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Chronological Forensic Timeline ({combinedTimeline.length} Telemetry Points)
              </h3>
              <span className="text-xs font-mono text-gray-400">
                AUDIT HISTORY &bull; {userProfile.user_id}
              </span>
            </div>

            {combinedTimeline.length > 0 ? (
              <div className="relative border-l border-white/10 ml-4 pl-6 space-y-6">
                {combinedTimeline.map((item, idx) => (
                  <div key={item.id || idx} className="relative group">
                    {/* Dot */}
                    <div className={`absolute -left-[31px] top-0 w-3.5 h-3.5 rounded-full border-2 bg-[#0b101d] ${
                      item.is_anomalous 
                        ? 'border-rose-500 bg-rose-500/20 animate-ping' 
                        : 'border-cyan-500'
                    }`} />
                    <div className={`absolute -left-[31px] top-0 w-3.5 h-3.5 rounded-full border-2 ${
                      item.is_anomalous ? 'border-rose-500 bg-rose-500' : 'border-cyan-500 bg-cyan-500'
                    }`} />

                    {/* Content Card */}
                    <div className={`soc-panel p-4 border transition-all ${
                      item.is_anomalous 
                        ? 'bg-rose-950/10 border-rose-500/30 hover:border-rose-500/50' 
                        : 'bg-white/[0.02] border-white/5 hover:border-white/15'
                    }`}>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2 font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-white">
                            #{item.id} &bull; {item.vector}
                          </span>
                          {item.is_anomalous && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                              ANOMALOUS ACTIVITY
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] text-gray-400">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Just now'}
                        </span>
                      </div>

                      <div className="text-xs text-gray-300 font-mono space-y-1">
                        <div>
                          Action Taken: <span className="text-emerald-400 font-bold">{item.action}</span>
                        </div>
                        {item.details && (
                          <div className="text-gray-400 text-[11px] bg-black/30 p-2 rounded border border-white/5 overflow-x-auto">
                            {typeof item.details === 'string' ? item.details : JSON.stringify(item.details)}
                          </div>
                        )}
                        {(item.risk_score || item.anomaly_score) && (
                          <div className="text-[10px] text-cyan-300 pt-1">
                            ML Anomaly Score: {item.anomaly_score || item.risk_score}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-gray-400 text-xs font-mono space-y-3">
                <CheckCircle2 className="w-10 h-10 text-emerald-400/60 mx-auto" />
                <div className="text-white font-bold text-sm">Clean Baseline Activity Record</div>
                <p className="max-w-md mx-auto text-gray-400">
                  User {userProfile.user_id} ({userProfile.full_name}) currently operates within expected behavioral parameters with 0 flagged anomalies.
                </p>
                <div className="pt-2 flex items-center justify-center gap-3">
                  <button
                    onClick={() => handleSimulateAnomaly(ANOMALY_PRESETS[0])}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold transition-all shadow-md"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    Simulate After-Hours Anomaly
                  </button>
                  <Link
                    to="/attacker-workspace"
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 transition-all"
                  >
                    Open Attacker Workspace &rarr;
                  </Link>
                </div>
              </div>
            )}
          </div>
        </>
      ) : null}
    </div>
  );
};
export default UserInvestigation;
