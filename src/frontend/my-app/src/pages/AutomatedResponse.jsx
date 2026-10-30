import React, { useState } from 'react';
import { Zap, Ban, UserX, Power, Network, ShieldCheck } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { nidsService } from '../services/nidsService';
import { insiderService } from '../services/insiderService';

export const AutomatedResponse = () => {
  const { defenseStatus, fetchDefenseStatus } = useSOC();
  const [toggleLoading, setToggleLoading] = useState(false);
  const [unblockingIp, setUnblockingIp] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  const showNotification = (msg, isError = false) => {
    setActionFeedback({ message: msg, isError });
    setTimeout(() => setActionFeedback(null), 5000);
  };

  const handleToggleDefense = async () => {
    setToggleLoading(true);
    try {
      await nidsService.toggleDefense(!defenseStatus.enabled);
      await fetchDefenseStatus();
      showNotification(`Automated firewall mitigation ${!defenseStatus.enabled ? 'ENABLED' : 'DISABLED'}`);
    } catch (e) {
      showNotification(e.response?.data?.error || 'Defense toggle failed', true);
    } finally {
      setToggleLoading(false);
    }
  };

  const handleUnblock = async (ip) => {
    setUnblockingIp(ip);
    try {
      await nidsService.unblockIp(ip);
      await fetchDefenseStatus();
      showNotification(`Firewall rule deleted: ${ip} successfully unblocked`);
    } catch (e) {
      showNotification(e.response?.data?.error || 'Unblock failed', true);
    } finally {
      setUnblockingIp(null);
    }
  };

  const handleLockUserPrompt = async () => {
    const userId = window.prompt("Enter Target Employee User ID to Lock (e.g. ACM1234, CMP2946):", "ACM1234");
    if (!userId || !userId.trim()) return;

    setActionLoading(true);
    try {
      const res = await insiderService.lockUser(userId.trim());
      showNotification(res.message || `User ${userId} credentials suspended.`);
    } catch (e) {
      showNotification(e.response?.data?.message || `Failed to lock user ${userId}`, true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleTerminateSessionPrompt = async () => {
    const userId = window.prompt("Enter Target Employee User ID to Sever Active Sessions (e.g. ACM1234):", "ACM1234");
    if (!userId || !userId.trim()) return;

    setActionLoading(true);
    try {
      const res = await insiderService.terminateUserSession(userId.trim());
      showNotification(res.message || `Active sessions severed for user ${userId}.`);
    } catch (e) {
      showNotification(e.response?.data?.message || `Failed to terminate sessions for ${userId}`, true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleIsolateHostPrompt = async () => {
    const hostIp = window.prompt("Enter Workstation Host IP or Hostname to Isolate (e.g. 192.168.1.105):", "192.168.1.105");
    if (!hostIp || !hostIp.trim()) return;

    setActionLoading(true);
    try {
      const res = await nidsService.isolateHost(hostIp.trim(), "Manual administrator containment");
      showNotification(res.message || `Host ${hostIp} isolated to Quarantine VLAN.`);
    } catch (e) {
      showNotification(e.response?.data?.error || `Failed to isolate host ${hostIp}`, true);
    } finally {
      setActionLoading(false);
    }
  };

  // Automated Action Capabilities
  const responseActions = [
    {
      title: 'Active Firewall Mitigation',
      desc: 'Automatically bans malicious source IPs flagged by LightGBM model with high confidence.',
      isConfigured: true,
      status: defenseStatus.enabled ? 'ACTIVE' : 'DISABLED',
      actionText: defenseStatus.enabled ? 'Disable Firewall' : 'Enable Firewall',
      onAction: handleToggleDefense,
      icon: Zap
    },
    {
      title: 'Manual IP Blacklist / Unblock',
      desc: 'Quarantine or release suspect IPs from active iptables / Windows firewall tables.',
      isConfigured: true,
      status: 'AVAILABLE',
      actionText: 'Manage Below',
      onAction: null,
      icon: Ban
    },
    {
      title: 'Lock User Account',
      desc: 'Temporarily lock high-risk AD/LDAP user credentials after confirmed UEBA alert.',
      isConfigured: true,
      status: 'ARMED',
      actionText: 'Execute Lockout',
      onAction: handleLockUserPrompt,
      icon: UserX
    },
    {
      title: 'Terminate User Session',
      desc: 'Sever active SSH, RDP, or domain logon sessions for compromised workstations.',
      isConfigured: true,
      status: 'ARMED',
      actionText: 'Sever Sessions',
      onAction: handleTerminateSessionPrompt,
      icon: Power
    },
    {
      title: 'Isolate Host Workstation',
      desc: 'Apply VLAN quarantine to target PC network adapter to contain lateral movement.',
      isConfigured: true,
      status: 'ARMED',
      actionText: 'Quarantine Host',
      onAction: handleIsolateHostPrompt,
      icon: Network
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="soc-panel p-5">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Zap className="w-4 h-4 text-cyan-400" />
          Automated Response & Containment Engine
        </h2>
        <div className="text-xs text-gray-400 mt-1 font-mono">
          Orchestrates active defensive maneuvers. All containment endpoints are armed with real-time enforcement.
        </div>
      </div>

      {/* Live Action Notification Banner */}
      {actionFeedback && (
        <div
          className={`p-4 rounded-lg font-mono text-xs flex items-center gap-2 border ${
            actionFeedback.isError
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
          }`}
        >
          <ShieldCheck className="w-4 h-4 shrink-0" />
          <span>{actionFeedback.message}</span>
        </div>
      )}

      {/* Response Action Cards Grid per Section 23 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {responseActions.map((act) => (
          <div key={act.title} className="soc-panel p-5 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-1.5">
                  <act.icon className="w-3.5 h-3.5 text-cyan-400" />
                  {act.title}
                </h3>
                {act.isConfigured ? (
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                    ARMED
                  </span>
                ) : (
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700 font-mono">
                    DISABLED
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-400 mt-2 leading-relaxed">{act.desc}</p>
            </div>

            <div>
              {act.isConfigured ? (
                act.onAction ? (
                  <button
                    onClick={act.onAction}
                    disabled={toggleLoading || actionLoading}
                    className={`w-full py-2 rounded-lg text-xs font-bold font-mono transition-colors shadow-sm ${
                      act.title === 'Active Firewall Mitigation'
                        ? defenseStatus.enabled
                          ? 'bg-rose-600/20 text-rose-300 border border-rose-500/30 hover:bg-rose-600/30'
                          : 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-600/30'
                        : 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-600/30'
                    }`}
                  >
                    {act.title === 'Active Firewall Mitigation' && toggleLoading
                      ? 'Updating...'
                      : actionLoading
                      ? 'Executing...'
                      : act.actionText}
                  </button>
                ) : (
                  <div className="text-[11px] font-mono text-cyan-400 text-center py-1">
                    &bull; Active in table below &bull;
                  </div>
                )
              ) : (
                <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 text-[11px] font-mono text-gray-500 text-center">
                  {act.reason}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Currently Blocked IPs List */}
      <div className="soc-panel p-5">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Ban className="w-4 h-4 text-rose-400" />
            Active Firewall IP Blacklist ({defenseStatus.blocked_ips?.length || 0} Blocked)
          </span>
        </h3>

        {defenseStatus.blocked_ips && defenseStatus.blocked_ips.length > 0 ? (
          <div className="overflow-x-auto font-mono text-xs">
            <table className="w-full text-left">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                  <th className="pb-2">Quarantined IP</th>
                  <th className="pb-2">Firewall Policy</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {defenseStatus.blocked_ips.map((ip) => (
                  <tr key={ip} className="hover:bg-white/[0.02]">
                    <td className="py-2.5 text-rose-400 font-bold">{ip}</td>
                    <td className="py-2.5 text-gray-400">DROP &bull; REJECT TCP SYN</td>
                    <td className="py-2.5 text-emerald-400">ENFORCED</td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => handleUnblock(ip)}
                        disabled={unblockingIp === ip}
                        className="px-2.5 py-1 text-[10px] text-amber-400 hover:text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded"
                      >
                        {unblockingIp === ip ? 'Releasing...' : 'Unblock IP'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-xs font-mono text-gray-400 bg-black/20 rounded-lg">
            No active IP bans currently enforced by the firewall mitigation engine.
          </div>
        )}
      </div>
    </div>
  );
};
