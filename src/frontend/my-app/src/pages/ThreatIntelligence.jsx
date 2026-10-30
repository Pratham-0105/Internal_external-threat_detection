import React, { useState } from 'react';
import { Globe, Unlock, Database } from 'lucide-react';
import { useSOC } from '../context/SOCContext';
import { nidsService } from '../services/nidsService';
import { StatusPill } from '../components/common/StatusPill';
import { EmptyState } from '../components/common/EmptyState';

export const ThreatIntelligence = () => {
  const { defenseStatus, incidents, fetchDefenseStatus } = useSOC();
  const [unblockingIp, setUnblockingIp] = useState(null);

  // Extract unique IOCs (IPs and attack vectors) from real backend incidents & defense status
  const iocList = React.useMemo(() => {
    const map = new Map();

    // From blocked IPs
    (defenseStatus.blocked_ips || []).forEach((ip) => {
      map.set(ip, {
        ioc: ip,
        type: 'IPv4',
        classification: 'Firewall Blacklisted',
        confidence: 99.0,
        source: 'Automated Mitigation Engine',
        status: 'BLOCKED',
        timestamp: new Date().toLocaleTimeString()
      });
    });

    // From malicious incidents
    incidents
      .filter((i) => i.is_attack && i.src_ip)
      .forEach((i) => {
        if (!map.has(i.src_ip)) {
          map.set(i.src_ip, {
            ioc: i.src_ip,
            type: 'IPv4',
            classification: i.vector,
            confidence: i.confidence,
            source: 'LightGBM / DPI Detector',
            status: i.status === 'RESOLVED' ? 'RESOLVED' : 'ACTIVE_THREAT',
            timestamp: i.time_display || i.timestamp
          });
        }
      });

    return Array.from(map.values());
  }, [defenseStatus, incidents]);

  const handleUnblock = async (ip) => {
    setUnblockingIp(ip);
    try {
      await nidsService.unblockIp(ip);
      await fetchDefenseStatus();
    } catch (e) {
      console.error('Unblock failed:', e);
    } finally {
      setUnblockingIp(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="soc-panel p-5">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          Threat Intelligence & IOC Repository
        </h2>
        <div className="text-xs text-gray-400 mt-1 font-mono">
          Consolidated Indicators of Compromise (IOC) derived from LightGBM predictions, DPI signature matches, and active firewall bans
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
        <div className="soc-panel p-4">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Blacklisted IPs</span>
          <div className="text-xl font-bold mt-1 text-rose-400">
            {defenseStatus.blocked_ips_count || defenseStatus.blocked_ips?.length || 0} IPs
          </div>
          <span className="text-xs text-gray-400 mt-1 block">Active firewall drop rules</span>
        </div>

        <div className="soc-panel p-4">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Identified Malicious Sources</span>
          <div className="text-xl font-bold mt-1 text-amber-400">
            {iocList.length} Unique IOCs
          </div>
          <span className="text-xs text-gray-400 mt-1 block">Indexed attack entities</span>
        </div>

        <div className="soc-panel p-4">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Honeypot Logs</span>
          <div className="text-xl font-bold mt-1 text-cyan-400">
            {defenseStatus.honeypot_logs?.length || 0} Sessions
          </div>
          <span className="text-xs text-gray-400 mt-1 block">Detained suspicious flows</span>
        </div>
      </div>

      {/* IOC Index Table */}
      <div className="soc-panel p-5">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            Active Threat Indicators (IOC Index)
          </span>
          <span className="text-[11px] font-mono text-gray-400">{iocList.length} Entries</span>
        </h3>

        {iocList.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                  <th className="pb-2">Indicator (IOC)</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Threat Classification</th>
                  <th className="pb-2">Confidence</th>
                  <th className="pb-2">Source</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {iocList.map((item, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.02]">
                    <td className="py-3 text-gray-200 font-bold">{item.ioc}</td>
                    <td className="py-3 text-gray-400">{item.type}</td>
                    <td className="py-3 text-rose-400 font-medium">{item.classification}</td>
                    <td className="py-3 text-cyan-400">{item.confidence}%</td>
                    <td className="py-3 text-gray-400">{item.source}</td>
                    <td className="py-3">
                      <StatusPill status={item.status} size="xs" />
                    </td>
                    <td className="py-3 text-right">
                      {item.status === 'BLOCKED' ? (
                        <button
                          onClick={() => handleUnblock(item.ioc)}
                          disabled={unblockingIp === item.ioc}
                          className="inline-flex items-center gap-1 text-[10px] text-amber-400 hover:text-amber-300 font-medium bg-amber-500/10 border border-amber-500/20 px-2 py-1 rounded"
                        >
                          <Unlock className="w-3 h-3" />
                          {unblockingIp === item.ioc ? 'Unblocking...' : 'Unblock IP'}
                        </button>
                      ) : (
                        <span className="text-gray-400 text-[10px]">Monitored</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No threat indicators recorded"
            description="The threat intelligence repository will automatically index malicious IPs and attack fingerprints."
          />
        )}
      </div>
    </div>
  );
};
