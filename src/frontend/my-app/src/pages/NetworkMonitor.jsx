import React, { useState, useEffect } from 'react';
import { Activity, Play, Square, RefreshCw, Radio, HardDrive } from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip } from 'recharts';
import { nidsService } from '../services/nidsService';
import { socketService } from '../services/socketService';
import { StatusPill } from '../components/common/StatusPill';
import { EmptyState } from '../components/common/EmptyState';

export const NetworkMonitor = () => {
  const [snifferStatus, setSnifferStatus] = useState({
    is_running: false,
    total_packets_captured: 0,
    buffered_flows_count: 0
  });
  const [toggleLoading, setToggleLoading] = useState(false);
  const [livePackets, setLivePackets] = useState([]);
  const [latencyChart, setLatencyChart] = useState([]);

  const fetchStatus = async () => {
    try {
      const data = await nidsService.getSnifferStatus();
      if (data) setSnifferStatus(data);
    } catch (e) {
      console.warn('Sniffer status fetch error:', e);
    }
  };

  const fetchRecentFlows = async () => {
    try {
      const res = await nidsService.getSnifferFlows(30);
      if (res && res.flows && res.flows.length > 0) {
        setLivePackets((prev) => {
          const existingIds = new Set(prev.map((p) => p.id));
          const newPkts = [];
          for (const f of res.flows) {
            if (!existingIds.has(f.id)) {
              newPkts.push({
                id: f.id,
                time: f.time || new Date().toLocaleTimeString(),
                src_ip: f.src_ip || '192.168.1.50',
                dst_ip: f.dst_ip || '192.168.1.1',
                src_port: f.src_port || 0,
                dst_port: f.dst_port || 0,
                protocol: f.protocol || 'TCP',
                vector: f.category || f.vector || 'Normal Interface Traffic',
                is_attack: Boolean(f.is_attack),
                latency: f.latency || 1.2,
                confidence: f.confidence || 98.5
              });
            }
          }
          if (newPkts.length === 0) return prev;
          return [...newPkts, ...prev].slice(0, 50);
        });

        setLatencyChart((prev) => {
          const existingIds = new Set(prev.map((p) => p.id || p.time));
          const newPoints = [];
          // Flows are prepended (newest first), reverse so oldest to newest in chart
          for (const f of [...res.flows].reverse()) {
            const chartId = f.id || f.time;
            if (!existingIds.has(chartId)) {
              newPoints.push({
                id: chartId,
                time: f.time || new Date().toLocaleTimeString(),
                latency: f.latency || 1.2,
                confidence: f.confidence || 98.5
              });
            }
          }
          if (newPoints.length === 0) return prev;
          return [...prev, ...newPoints].slice(-25);
        });
      }
    } catch (e) {
      console.warn('Flows fetch error:', e);
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchRecentFlows();

    const unsub = socketService.subscribe('new_threat_event', (eventData) => {
      const pkt = {
        id: eventData.id || Date.now(),
        time: eventData.time || new Date().toLocaleTimeString(),
        src_ip: eventData.src_ip || '192.168.1.50',
        dst_ip: eventData.dst_ip || '192.168.1.1',
        src_port: eventData.src_port || 0,
        dst_port: eventData.dst_port || 0,
        protocol: eventData.protocol || 'TCP',
        vector: eventData.category || eventData.vector || 'Normal Interface Traffic',
        is_attack: Boolean(eventData.is_attack),
        latency: eventData.latency || 1.2,
        confidence: eventData.confidence || 98.5
      };

      setLivePackets((prev) => {
        if (prev.some((p) => p.id === pkt.id)) return prev;
        return [pkt, ...prev.slice(0, 49)];
      });
      setLatencyChart((prev) => {
        if (prev.some((p) => p.id === pkt.id)) return prev;
        return [
          ...prev.slice(-24),
          { id: pkt.id, time: pkt.time, latency: pkt.latency, confidence: pkt.confidence }
        ];
      });
    });

    return () => {
      unsub();
    };
  }, []);

  // Responsive polling loop
  useEffect(() => {
    const pollInterval = snifferStatus.is_running ? 1000 : 3500;
    const interval = setInterval(() => {
      fetchStatus();
      if (snifferStatus.is_running) {
        fetchRecentFlows();
      }
    }, pollInterval);

    return () => clearInterval(interval);
  }, [snifferStatus.is_running]);

  const handleToggle = async () => {
    setToggleLoading(true);
    const targetRunning = !snifferStatus.is_running;
    setSnifferStatus((prev) => ({ ...prev, is_running: targetRunning }));
    try {
      if (!targetRunning) {
        await nidsService.stopSniffer();
      } else {
        await nidsService.startSniffer();
      }
      await fetchStatus();
      if (targetRunning) {
        await fetchRecentFlows();
      }
    } catch (e) {
      console.error('Sniffer toggle failed:', e);
      // Revert state on error
      await fetchStatus();
    } finally {
      setToggleLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Control Banner */}
      <div className="soc-panel p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            Live Network Packet Sniffer
          </h2>
          <div className="text-xs text-gray-400 mt-1 font-mono">
            Scapy & Socket.IO driver capturing physical interface packets and calculating 12 time-based features
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleToggle}
            disabled={toggleLoading}
            className={`px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-2 transition-all shadow-md ${
              snifferStatus.is_running
                ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/30'
            }`}
          >
            {snifferStatus.is_running ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                Stop Sniffer
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                Start Live Sniffer
              </>
            )}
          </button>

          <button
            onClick={fetchStatus}
            className="p-2 text-gray-400 hover:text-white bg-white/5 border border-white/5 rounded-lg"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Sniffer Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="soc-panel p-4 font-mono">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Sniffer State</span>
          <div className="text-xl font-bold mt-1 text-white flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${snifferStatus.is_running ? 'bg-emerald-400 animate-ping' : 'bg-gray-500'}`} />
            {snifferStatus.is_running ? 'ACTIVE SNIFFING' : 'IDLE / STANDBY'}
          </div>
          <span className="text-xs text-gray-400 mt-1 block">Live interface listener</span>
        </div>

        <div className="soc-panel p-4 font-mono">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Total Packets Captured</span>
          <div className="text-xl font-bold mt-1 text-cyan-400">
            {snifferStatus.total_packets_captured} Pkts
          </div>
          <span className="text-xs text-gray-400 mt-1 block">Accumulated interface frames</span>
        </div>

        <div className="soc-panel p-4 font-mono">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Buffered Flows</span>
          <div className="text-xl font-bold mt-1 text-purple-400">
            {snifferStatus.buffered_flows_count} Active Flows
          </div>
          <span className="text-xs text-gray-400 mt-1 block">Sliding window aggregation</span>
        </div>
      </div>

      {/* Real-time Telemetry Latency Chart */}
      <div className="soc-panel p-5">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          Real-time Inference Latency (ms) & Confidence (%)
        </h3>
        {latencyChart.length > 0 ? (
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={latencyChart}>
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
                <Line type="monotone" dataKey="latency" stroke="#06b6d4" strokeWidth={2} dot={false} name="Latency (ms)" />
                <Line type="monotone" dataKey="confidence" stroke="#f43f5e" strokeWidth={1.5} dot={false} name="Attack Confidence (%)" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyState
            title="Waiting for live telemetry"
            description="Start the sniffer or trigger an attack scenario to observe real-time latency."
          />
        )}
      </div>

      {/* Live Ingested Packet Table */}
      <div className="soc-panel p-5">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-emerald-400" />
            Live Ingested Traffic Stream
          </span>
          <span className="text-[11px] font-mono text-gray-400">{livePackets.length} Streamed Packets</span>
        </h3>

        {livePackets.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[10px] uppercase text-gray-400 border-b border-white/5 pb-2">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Source</th>
                  <th className="pb-2">Destination</th>
                  <th className="pb-2">Proto</th>
                  <th className="pb-2">Classification</th>
                  <th className="pb-2">Latency</th>
                  <th className="pb-2">Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {livePackets.map((p, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.02]">
                    <td className="py-2 text-gray-400">{p.time}</td>
                    <td className="py-2 text-gray-200">{p.src_ip}:{p.src_port}</td>
                    <td className="py-2 text-gray-400">{p.dst_ip}:{p.dst_port}</td>
                    <td className="py-2 text-cyan-400">{p.protocol}</td>
                    <td className="py-2 font-medium">{p.vector}</td>
                    <td className="py-2 text-gray-400">{p.latency}ms</td>
                    <td className="py-2">
                      <StatusPill
                        severity={p.is_attack ? 'CRITICAL' : 'LOW'}
                        label={p.is_attack ? 'ATTACK' : 'BENIGN'}
                        size="xs"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="Stream Idle"
            description="Packet capture events broadcasted over Socket.IO will populate this table automatically."
          />
        )}
      </div>
    </div>
  );
};
