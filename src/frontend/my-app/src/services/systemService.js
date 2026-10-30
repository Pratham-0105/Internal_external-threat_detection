import { gatewayClient, nidsClient, insiderClient } from './apiClient';

export const systemService = {
  async getSystemStatus() {
    const status = {
      aiEngine: { online: false, text: 'Offline' },
      networkMonitor: { online: false, text: 'Idle' },
      mlService: { online: false, text: 'Offline' },
      database: { online: false, text: 'Disconnected' }
    };

    try {
      // 1. Check Gateway & NIDS ML API
      const nidsHealth = await nidsClient.get('/health').catch(() => null);
      if (nidsHealth && nidsHealth.data?.status === 'healthy') {
        status.mlService = { online: true, text: 'LightGBM Active' };
        status.aiEngine = { online: true, text: 'Zero-Day / XAI Online' };
        status.database = { online: true, text: 'SQLite Connected' };
      }

      // 2. Check Sniffer state
      const snifferRes = await nidsClient.get('/sniff/status').catch(() => null);
      if (snifferRes && snifferRes.data) {
        const isRunning = snifferRes.data.is_running;
        status.networkMonitor = {
          online: isRunning,
          text: isRunning ? `Sniffing (${snifferRes.data.total_packets_captured} Pkts)` : 'Idle / Standby'
        };
      }

      // 3. Check Insider Threat Engine
      const insiderRes = await insiderClient.get('/api/test').catch(() => null);
      if (insiderRes && insiderRes.data?.status === 'ok') {
        status.database.text = 'Dual SQLite Active';
      }

      // 4. Gateway health if reachable
      const gwRes = await gatewayClient.get('/api/health').catch(() => null);
      if (gwRes && gwRes.data) {
        // Can further refine based on gateway output
      }
    } catch (e) {
      console.warn('System status fetch failed:', e);
    }

    return status;
  }
};
