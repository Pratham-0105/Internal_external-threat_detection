import { nidsClient } from './apiClient';

export const nidsService = {
  // Health & Model Verification
  async getHealth() {
    const res = await nidsClient.get('/health');
    return res.data;
  },

  // Incident persistence & history
  async getIncidents() {
    const res = await nidsClient.get('/incidents');
    return res.data;
  },

  // Clear all persisted incidents
  async clearIncidents() {
    const res = await nidsClient.post('/incidents/clear');
    return res.data;
  },

  // Incident Triage & Notes
  async triageIncident(incidentId, status, notes = '') {
    const res = await nidsClient.post(`/incidents/${incidentId}/triage`, {
      status,
      notes
    });
    return res.data;
  },

  // Threat ML Prediction & DPI/XAI Inference
  async predict(packetArray) {
    const res = await nidsClient.post('/predict', packetArray);
    return res.data;
  },

  // Live Packet Sniffer Controls
  async getSnifferStatus() {
    const res = await nidsClient.get('/sniff/status');
    return res.data;
  },

  async getSnifferFlows(limit = 50) {
    const res = await nidsClient.get(`/sniff/flows?limit=${limit}`);
    return res.data;
  },

  async startSniffer() {
    const res = await nidsClient.post('/sniff/start');
    return res.data;
  },

  async stopSniffer() {
    const res = await nidsClient.post('/sniff/stop');
    return res.data;
  },

  // Active Defense & Firewall
  async getDefenseStatus() {
    const res = await nidsClient.get('/defense/status');
    return res.data;
  },

  async toggleDefense(enabled) {
    const res = await nidsClient.post('/defense/toggle', { enabled });
    return res.data;
  },

  async unblockIp(ip) {
    const res = await nidsClient.post('/defense/unblock', { ip });
    return res.data;
  },

  // Network Workstation Host Isolation
  async isolateHost(host, reason = 'Automated containment action') {
    const res = await nidsClient.post('/defense/isolate-host', { host, reason });
    return res.data;
  },

  // RBAC Authentication
  async login(username, password) {
    const res = await nidsClient.post('/auth/login', { username, password });
    return res.data;
  }
};
