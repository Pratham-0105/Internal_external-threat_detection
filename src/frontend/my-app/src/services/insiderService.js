import { insiderClient } from './apiClient';

export const insiderService = {
  // Test endpoint to verify Insider Threat engine is responsive
  async testApi() {
    const res = await insiderClient.get('/api/test');
    return res.data;
  },

  // Retrieve current detection settings & thresholds
  async getSettings() {
    const res = await insiderClient.get('/api/settings');
    return res.data;
  },

  // Ingest synthetic or live agent user event through ML + Keyword detector
  async ingestEvent(eventData) {
    const res = await insiderClient.post('/api/ingest', eventData);
    return res.data;
  },

  // Retrieve all monitored user behavioral profiles with search and risk filters
  async getUsers({ search = '', department = '', risk_level = '', limit = 50, page = 1 } = {}) {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (department) params.append('department', department);
    if (risk_level) params.append('risk_level', risk_level);
    params.append('limit', limit);
    params.append('page', page);

    const res = await insiderClient.get(`/api/users?${params.toString()}`);
    return res.data;
  },

  // Retrieve single user profile & baseline metrics
  async getUserProfile(userId) {
    const res = await insiderClient.get(`/api/users/${userId}`);
    return res.data;
  },

  // Retrieve chronological event history for a user
  async getUserEvents(userId) {
    const res = await insiderClient.get(`/api/users/${userId}/events`);
    return res.data;
  },

  // Retrieve security alerts for a user
  async getUserAlerts(userId) {
    const res = await insiderClient.get(`/api/users/${userId}/alerts`);
    return res.data;
  },

  // Retrieve global live appended real-time events across all entities
  async getEvents({ limit = 50, anomalous = false } = {}) {
    const params = new URLSearchParams();
    params.append('limit', limit);
    if (anomalous) params.append('anomalous', 'true');
    const res = await insiderClient.get(`/api/events?${params.toString()}`);
    return res.data;
  },

  // Retrieve global live alerts across all entities
  async getAlerts({ limit = 50 } = {}) {
    const res = await insiderClient.get(`/api/alerts?limit=${limit}`);
    return res.data;
  },

  // Retrieve aggregate real-time UEBA analytics & counts
  async getStats() {
    const res = await insiderClient.get('/api/stats');
    return res.data;
  },

  // Update detection settings and risk scoring thresholds
  async updateSettings(settingsPayload) {
    const res = await insiderClient.post('/api/settings', settingsPayload);
    return res.data;
  },

  // Lock and suspend compromised employee account credentials
  async lockUser(userId) {
    const res = await insiderClient.post(`/api/users/${userId}/lock`);
    return res.data;
  },

  // Terminate active SSH, RDP, or domain logon sessions for target user
  async terminateUserSession(userId) {
    const res = await insiderClient.post(`/api/users/${userId}/terminate-session`);
    return res.data;
  }
};
