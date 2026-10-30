import axios from 'axios';

const getEnv = (viteKey, reactKey, fallback) => {
  try {
    if (typeof import.meta !== 'undefined' && import.meta.env) {
      if (import.meta.env[viteKey]) return import.meta.env[viteKey];
      if (import.meta.env[reactKey]) return import.meta.env[reactKey];
    }
  } catch (e) {}
  if (typeof window !== 'undefined' && window.__ENV__) {
    if (window.__ENV__[viteKey]) return window.__ENV__[viteKey];
    if (window.__ENV__[reactKey]) return window.__ENV__[reactKey];
  }
  return fallback;
};

export const NIDS_BASE_URL = getEnv('VITE_NIDS_API_URL', 'REACT_APP_NIDS_API_URL', 'http://localhost:5005');
export const INSIDER_BASE_URL = getEnv('VITE_INSIDER_API_URL', 'REACT_APP_INSIDER_API_URL', 'http://localhost:5001');
export const GATEWAY_BASE_URL = getEnv('VITE_GATEWAY_URL', 'REACT_APP_GATEWAY_URL', 'http://localhost:8000');
export const AGENT_API_KEY = getEnv('VITE_AGENT_API_KEY', 'REACT_APP_AGENT_API_KEY', 'dev-agent-key-change-in-production');

// NIDS ML API Client (Port 5005)
export const nidsClient = axios.create({
  baseURL: NIDS_BASE_URL,
  timeout: 120000,
  headers: {
    'Content-Type': 'application/json'
  }
});

nidsClient.interceptors.request.use((config) => {
  const token =
    (typeof window !== 'undefined' && localStorage.getItem('casoc_auth_token')) ||
    'token_admin_ADMIN';
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Insider Threat API Client (Port 5001)
export const insiderClient = axios.create({
  baseURL: INSIDER_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': AGENT_API_KEY
  }
});

// Gateway API Client (Port 8000)
export const gatewayClient = axios.create({
  baseURL: GATEWAY_BASE_URL,
  timeout: 5000,
  headers: {
    'Content-Type': 'application/json'
  }
});

export default nidsClient;
