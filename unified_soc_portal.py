#!/usr/bin/env python3
"""
Unified SOC Portal & Command Hub
Single-host access point for both:
1. Insider Threat Detection System (UEBA) - Port 5001
2. Network Intrusion Detection System (NIDS Dashboard & ML Engine) - Ports 3000 & 5000

Access Link: http://localhost:8000
"""

import http.server
import socketserver
import json
import urllib.request
import urllib.error
import subprocess
import os
import sys

PORT = 8000
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Store running child processes
SUBPROCESSES = {
    "insider": None,
    "nids_api": None,
    "nids_ui": None
}

def get_service_python(service_dir):
    if sys.platform == "win32":
        candidates = [os.path.join(service_dir, ".venv", "Scripts", "python.exe")]
    else:
        candidates = [os.path.join(service_dir, ".venv", "bin", "python")]
    for c in candidates:
        if os.path.isfile(c) and (sys.platform == "win32" or os.access(c, os.X_OK)):
            return c
    return sys.executable


SERVICES = {
    "insider": {
        "name": "Insider Threat Detection (UEBA)",
        "url": "http://localhost:5001",
        "dir": os.path.join(ROOT_DIR, "src", "insider-threat"),
        "cmd": [get_service_python(os.path.join(ROOT_DIR, "src", "insider-threat")), "run.py"],
        "description": "Monitors employee activity, logon anomalies, USB connections, and sensitive file/email exfiltration."
    },
    "nids_ui": {
        "name": "NIDS Real-time Dashboard",
        "url": "http://localhost:3000",
        "dir": os.path.join(ROOT_DIR, "src", "frontend", "my-app"),
        "cmd": ["npm.cmd", "start"] if sys.platform == "win32" else ["npm", "start"],
        "description": "React-based interactive packet analysis, live threat visualizer, and multi-attack telemetry simulator."
    },
    "nids_api": {
        "name": "NIDS ML Inference Engine",
        "url": "http://localhost:5005/health",
        "health_url": "http://localhost:5005/health",
        "dir": os.path.join(ROOT_DIR, "src", "flask-api"),
        "cmd": [get_service_python(os.path.join(ROOT_DIR, "src", "flask-api")), "run.py"],
        "description": "LightGBM time-series inference engine classifying traffic into Benign or Attack with WebSocket feed."
    }
}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SOC Unified Command Center | Intrusion & Insider Threat</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #0a0e17;
      --bg-surface: #111827;
      --bg-card: rgba(17, 24, 39, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --accent-emerald: #10b981;
      --accent-rose: #f43f5e;
      --accent-amber: #f59e0b;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Inter', sans-serif;
      background-color: var(--bg-base);
      color: var(--text-main);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }

    header {
      background: linear-gradient(180deg, rgba(15, 23, 42, 0.98) 0%, rgba(10, 14, 23, 0.98) 100%);
      border-bottom: 1px solid var(--border-color);
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      backdrop-filter: blur(12px);
      z-index: 50;
      flex-shrink: 0;
    }

    .brand-cluster {
      display: flex;
      align-items: center;
      gap: 0.85rem;
    }

    .brand-icon {
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.3rem;
      box-shadow: 0 0 20px rgba(14, 165, 233, 0.4);
    }

    .brand-text h1 {
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .brand-text .badge {
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      background: rgba(14, 165, 233, 0.18);
      color: #38bdf8;
      border: 1px solid rgba(14, 165, 233, 0.3);
    }

    .brand-text p {
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    .tab-group {
      display: flex;
      align-items: center;
      background: rgba(0, 0, 0, 0.3);
      padding: 0.3rem;
      border-radius: 10px;
      border: 1px solid var(--border-color);
      gap: 0.25rem;
    }

    .tab-btn {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      border-radius: 7px;
      border: none;
      background: transparent;
      color: var(--text-muted);
      font-size: 0.825rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .tab-btn:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.05);
    }

    .tab-btn.active {
      color: #ffffff;
      background: linear-gradient(135deg, rgba(59, 130, 246, 0.3), rgba(14, 165, 233, 0.3));
      border: 1px solid rgba(56, 189, 248, 0.35);
      box-shadow: 0 2px 10px rgba(14, 165, 233, 0.2);
    }

    .status-pill {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #64748b;
      box-shadow: 0 0 6px rgba(100, 116, 139, 0.5);
      transition: all 0.3s ease;
    }

    .status-pill.online {
      background: #10b981;
      box-shadow: 0 0 8px #10b981;
    }

    .status-pill.offline {
      background: #f43f5e;
      box-shadow: 0 0 8px #f43f5e;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .quick-start-btn {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.5rem 0.9rem;
      font-size: 0.8rem;
      font-weight: 700;
      color: #ffffff;
      background: linear-gradient(135deg, #10b981, #059669);
      border: 1px solid #10b981;
      border-radius: 8px;
      cursor: pointer;
      box-shadow: 0 2px 10px rgba(16, 185, 129, 0.3);
      transition: opacity 0.2s;
    }

    .quick-start-btn:hover {
      opacity: 0.9;
    }

    .ext-link-btn {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.45rem 0.85rem;
      font-size: 0.775rem;
      font-weight: 600;
      color: var(--text-muted);
      border: 1px solid var(--border-color);
      border-radius: 7px;
      text-decoration: none;
      transition: all 0.2s;
      background: rgba(255, 255, 255, 0.02);
    }

    .ext-link-btn:hover {
      color: #ffffff;
      border-color: rgba(255, 255, 255, 0.25);
      background: rgba(255, 255, 255, 0.06);
    }

    main {
      flex: 1;
      display: flex;
      position: relative;
      background: #06090e;
      overflow: hidden;
    }

    .view-panel {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      display: none;
      flex-direction: column;
    }

    .view-panel.active {
      display: flex;
    }

    iframe {
      width: 100%;
      height: 100%;
      border: none;
      background: #0b0f19;
    }

    .overview-container {
      padding: 2.5rem;
      overflow-y: auto;
      max-width: 1300px;
      margin: 0 auto;
      width: 100%;
    }

    .hero-banner {
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.7) 100%);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 2rem;
      margin-bottom: 2rem;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
    }

    .hero-banner h2 {
      font-size: 1.75rem;
      font-weight: 800;
      margin-bottom: 0.5rem;
      background: linear-gradient(90deg, #ffffff 0%, #38bdf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .hero-banner p {
      color: var(--text-muted);
      font-size: 0.95rem;
      max-width: 750px;
      line-height: 1.5;
    }

    .grid-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2.5rem;
    }

    .soc-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: transform 0.2s ease, border-color 0.2s ease;
      position: relative;
    }

    .soc-card:hover {
      transform: translateY(-3px);
      border-color: rgba(56, 189, 248, 0.4);
      box-shadow: 0 8px 25px rgba(0, 0, 0, 0.5);
    }

    .card-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1rem;
    }

    .card-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.725rem;
      font-weight: 600;
      padding: 0.2rem 0.6rem;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-muted);
      border: 1px solid var(--border-color);
    }

    .card-title {
      font-size: 1.15rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 0.4rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .card-desc {
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 1.25rem;
    }

    .card-meta {
      display: flex;
      align-items: center;
      gap: 1rem;
      font-size: 0.8rem;
      font-family: 'JetBrains Mono', monospace;
      color: #94a3b8;
      padding: 0.75rem 0;
      border-top: 1px solid var(--border-color);
      margin-bottom: 1rem;
    }

    .card-btn-row {
      display: flex;
      gap: 0.75rem;
    }

    .btn-action {
      flex: 1;
      padding: 0.65rem 1rem;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.85rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      text-decoration: none;
      transition: all 0.2s;
    }

    .btn-launch {
      background: linear-gradient(135deg, #2563eb, #0284c7);
      color: white;
    }

    .btn-start {
      background: linear-gradient(135deg, #10b981, #059669);
      color: white;
    }

    .btn-secondary {
      padding: 0.65rem 0.85rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      border-radius: 8px;
      font-size: 0.85rem;
      cursor: pointer;
      text-decoration: none;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
    }

    /* Offline Placeholder */
    .offline-placeholder {
      display: none;
      height: 100%;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 2rem;
      background: #090e17;
    }

    .offline-placeholder.visible {
      display: flex;
    }

    .offline-box {
      background: var(--bg-card);
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 2.5rem;
      border-radius: 16px;
      max-width: 540px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
    }

    .offline-box .alert-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }

    .offline-box h3 {
      font-size: 1.25rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 0.5rem;
    }

    .offline-box p {
      color: var(--text-muted);
      font-size: 0.875rem;
      margin-bottom: 1.5rem;
      line-height: 1.5;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand-cluster">
      <div class="brand-icon">🛡️</div>
      <div class="brand-text">
        <h1>Unified SOC Portal <span class="badge">Live Gateway</span></h1>
        <p>Intrusion Detection System + Insider Threat Platform</p>
      </div>
    </div>

    <div class="tab-group">
      <button class="tab-btn active" onclick="switchTab('overview')">
        <span>📊</span> Overview Hub
      </button>

      <button class="tab-btn" onclick="switchTab('insider')">
        <span class="status-pill" id="pill-insider"></span>
        <span>👤</span> Insider Threat (UEBA)
      </button>

      <button class="tab-btn" onclick="switchTab('nids_ui')">
        <span class="status-pill" id="pill-nids-ui"></span>
        <span>🌐</span> NIDS Live Dashboard
      </button>

      <button class="tab-btn" onclick="switchTab('nids_api')">
        <span class="status-pill" id="pill-nids-api"></span>
        <span>⚡</span> NIDS ML API
      </button>
    </div>

    <div class="header-actions">
      <button class="quick-start-btn" onclick="startAllServices()" id="btn-start-all">
        <span>🚀</span> Start All Services
      </button>
      <a href="http://localhost:5001" target="_blank" class="ext-link-btn" title="Open Insider Threat in New Tab">
        <span>👤 :5001</span> ↗
      </a>
      <a href="http://localhost:3000" target="_blank" class="ext-link-btn" title="Open NIDS UI in New Tab">
        <span>🌐 :3000</span> ↗
      </a>
      <a href="http://localhost:5000/incidents" target="_blank" class="ext-link-btn" title="Open ML API in New Tab">
        <span>⚡ :5000</span> ↗
      </a>
    </div>
  </header>

  <main>
    <!-- View 1: Unified Hub / Overview -->
    <div id="view-overview" class="view-panel active">
      <div class="overview-container">
        <div class="hero-banner">
          <h2>Central Security Operations Portal</h2>
          <p>
            You are accessing all security monitoring layers through a single host (<strong>http://localhost:8000</strong>).
            Click <strong>"Start All Services"</strong> above to boot all backend components with one click.
          </p>
        </div>

        <div class="grid-cards">
          <!-- Card 1: Insider Threat -->
          <div class="soc-card">
            <div>
              <div class="card-head">
                <div class="card-badge">UEBA / HOST AGENT</div>
                <span class="status-pill" id="card-pill-insider"></span>
              </div>
              <div class="card-title">👤 Insider Threat Detection</div>
              <div class="card-desc">
                Machine-learning-driven UEBA platform watching logons, web activity, sensitive file downloads, external email exfiltration, and unauthorized USB connects.
              </div>
            </div>
            <div>
              <div class="card-meta">
                <span>PORT: 5001</span>
                <span>DATASET: CERT r4.2</span>
                <span>MODEL: Isolation Forest</span>
              </div>
              <div class="card-btn-row">
                <button class="btn-action btn-launch" id="action-insider" onclick="handleCardAction('insider')">Launch View</button>
                <a href="http://localhost:5001" target="_blank" class="btn-secondary" title="Open in new window">↗</a>
              </div>
            </div>
          </div>

          <!-- Card 2: NIDS React UI -->
          <div class="soc-card">
            <div>
              <div class="card-head">
                <div class="card-badge">NETWORK / L3-L7 IDS</div>
                <span class="status-pill" id="card-pill-nids-ui"></span>
              </div>
              <div class="card-title">🌐 NIDS Live Dashboard</div>
              <div class="card-desc">
                React-powered dashboard visualizing real-time telemetry, simulated DDoS, SQL Injection, Log4Shell, Botnet attacks, and geo-ip forensic flags.
              </div>
            </div>
            <div>
              <div class="card-meta">
                <span>PORT: 3000</span>
                <span>STACK: React 19 + Recharts</span>
                <span>STREAM: Socket.IO</span>
              </div>
              <div class="card-btn-row">
                <button class="btn-action btn-launch" id="action-nids-ui" onclick="handleCardAction('nids_ui')">Launch View</button>
                <a href="http://localhost:3000" target="_blank" class="btn-secondary" title="Open in new window">↗</a>
              </div>
            </div>
          </div>

          <!-- Card 3: Flask ML API -->
          <div class="soc-card">
            <div>
              <div class="card-head">
                <div class="card-badge">AI / INFERENCE ENGINE</div>
                <span class="status-pill" id="card-pill-nids-api"></span>
              </div>
              <div class="card-title">⚡ NIDS ML API & Incidents</div>
              <div class="card-desc">
                Low-latency LightGBM detection service evaluating 12-25 time-based packet flow variables, streaming predictions and incident history.
              </div>
            </div>
            <div>
              <div class="card-meta">
                <span>PORT: 5000</span>
                <span>MODEL: LightGBM .pkl</span>
                <span>DATASET: CICIDS 2017</span>
              </div>
              <div class="card-btn-row">
                <button class="btn-action btn-launch" id="action-nids-api" onclick="handleCardAction('nids_api')">Launch View</button>
                <a href="http://localhost:5000/incidents" target="_blank" class="btn-secondary" title="Open in new window">↗</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- View 2: Insider Threat System Frame -->
    <div id="view-insider" class="view-panel">
      <div class="offline-placeholder" id="offline-insider">
        <div class="offline-box">
          <div class="alert-icon">👤</div>
          <h3>Insider Threat Engine is Offline</h3>
          <p>This service runs on port 5001. Click below to start it instantly in the background.</p>
          <button class="btn-action btn-start" onclick="triggerStartService('insider')">▶️ Start Insider Threat Engine</button>
        </div>
      </div>
      <iframe id="frame-insider" src="http://localhost:5001/dashboard/"></iframe>
    </div>

    <!-- View 3: NIDS React UI Frame -->
    <div id="view-nids_ui" class="view-panel">
      <div class="offline-placeholder" id="offline-nids_ui">
        <div class="offline-box">
          <div class="alert-icon">🌐</div>
          <h3>NIDS Live Dashboard is Offline</h3>
          <p>This React app runs on port 3000. Click below to start it in the background.</p>
          <button class="btn-action btn-start" onclick="triggerStartService('nids_ui')">▶️ Start NIDS Dashboard</button>
        </div>
      </div>
      <iframe id="frame-nids-ui" src="http://localhost:3000/"></iframe>
    </div>

    <!-- View 4: NIDS ML API Frame -->
    <div id="view-nids_api" class="view-panel">
      <div class="offline-placeholder" id="offline-nids_api">
        <div class="offline-box">
          <div class="alert-icon">⚡</div>
          <h3>NIDS ML API is Offline</h3>
          <p>The LightGBM API runs on port 5000. Click below to start it in the background.</p>
          <button class="btn-action btn-start" onclick="triggerStartService('nids_api')">▶️ Start NIDS ML API</button>
        </div>
      </div>
      <iframe id="frame-nids-api" src="http://localhost:5000/incidents"></iframe>
    </div>
  </main>

  <script>
    let serviceStatus = { insider: false, nids_ui: false, nids_api: false };

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));

      const targetBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick') && b.getAttribute('onclick').includes(tabId));
      if (targetBtn) targetBtn.classList.add('active');

      const targetPanel = document.getElementById('view-' + tabId);
      if (targetPanel) targetPanel.classList.add('active');

      const frameMap = {
        'insider': { id: 'frame-insider', url: 'http://localhost:5001/dashboard/' },
        'nids_ui': { id: 'frame-nids-ui', url: 'http://localhost:3000/' },
        'nids_api': { id: 'frame-nids-api', url: 'http://localhost:5000/incidents' }
      };

      if (frameMap[tabId]) {
        const frame = document.getElementById(frameMap[tabId].id);
        if (frame) {
          frame.style.display = 'block';
          if (!frame.src || frame.src === 'about:blank') {
            frame.src = frameMap[tabId].url;
          }
        }
      }
    }

    function handleCardAction(serviceKey) {
      if (serviceStatus[serviceKey]) {
        switchTab(serviceKey);
      } else {
        triggerStartService(serviceKey);
      }
    }

    async function triggerStartService(serviceKey) {
      try {
        const res = await fetch('/api/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ service: serviceKey })
        });
        if (res.ok) {
          alert('Starting ' + serviceKey + ' in the background... Please wait a few seconds.');
          setTimeout(checkHealth, 3000);
        }
      } catch (e) {
        console.error("Start error:", e);
      }
    }

    async function startAllServices() {
      const btn = document.getElementById('btn-start-all');
      btn.innerHTML = '<span>⏳</span> Starting Services...';
      try {
        await fetch('/api/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ service: 'all' })
        });
      } catch (e) {
        console.error("Start all error:", e);
      }
      setTimeout(() => {
        btn.innerHTML = '<span>✓</span> All Services Connected';
        checkHealth();
        const fInsider = document.getElementById('frame-insider');
        if (fInsider) fInsider.src = 'http://localhost:5001/dashboard/';
        const fNids = document.getElementById('frame-nids-ui');
        if (fNids) fNids.src = 'http://localhost:3000/';
        const fApi = document.getElementById('frame-nids-api');
        if (fApi) fApi.src = 'http://localhost:5000/incidents';
        setTimeout(() => {
          btn.innerHTML = '<span>🚀</span> Start All Services';
        }, 3000);
      }, 2000);
    }

    async function checkHealth() {
      try {
        const res = await fetch('/api/health');
        if (res.ok) {
          const data = await res.json();
          serviceStatus = data;
          updateServiceUI('insider', data.insider, 'http://localhost:5001');
          updateServiceUI('nids_ui', data.nids_ui, 'http://localhost:3000');
          updateServiceUI('nids_api', data.nids_api, 'http://localhost:5000/incidents');
        }
      } catch (err) {
        console.error("Health check error:", err);
      }
    }

    function updateServiceUI(key, isOnline, targetUrl) {
      const cleanKey = key.replace('_', '-');
      const pill = document.getElementById('pill-' + cleanKey);
      const cardPill = document.getElementById('card-pill-' + cleanKey);
      const actionBtn = document.getElementById('action-' + cleanKey);
      const offlineBox = document.getElementById('offline-' + key);
      const frame = document.getElementById(key === 'insider' ? 'frame-insider' : (key === 'nids_ui' ? 'frame-nids-ui' : 'frame-nids-api'));

      [pill, cardPill].forEach(p => {
        if (!p) return;
        p.classList.remove('online', 'offline');
        p.classList.add(isOnline ? 'online' : 'offline');
        p.title = isOnline ? 'Service Online' : 'Service Offline';
      });

      if (actionBtn) {
        if (isOnline) {
          actionBtn.className = 'btn-action btn-launch';
          actionBtn.innerText = 'Launch View';
        } else {
          actionBtn.className = 'btn-action btn-start';
          actionBtn.innerText = '▶️ Start Service';
        }
      }

      if (offlineBox && frame) {
        if (isOnline) {
          offlineBox.classList.remove('visible');
          frame.style.display = 'block';
          if (!frame.src || frame.src === 'about:blank') {
            frame.src = targetUrl;
          }
        } else {
          offlineBox.classList.add('visible');
          frame.style.display = 'none';
        }
      }
    }

    setInterval(checkHealth, 4000);
    checkHealth();
  </script>
</body>
</html>
"""

def is_service_online(url, timeout=1.0):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-HealthCheck'})
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return True
    except Exception:
        return False

def launch_subservice(key):
    if key not in SERVICES:
        return False
    conf = SERVICES[key]
    try:
        # Check if already online
        if is_service_online(conf["url"]):
            return True
        cmd = conf["cmd"]
        if sys.platform == "win32" and isinstance(cmd, list):
            cmd = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        p = subprocess.Popen(
            cmd,
            cwd=conf["dir"],
            shell=(sys.platform == "win32"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        SUBPROCESSES[key] = p
        return True
    except Exception as e:
        print(f"[!] Error launching {key}: {e}")
        return False

class UnifiedSOCHandler(http.server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization')
        self.end_headers()

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode('utf-8'))
        elif self.path == '/api/health':
            insider_check = os.environ.get("INSIDER_CHECK_URL", "http://localhost:5001/health")
            nids_ui_check = os.environ.get("NIDS_UI_CHECK_URL", "http://localhost:3000")
            nids_api_check = os.environ.get("NIDS_API_CHECK_URL", "http://localhost:5000/health")

            insider_online = is_service_online(insider_check) or is_service_online("http://localhost:5001")
            nids_ui_online = is_service_online(nids_ui_check)
            nids_api_online = (
                is_service_online("http://localhost:5005/health") or
                is_service_online(nids_api_check) or
                is_service_online("http://localhost:5005") or
                is_service_online("http://localhost:5000/health")
            )


            payload = {
                "insider": insider_online,
                "nids_ui": nids_ui_online,
                "nids_api": nids_api_online
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/start':
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}
            target = data.get('service', 'all')

            if target == 'all':
                launch_subservice('insider')
                launch_subservice('nids_api')
                launch_subservice('nids_ui')
            else:
                launch_subservice(target)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "starting", "target": target}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    print("=" * 70)
    print("[SOC] UNIFIED SECURITY OPERATIONS CENTER COMMAND HUB")
    print("=" * 70)
    print(f"[*] Serving Unified Host Link: http://localhost:{PORT}")
    print("[*] Single-pane access to:")
    print("    - Insider Threat Detection System (Port 5001)")
    print("    - NIDS React Telemetry Dashboard (Port 3000)")
    print("    - NIDS LightGBM Inference API   (Port 5000)")
    print("=" * 70)

    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", PORT), UnifiedSOCHandler) as httpd:
            print(f"[OK] Gateway running on http://localhost:{PORT}")
            print("[OK] Press Ctrl+C to stop.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Unified SOC Portal.")
    except Exception as e:
        print(f"[!] Server error: {e}")

if __name__ == '__main__':
    main()
