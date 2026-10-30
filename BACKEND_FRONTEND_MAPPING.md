# CASOC Backend-to-Frontend Architecture & API Mapping

**Project**: Cognitive Autonomous Security Operations Center (CASOC)  
**Date**: September 2026  
**Status**: Real Backend Verification Complete  

---

## 1. System Topology & Active Services

| Service Name | Host & Port | Framework | Database | Primary Capability | Real-Time Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NIDS ML & Detection Engine** | `http://localhost:5000` | Flask 3.0.3 + Werkzeug | SQLite (`nids_audit.db`) | LightGBM, DPI Regex Scanner, Zero-Day Scorer, Threat Memory, Active Defense | **Flask-SocketIO (`new_threat_event`)** |
| **Insider Threat UEBA Engine** | `http://localhost:5001` | Flask 3.0.0 + Werkzeug | SQLite (`insider_threat.db`) | Isolation Forest, Keyword Detector (42 signatures), Risk Scorer | *None (Polling / HTTP REST only)* |
| **Unified SOC Gateway** | `http://localhost:8000` | Python `http.server` | None | Unified Health Check & Microservice Process Supervision | *None* |
| **CASOC SOC Frontend** | `http://localhost:3000` | React 19 + Tailwind CSS | Browser State / Context | Single-Pane Security Operations Command Center | **Socket.IO Client** |

---

## 2. Comprehensive Endpoint Mapping Table

| Frontend Feature | Backend Endpoint | HTTP Method | Required Headers | Request Body / Parameters | Response Structure | Real-Time Event | Backend Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Main Dashboard: KPI & Event Stream** | `/incidents` (Port 5000) | `GET` | None | None | Array of incident objects (`id`, `vector`, `src_ip`, `dst_ip`, `is_attack`, `confidence`, `status`, `action_taken`, `latency_ms`) | `new_threat_event` (Socket.IO) | **VERIFIED & ACTIVE** |
| **Main Dashboard: Active Defense State** | `/defense/status` (Port 5000) | `GET` | None | None | `{ enabled: bool, blocked_ips: string[], blocked_ips_count: int }` | None | **VERIFIED & ACTIVE** |
| **Main Dashboard: System Health** | `/health` (Port 5000)<br>`/sniff/status` (Port 5000)<br>`/api/test` (Port 5001) | `GET` | Port 5001 requires `X-API-Key` | None | `{ status: 'healthy', model_loaded: bool }`<br>`{ is_running, total_packets_captured }`<br>`{ status: 'ok', keywords_count: 42 }` | None | **VERIFIED & ACTIVE** |
| **External Detection: Live Packet Sniffer** | `/sniff/start`<br>`/sniff/stop`<br>`/sniff/status` (Port 5000) | `POST`<br>`POST`<br>`GET` | None | None | `{ success: bool, message: string, status: {...} }` | None | **VERIFIED & ACTIVE** |
| **External Detection: ML & DPI Classification** | `/predict` (Port 5000) | `POST` | `Content-Type: application/json` | Array of &ge;1 packet objects: `[{ timestamp, src_ip, dst_ip, src_port, dst_port, protocol, payload }]` | `{ id, is_attack, classification, risk_score, threat_severity, category, confidence, dpi, zero_day, action_taken, xai, features }` | **Broadcasts `new_threat_event` to all connected clients** | **VERIFIED & ACTIVE** |
| **Incident Management: Triage & Notes** | `/incidents/<id>/triage` (Port 5000) | `POST` | `Content-Type: application/json` | `{ status: 'INVESTIGATING' \| 'RESOLVED' \| 'FALSE_POSITIVE', notes: string }` | `{ message: string, incident: {...} }` | None | **VERIFIED & ACTIVE** |
| **Automated Response: Active Mitigation** | `/defense/toggle`<br>`/defense/unblock` (Port 5000) | `POST` | `Authorization: Bearer <token>` | `{ enabled: bool }`<br>`{ ip: string }` | `{ enabled: bool, message: string }`<br>`{ success: bool, message: string }` | None | **VERIFIED & ACTIVE** |
| **RBAC Authentication** | `/auth/login` (Port 5000) | `POST` | `Content-Type: application/json` | `{ username: string, password: string }` | `{ success: bool, token: string, role: 'ADMIN' \| 'ANALYST', name: string }` | None | **VERIFIED & ACTIVE** |
| **Insider Security: Synthetic/Event Ingestion** | `/api/ingest`<br>`/api/receive-log` (Port 5001) | `POST` | `Content-Type: application/json`<br>`X-API-Key: <dev-agent-key>` | `{ user: string, event_type: 'LOGON' \| 'DEVICE' \| 'HTTP' \| 'FILE' \| 'EMAIL', activity: string, timestamp: string, details: string (JSON) }` | `{ status: 'threat_detected' \| 'normal', alert_id, event_id, risk_level, risk_score, description, detection_method, keywords_found }` | None | **VERIFIED & ACTIVE** |
| **Insider Security: Settings & Thresholds** | `/api/settings` (Port 5001) | `GET` | `X-API-Key: <dev-agent-key>` | None | `{ status: 'success', settings: { keyword_detection_enabled, ml_detection_enabled, thresholds, business_hours } }` | None | **VERIFIED & ACTIVE** |
| **Insider Security: Live Event History** | `/api/events` (Port 5001) | `GET` | `X-API-Key` | Query params: `limit`, `user_id`, `is_anomalous` | Array of events from `events` table | None | **BACKEND ENDPOINT REQUIRED** *(Currently only Jinja2 HTML at `/dashboard/events`)* |
| **Insider Security: Historical Alert List** | `/api/alerts` (Port 5001) | `GET` | `X-API-Key` | Query params: `status`, `risk_level` | Array of alerts from `alerts` table | None | **BACKEND ENDPOINT REQUIRED** *(Currently only Jinja2 HTML at `/dashboard/alerts`)* |
| **Insider Security: Monitored User Profiles** | `/api/users` (Port 5001) | `GET` | `X-API-Key` | Query params: `department`, `risk_level` | Array of user profiles from `user_profiles` table | None | **BACKEND ENDPOINT REQUIRED** *(Currently only Jinja2 HTML at `/dashboard/users`)* |
| **Attack Simulation: External Attack Vectors** | `/predict` (Port 5000) | `POST` | `Content-Type: application/json` | Controlled synthetic packet arrays (DDoS burst, SQLi payload, XSS script, Port scan probes, Log4Shell RCE) | Full prediction result + DPI audit + risk score + automatic firewall mitigation | **Emits `new_threat_event` -> Dashboard updates live** | **VERIFIED & ACTIVE (via `/predict`)** |
| **Attack Simulation: Insider Threat Vectors** | `/api/ingest` (Port 5001) | `POST` | `X-API-Key: <dev-agent-key>` | Controlled behavioral activity (Abnormal Login, USB Exfiltration, Mass File Download, Privilege Misuse) | Full UEBA scoring (`is_anomaly`, `risk_score`, `keywords_found`, `alert_id`) | None (Port 5001 has no WS) | **VERIFIED & ACTIVE (via `/api/ingest`)** |
| **Attack Simulation: Pre-Packaged Scenarios** | `/simulation/run` (Port 5000/5001) | `POST` | None | `{ scenario_id: 'web_attack' \| 'insider_exfil' \| 'combined' }` | Execution timeline & stage-by-stage results | WebSocket event per stage | **BACKEND ENDPOINT REQUIRED** *(Can execute client-side sequence against `/predict` and `/api/ingest` without fake data)* |
| **Threat DNA: Behavioral Dimensions** | `/threat-dna` (Port 5000) | `GET` | None | None | Multi-dimensional threat fingerprint | None | **BACKEND ENDPOINT REQUIRED** |
| **Threat Memory: Similarity Query** | `/threat-memory/query` (Port 5000) | `POST` | None | `{ ip, payload }` | Historical similarity matching | None | **BACKEND ENDPOINT REQUIRED** *(Internal memory engine exists in `threat_memory.py`, but has no direct HTTP GET/POST route)* |
| **Behaviour Evolution: Baseline Deviations** | `/user/<id>/evolution` (Port 5001) | `GET` | None | None | Longitudinal deviation trend | None | **BACKEND ENDPOINT REQUIRED** |

---

## 3. Real-Time WebSocket Synchronization Flow

```
+------------------------------------------------------------------------------------+
| 1. ATTACK SIMULATION TRIGGER                                                       |
|    - User / Scenario Runner dispatches test payload to Port 5000 (/predict)        |
+-----------------------------------------+------------------------------------------+
                                          |
                                          v
+------------------------------------------------------------------------------------+
| 2. BACKEND DETECTION PIPELINE (src/flask-api)                                      |
|    - Layer 1: Feature Extraction (12 time-series flow features)                    |
|    - Layer 2: LightGBM ML Classifier (attack_prob & confidence)                     |
|    - Layer 3: Deep Packet Inspection (DPI Regex Patterns: SQLi, XSS, RCE, IMDSv1)  |
|    - Layer 4: Zero-Day Anomaly Detection Scorer                                    |
|    - Layer 5: Threat Memory IOC & Hash Lookup                                      |
|    - Layer 6: Unified Risk Scoring (0 - 100) & Severity Classification              |
|    - Layer 7: Active Defense (IP blocked / honeypot rerouted via mitigation.py)    |
|    - Layer 8: SQLite Database Persistence (incident_records table)                 |
+-----------------------------------------+------------------------------------------+
                                          |
                                          v
+------------------------------------------------------------------------------------+
| 3. REAL-TIME BROADCAST (prediction_routes.py:L190-L193)                            |
|    - socketio.emit('new_threat_event', result)                                     |
+-----------------------------------------+------------------------------------------+
                                          |
                                          v
+------------------------------------------------------------------------------------+
| 4. CASOC FRONTEND DASHBOARD (src/frontend/my-app)                                  |
|    - socketService.js intercepts event on client                                    |
|    - SOCContext updates state: [newIncident, ...prevIncidents]                     |
|    - KPI Cards immediately recalculate (Active Threats +1, Malicious Events +1)    |
|    - Threat Activity AreaChart adds the data point in real-time                    |
|    - Active Defense list updates with newly blocked IP                             |
|    - Global Notification Center triggers popup alert                               |
+------------------------------------------------------------------------------------+
```

---

## 4. Key Limitations & Integration Actions

1. **Port 5001 WebSocket Gap**:
   - `src/flask-api` on Port 5000 has `flask_socketio.SocketIO` listening and emitting `new_threat_event`.
   - `src/insider-threat` on Port 5001 currently has **NO WebSocket or SSE server**. When an insider threat event is ingested at `/api/ingest`, the alert is written to SQLite `alerts` table, but no WebSocket event is emitted.
   - *Resolution*: When the Attack Simulation Lab triggers an insider threat scenario, the frontend can query `/api/ingest`, display the real returned JSON response, and if authorized, Port 5000 can be called to synchronize the incident or forward the event.

2. **Jinja2 vs JSON on Port 5001**:
   - The insider threat backend was originally built as a multi-page Flask application rendering HTML via `render_template`.
   - `/api/ingest`, `/api/receive-log`, `/api/test`, and `/api/settings` return real JSON.
   - User lists and historical alerts are rendered as HTML at `/dashboard/users` and `/dashboard/alerts`.
   - *Resolution*: Display real data returned by `/api/test`, `/api/settings`, and `/api/ingest`. For user details, pull from known monitored CERT accounts (`ACM1234`, `ACM2278`, `CMP2946`, `MBG3183`, `PLJ1771`) verified in `config.py:CERT_MALICIOUS_USERS`. Where an endpoint is missing, mark clean empty states with "BACKEND ENDPOINT REQUIRED".
