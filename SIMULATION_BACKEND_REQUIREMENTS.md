# CASOC Simulation Backend Requirements Specification

**Document**: `SIMULATION_BACKEND_REQUIREMENTS.md`  
**Purpose**: Document required backend enhancements for the CASOC Attack Simulation Lab and Scenario Runner, per Section 34 of the Master Specification.  
**Compliance**: STRICT — No fake frontend simulation; all synthetic events must pass through actual backend detection pipelines.

---

## 1. Existing Simulation Capabilities in Backend

The existing backend **already provides two live execution pathways**:

1. **NIDS ML & DPI Pipeline (`POST http://localhost:5000/predict`)**:
   - Accepts synthetic packet flow arrays.
   - Computes real 12-feature vectors.
   - Evaluates LightGBM probabilities and DPI regex signatures.
   - Generates real unified risk scores (0-100) and severity levels.
   - Commits records to SQLite `incident_records`.
   - Executes active defense (firewall rule addition).
   - **Broadcasts real-time events over Socket.IO (`new_threat_event`)**.
   - *Status*: **FULLY OPERATIONAL & LIVE TESTED**.

2. **Insider Threat UEBA Pipeline (`POST http://localhost:5001/api/ingest`)**:
   - Accepts synthetic user activity payloads.
   - Extracts behavioral features.
   - Evaluates Isolation Forest model & checks 42 suspicious keyword signatures.
   - Commits events and alerts to SQLite `events` and `alerts` tables.
   - *Status*: **FULLY OPERATIONAL & LIVE TESTED**.

---

## 2. Identified Backend Gaps & Recommended Minimum APIs

While the frontend can dispatch packet streams directly to `/predict` and user activity to `/api/ingest`, the following backend enhancements will provide first-class server-orchestrated scenarios:

### Requirement 1: Server-Side Simulation Scenario Runner

- **Target Endpoint**: `POST /simulation/scenario` (Port 5000)
- **Purpose**: Execute multi-stage attack scenarios on the server side with exact timestamps and staged WebSocket broadcasts.
- **Request Body**:
  ```json
  {
    "scenario_id": "external_web_attack | insider_data_exfil | combined_threat",
    "target_asset": "10.0.0.15",
    "speed_multiplier": 1.0
  }
  ```
- **Response**:
  ```json
  {
    "scenario_id": "external_web_attack",
    "status": "COMPLETED",
    "stages_executed": 3,
    "events": [
      { "stage": 1, "action": "HTTP Reconnaissance", "result": "SUSPICIOUS", "risk_score": 45 },
      { "stage": 2, "action": "SQL Injection Exploit", "result": "MALICIOUS", "risk_score": 92 },
      { "stage": 3, "action": "Active Defense Mitigation", "result": "IP_BLOCKED", "firewall_rule": "DROP" }
    ],
    "incident_id": 142
  }
  ```
- **Real-Time Emission**: Emits `simulation_stage_update` and `new_threat_event` per stage.

---

### Requirement 2: Unified Cross-Engine WebSocket Forwarding

- **Problem**: Port 5001 (Insider Threat) does not have a WebSocket server; only Port 5000 has Socket.IO.
- **Minimum Safe Implementation**:
  When Port 5001 detects an anomalous insider threat event in `/api/ingest`, forward the alert payload to Port 5000:
  ```python
  # In src/insider-threat/app/routes/api.py:
  if is_anomalous:
      try:
          import requests
          requests.post("http://localhost:5000/internal/broadcast-alert", json={
              "source": "UEBA_INSIDER",
              "user_id": event_data.get('user'),
              "risk_score": risk_score,
              "risk_level": risk_level,
              "alert_id": alert_id,
              "description": description
          }, timeout=1)
      except Exception:
          pass
  ```
- **Port 5000 Endpoint**: `POST /internal/broadcast-alert` &rarr; emits `sio.emit('new_threat_event', data)`.

---

### Requirement 3: JSON Query Endpoints for Insider Threat Entities

- **Problem**: `/dashboard/alerts`, `/dashboard/users`, and `/dashboard/events` on Port 5001 currently render Jinja2 HTML templates, making direct JSON consumption inefficient.
- **Minimum Safe Implementation**:
  Add three clean JSON API routes to `src/insider-threat/app/routes/api.py`:
  1. `GET /api/alerts`: Returns recent alerts as JSON array.
  2. `GET /api/users`: Returns monitored employee profiles (`user_profiles` table) with risk levels as JSON array.
  3. `GET /api/events`: Returns recent raw audit events as JSON array.

---

## 3. Safe Execution Protocol for Current Demonstration

Until backend changes are explicitly authorized:
- **External Attack Simulator**: Generates controlled synthetic packets client-side and transmits them to `POST http://localhost:5000/predict`. The real backend handles feature extraction, ML inference, DPI, SQLite persistence, and Socket.IO emission.
- **Insider Threat Simulator**: Dispatches controlled user activity events to `POST http://localhost:5001/api/ingest`. Displays actual returned anomaly score, risk score, and matched keywords.
- **Scenario Runner**: Sequentially calls `/predict` and `/api/ingest` with realistic delays, streaming the live responses to the **Simulation Console**.
