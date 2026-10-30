# CASOC Backend Integration & Missing API Contracts (TODO)

This document outlines the API endpoints that are required for full end-to-end integration with the CASOC (Cognitive Autonomous Security Operations Center) frontend. 

In strict compliance with the **Backend-First Rule**, the CASOC frontend does **not** invent mock data or replace backend responses with fake simulations. Where backend functionality is not yet exposed via a JSON REST endpoint, the frontend renders explicit, clean empty states (e.g. *"Data will appear when the backend endpoint is connected"*) and awaits backend implementation according to the contracts defined below.

---

## 1. Insider Threat Detection API Enhancements (Port 5001)

The backend in `src/insider-threat` maintains rich database records in `instance/insider_threat.db` (`Alert`, `Event`, `UserProfile`, `User`). Currently, routes in `app/routes/dashboard.py` return server-side rendered HTML using Jinja2. The following JSON REST endpoints are requested to support direct frontend consumption:

### A. List Insider Alerts
- **Endpoint**: `GET /api/alerts`
- **Method**: `GET`
- **Headers**: `X-API-Key: <AGENT_API_KEY>` (or JWT Bearer Token)
- **Query Parameters**:
  - `status`: `OPEN` | `INVESTIGATING` | `CLOSED` | `FALSE_POSITIVE` | `all` (default: `all`)
  - `risk_level`: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL` | `all` (default: `all`)
  - `limit`: `int` (default: `50`)
- **Response Format (`200 OK`)**:
  ```json
  [
    {
      "id": 1,
      "alert_id": "a9f8b7c6d5e4f3a2",
      "user_id": "ACM1234",
      "timestamp": "2026-09-12T00:15:30.000000",
      "risk_level": "CRITICAL",
      "risk_score": 0.94,
      "anomaly_score": 0.88,
      "alert_type": "FILE",
      "description": "Sensitive document accessed after business hours via USB removable drive.",
      "status": "OPEN",
      "resolution_notes": ""
    }
  ]
  ```
- **Reason**: Needed by the **Insider Threats** page and **Alerts Queue** to display real historical and live insider alerts.

---

### B. List Monitored Users & Behavioral Risk Profiles
- **Endpoint**: `GET /api/users`
- **Method**: `GET`
- **Headers**: `X-API-Key: <AGENT_API_KEY>`
- **Query Parameters**:
  - `search`: `string`
  - `department`: `string`
  - `risk_level`: `string`
  - `page`: `int`
  - `per_page`: `int`
- **Response Format (`200 OK`)**:
  ```json
  {
    "total": 45,
    "users": [
      {
        "user_id": "ACM1234",
        "full_name": "Alexander Hayes",
        "department": "Engineering",
        "role": "Lead DevOps Specialist",
        "current_risk_level": "CRITICAL",
        "total_alerts": 8,
        "high_risk_alerts": 5,
        "last_activity": "2026-09-12T00:12:00.000000"
      }
    ]
  }
  ```
- **Reason**: Needed by **User Behaviour** and **User Investigation** to populate monitored employee lists.

---

### C. Single User Activity Timeline & Forensic History
- **Endpoint**: `GET /api/users/<user_id>/timeline`
- **Method**: `GET`
- **Headers**: `X-API-Key: <AGENT_API_KEY>`
- **Response Format (`200 OK`)**:
  ```json
  {
    "user_id": "ACM1234",
    "profile": {
      "full_name": "Alexander Hayes",
      "department": "Engineering",
      "current_risk_level": "CRITICAL"
    },
    "baseline": {
      "avg_logon_time": "08:30:00",
      "avg_logoff_time": "17:45:00",
      "avg_file_accesses_per_day": 24.5,
      "avg_http_requests_per_day": 310.0,
      "usb_usage_frequency": 0.1
    },
    "events": [
      {
        "event_id": "evt_ACM1234_178912345_abc1234",
        "timestamp": "2026-09-12T00:15:30.000000",
        "event_type": "DEVICE",
        "activity": "USB Connect",
        "details": "{\"pc\":\"PC-ENG-09\",\"file_tree\":\"E:\\\\\"}",
        "is_anomalous": true,
        "anomaly_score": 0.88,
        "risk_score": 0.94
      }
    ]
  }
  ```
- **Reason**: Powers the vertical investigation timeline in the **User Investigation** view.

---

## 2. CASOC AI Intelligence Engine Enhancements

### A. Threat Correlation Endpoint
- **Endpoint**: `GET /api/correlation`
- **Method**: `GET`
- **Target Backend**: NIDS ML API (Port 5000) or Gateway (Port 8000)
- **Response Format (`200 OK`)**:
  ```json
  {
    "correlated_incidents": [
      {
        "correlation_id": "CORR-2026-001",
        "title": "Coordinated Lateral Movement & Exfiltration",
        "severity": "CRITICAL",
        "risk_score": 92.0,
        "external_vector": {
          "incident_id": 82,
          "category": "PortScan Probe",
          "src_ip": "185.220.101.5",
          "timestamp": "2026-09-12T00:10:00"
        },
        "insider_vector": {
          "user_id": "ACM1234",
          "event_type": "DEVICE",
          "activity": "USB Connect",
          "timestamp": "2026-09-12T00:15:30"
        },
        "correlation_confidence": 0.89,
        "summary": "External port scan probe preceded an unauthorized local USB data transfer within 5 minutes."
      }
    ]
  }
  ```
- **Reason**: Needed by **Threat Correlation** to combine external network events with insider behavioral anomalies.

---

### B. Threat DNA Fingerprint Endpoint
- **Endpoint**: `GET /api/threat-dna`
- **Method**: `GET`
- **Target Backend**: NIDS ML API (Port 5000)
- **Response Format (`200 OK`)**:
  ```json
  {
    "dimensions": [
      { "name": "Network Pattern", "score": 85, "deviation": "+18%" },
      { "name": "Login Pattern", "score": 42, "deviation": "-5%" },
      { "name": "File Behaviour", "score": 79, "deviation": "+32%" },
      { "name": "Privilege Usage", "score": 64, "deviation": "+12%" },
      { "name": "Data Transfer", "score": 91, "deviation": "+45%" },
      { "name": "Attack Pattern", "score": 88, "deviation": "+29%" }
    ],
    "cluster_id": "CLUSTER-SYN-FLOOD-EXFIL",
    "fingerprint_hash": "sha256:d41d8cd98f00b204e9800998ecf8427e"
  }
  ```
- **Reason**: Powers the multi-dimensional radar/spider chart in the **Threat DNA** view.

---

### C. Behaviour Evolution Baseline & Deviation Endpoint
- **Endpoint**: `GET /api/behaviour-evolution`
- **Method**: `GET`
- **Query Parameters**: `user_id`: `string`, `timeframe`: `7d` | `30d`
- **Response Format (`200 OK`)**:
  ```json
  {
    "user_id": "ACM1234",
    "trends": [
      { "date": "2026-09-06", "baseline": 20, "actual": 22, "risk_score": 15 },
      { "date": "2026-09-07", "baseline": 20, "actual": 25, "risk_score": 18 },
      { "date": "2026-09-08", "baseline": 20, "actual": 21, "risk_score": 16 },
      { "date": "2026-09-09", "baseline": 20, "actual": 68, "risk_score": 65 },
      { "date": "2026-09-10", "baseline": 20, "actual": 92, "risk_score": 89 }
    ]
  }
  ```
- **Reason**: Powers the historical baseline vs. deviation curves on the **Behaviour Evolution** page.

---

## 3. Automated Response Execution Endpoints (Port 5000)

Currently implemented in `prediction_routes.py`:
- `GET /defense/status` (Implemented)
- `POST /defense/toggle` (Implemented)
- `POST /defense/unblock` (Implemented)

Additional non-destructive response capabilities requested for the **Automated Response** panel:
- `POST /defense/block` — Add an IP manually to the firewall ban list.
  - Body: `{"ip": "1.2.3.4", "reason": "Analyst manual quarantine"}`
- `POST /defense/isolate-host` — Mark a target machine or asset as isolated.
- `POST /defense/lock-account` — Disable a compromised user account.
