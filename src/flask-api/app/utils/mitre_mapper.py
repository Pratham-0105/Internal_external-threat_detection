"""
MITRE ATT&CK Enterprise Matrix Auto-Mapping Engine for CASOC.
Maps detected network intrusions, multi-class threat categories, and DPI signatures
to official MITRE ATT&CK Tactics, Techniques, and mitigation playbooks.
"""

# Knowledge base of MITRE ATT&CK enterprise mappings
MITRE_TACTICS_AND_TECHNIQUES = {
    "DDOS": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
        "description": "Adversaries may attempt to cause a denial of service (DoS) by sending high-volume network packet floods (SYN flood, UDP flood) to exhaust target bandwidth or connection table states.",
        "mitigation_summary": "Implement upstream rate limiting, SYN cookies (syncookies=1), BGP Anycast scrubbing, and IP blackholing.",
        "nist_phase": "Containment & Eradication",
        "detection_confidence": "HIGH"
    },
    "PORTSCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries may attempt to get a listing of services and open ports running on remote hosts to identify exploitable entry points.",
        "mitigation_summary": "Enforce strict ingress firewall filtering, disable unused listening services, and employ honeypots/canary ports.",
        "nist_phase": "Identification",
        "detection_confidence": "HIGH"
    },
    "DOS": {
        "technique_id": "T1499.003",
        "technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "url": "https://attack.mitre.org/techniques/T1499/003/",
        "description": "Adversaries may send slow or resource-intensive application requests (Slowloris, Slow POST, GoldenEye) to starve web server worker pools.",
        "mitigation_summary": "Enforce minimum client data rates, reduce HTTP keep-alive timeouts, and deploy reverse-proxy buffering.",
        "nist_phase": "Containment",
        "detection_confidence": "HIGH"
    },
    "BRUTE_FORCE": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Adversaries may attempt to authenticate against SSH or FTP services using systematic or dictionary credential lists (Patator).",
        "mitigation_summary": "Enforce account lockouts (Fail2ban), require multi-factor authentication (MFA), and use key-based authentication only.",
        "nist_phase": "Containment & Hardening",
        "detection_confidence": "HIGH"
    },
    "WEB_ATTACK": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries may exploit vulnerabilities in web applications, such as SQL Injection (SQLi) or Remote Code Execution (RCE), to execute arbitrary commands.",
        "mitigation_summary": "Implement parameterized queries (prepared statements), deploy Web Application Firewall (WAF) rule sets, and sanitize user input.",
        "nist_phase": "Containment & Remediation",
        "detection_confidence": "CRITICAL"
    },
    "BOTNET": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to blend beaconing traffic with normal web browsing for Command and Control (C2).",
        "mitigation_summary": "Isolate compromised host immediately, sinkhole malicious C2 domains, and analyze process network handles with EDR.",
        "nist_phase": "Containment & Eradication",
        "detection_confidence": "HIGH"
    },
    "INFILTRATION": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "url": "https://attack.mitre.org/techniques/T1068/",
        "description": "Adversaries may exploit software vulnerabilities in elevated processes or kernel modules to gain unauthorized administrative privileges.",
        "mitigation_summary": "Patch operating systems and installed dependencies promptly, enforce least-privilege RBAC, and enable SELinux/AppArmor.",
        "nist_phase": "Containment & Recovery",
        "detection_confidence": "HIGH"
    },
    "ZERO_DAY": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1203/",
        "description": "Adversaries may execute undocumented exploits or atypical instruction sequences that statistically deviate from baseline normal telemetry.",
        "mitigation_summary": "Quarantine anomalous host, snapshot memory for sandbox reverse engineering, and capture full packet payload.",
        "nist_phase": "Analysis & Eradication",
        "detection_confidence": "MEDIUM"
    },
    "INSIDER_EXFILTRATION": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "description": "An insider or adversary may exfiltrate sensitive files, emails, or credentials over unauthorized secondary channels or USB mass storage.",
        "mitigation_summary": "Revoke active session tokens, block removable storage devices via Group Policy (GPO), and lock account pending investigation.",
        "nist_phase": "Containment",
        "detection_confidence": "HIGH"
    },
    "INSIDER_LOGON": {
        "technique_id": "T1078.002",
        "technique_name": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
        "description": "Adversaries or malicious insiders may compromise or abuse legitimate domain credentials outside normal working hours or locations.",
        "mitigation_summary": "Force credential reset, terminate all concurrent Kerberos tickets, and verify MFA device authenticity.",
        "nist_phase": "Containment",
        "detection_confidence": "HIGH"
    }
}

def map_threat_to_mitre(category_code, category_name="", dpi_res=None, anomaly_res=None):
    """
    Resolves the most relevant MITRE ATT&CK technique given threat classification,
    category code, and deep inspection signals.
    """
    code = (category_code or "").upper()
    cat_lower = (category_name or "").lower()

    # 1. Check DPI findings first for precision
    if dpi_res and dpi_res.get('dpi_flagged'):
        findings = dpi_res.get('findings', [])
        for f in findings:
            sig = f.get('signature', '').upper()
            if 'SQL' in sig:
                return MITRE_TACTICS_AND_TECHNIQUES["WEB_ATTACK"]
            elif 'XSS' in sig:
                return {
                    "technique_id": "T1189",
                    "technique_name": "Drive-by Compromise",
                    "tactic": "Initial Access",
                    "tactic_id": "TA0001",
                    "url": "https://attack.mitre.org/techniques/T1189/",
                    "description": "Adversaries may inject malicious Cross-Site Scripting (XSS) scripts into web applications to execute in client browsers.",
                    "mitigation_summary": "Implement Context-Aware Output Encoding and strict Content Security Policy (CSP).",
                    "nist_phase": "Containment & Remediation",
                    "detection_confidence": "CRITICAL"
                }
            elif 'LOG4J' in sig or 'RCE' in sig:
                return {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "tactic_id": "TA0002",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                    "description": "Adversaries may abuse command and script interpreters (JNDI/LDAP lookups) to execute arbitrary commands.",
                    "mitigation_summary": "Patch Log4j dependencies (>=2.17.1), disable message lookup substitution, and restrict outbound LDAP/RMI.",
                    "nist_phase": "Containment & Eradication",
                    "detection_confidence": "CRITICAL"
                }

    # 2. Check Zero-Day Anomaly
    if anomaly_res and anomaly_res.get('is_zero_day'):
        return MITRE_TACTICS_AND_TECHNIQUES["ZERO_DAY"]

    # 3. Check standardized category codes
    if code in MITRE_TACTICS_AND_TECHNIQUES:
        return MITRE_TACTICS_AND_TECHNIQUES[code]

    # 4. Check category name strings
    if 'ddos' in cat_lower or 'syn flood' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["DDOS"]
    elif 'portscan' in cat_lower or 'probe' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["PORTSCAN"]
    elif 'dos' in cat_lower or 'slowloris' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["DOS"]
    elif 'brute' in cat_lower or 'patator' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["BRUTE_FORCE"]
    elif 'botnet' in cat_lower or 'c2' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["BOTNET"]
    elif 'infiltrat' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["INFILTRATION"]
    elif 'web' in cat_lower or 'sql' in cat_lower:
        return MITRE_TACTICS_AND_TECHNIQUES["WEB_ATTACK"]

    # Default Benign / Normal fallback
    return {
        "technique_id": "N/A",
        "technique_name": "Legitimate Enterprise Operation",
        "tactic": "Operational Normal",
        "tactic_id": "TA0000",
        "url": "https://attack.mitre.org/",
        "description": "Packet flow conforms to baseline benign operational parameters.",
        "mitigation_summary": "No mitigation required. Continuous monitoring maintained.",
        "nist_phase": "Preparation",
        "detection_confidence": "LOW"
    }

def get_all_mitre_coverage():
    """Returns the comprehensive MITRE matrix coverage for dashboard inspection."""
    return list(MITRE_TACTICS_AND_TECHNIQUES.values())
