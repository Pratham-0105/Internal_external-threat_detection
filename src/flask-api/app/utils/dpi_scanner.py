"""
Deep Packet Inspection (DPI) & Layer 7 Payload Sanitizer.
Scans incoming packet payload text for SQL Injection, XSS, Command Injection, and Path Traversal signatures.
"""
import re

DPI_PATTERNS = [
    {
        "type": "SQL Injection (SQLi)",
        "severity": "CRITICAL",
        "regex": re.compile(r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC)\b|'--|' OR '1'='1|/\*|\*/)", re.IGNORECASE)
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "regex": re.compile(r"(<script.*?>|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.IGNORECASE)
    },
    {
        "type": "Command Injection",
        "severity": "CRITICAL",
        "regex": re.compile(r"(;|&&|\|\||`|\$\(|\b(wget|curl|nc|bash|powershell|cmd\.exe|/etc/passwd)\b)", re.IGNORECASE)
    },
    {
        "type": "Log4Shell / JNDI RCE",
        "severity": "CRITICAL",
        "regex": re.compile(r"(\$\{jndi:(ldap|rmi|dns|nis|iiop)://)", re.IGNORECASE)
    },
    {
        "type": "Cloud Metadata Exfiltration (IMDSv1)",
        "severity": "CRITICAL",
        "regex": re.compile(r"(169\.254\.169\.254|latest/meta-data|iam/security-credentials)", re.IGNORECASE)
    },
    {
        "type": "Directory Traversal & Secrets Leakage",
        "severity": "MEDIUM",
        "regex": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/shadow|\.env|id_rsa)", re.IGNORECASE)
    },
    {
        "type": "Brute-Force Auth Attack",
        "severity": "HIGH",
        "regex": re.compile(r"(\b(bruteforce|admin_login|access_denied|failed_auth|dict_attack)\b|invalid_password)", re.IGNORECASE)
    },
    {
        "type": "DDoS SYN Flood",
        "severity": "CRITICAL",
        "regex": re.compile(r"(SYN_FLOOD|VOLUMETRIC_STREAM|TCP_FLOOD|BURST_FLOOD|SYN_BURST)", re.IGNORECASE)
    },
    {
        "type": "PortScan Probe",
        "severity": "HIGH",
        "regex": re.compile(r"(PORT_SCAN|NMAP_SCAN|STEALTH_SCAN_PROBE|NMAP_SYN)", re.IGNORECASE)
    },
    {
        "type": "DoS Slowloris Flood",
        "severity": "HIGH",
        "regex": re.compile(r"(SLOWLORIS|HTTP_HEADER_SATURATION|X-a:\s*b)", re.IGNORECASE)
    },
    {
        "type": "Botnet C2 Beacon",
        "severity": "CRITICAL",
        "regex": re.compile(r"(BOT_COMMAND_HEARTBEAT|C2_BEACON|BOTNET_C2|IRC_JOIN_CHANNEL)", re.IGNORECASE)
    }
]

def scan_dpi_payload(packet_data):
    """
    Performs Deep Packet Inspection on raw packet string attributes.
    """
    findings = []
    
    # Inspect packet values and headers
    payload_str = ""
    if isinstance(packet_data, list):
        payload_str = " ".join([str(p) for p in packet_data])
    else:
        payload_str = str(packet_data)

    for rule in DPI_PATTERNS:
        match = rule["regex"].search(payload_str)
        if match:
            findings.append({
                "signature": rule["type"],
                "severity": rule["severity"],
                "matched_pattern": match.group(0),
                "snippet": payload_str[:120]
            })

    return {
        "dpi_flagged": len(findings) > 0,
        "findings_count": len(findings),
        "findings": findings
    }
